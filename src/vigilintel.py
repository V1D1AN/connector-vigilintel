#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VigilIntel Connector v2 for OpenCTI
Supports both JSON (full CTI data) and STIX 2.1 (full CTI) formats
https://github.com/kidrek/VigilIntel

JSON Sections processed (actual VigilIntel keys):
- strategic_analysis: Strategic analysis note
- geopolitical_analyse: Geopolitical notes
- breach_analyse: Data breaches/incidents with threat actors
- vulnerabilities_analyse: CVEs with CVSS, CPE, CISA KEV
- threats_analyse: Detailed threat reports with IOCs, TTPs, tools
"""

import json
import os
import re
import time
import hashlib
import requests
import yaml
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

from pycti import OpenCTIConnectorHelper, get_config_variable
from stix2 import (
    Bundle, Identity, Report, Indicator, Vulnerability, Note,
    ThreatActor, AttackPattern, Relationship, ExternalReference,
    Tool, Software,
)


class VigilIntelConnector:
    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/../config.yml"
        config = yaml.load(open(config_file_path), Loader=yaml.FullLoader) if os.path.isfile(config_file_path) else {}

        self.helper = OpenCTIConnectorHelper(config)

        # Configuration
        self.github_base_url = get_config_variable("VIGILINTEL_GITHUB_URL", ["vigilintel", "github_url"], config, default="https://raw.githubusercontent.com/kidrek/VigilIntel/main")
        self.format = get_config_variable("VIGILINTEL_FORMAT", ["vigilintel", "format"], config, default="stix").lower()
        self.language = get_config_variable("VIGILINTEL_LANGUAGE", ["vigilintel", "language"], config, default="en").lower()
        self.interval = get_config_variable("VIGILINTEL_INTERVAL", ["vigilintel", "interval"], config, default=86400, isNumber=True)
        self.update_existing_data = get_config_variable("CONNECTOR_UPDATE_EXISTING_DATA", ["connector", "update_existing_data"], config, default=True)
        self.create_indicators = get_config_variable("VIGILINTEL_CREATE_INDICATORS", ["vigilintel", "create_indicators"], config, default=True)

        # Default marking (TLP) applied to every object produced by this connector
        # Accepted values: "TLP:CLEAR", "TLP:WHITE", "TLP:GREEN", "TLP:AMBER",
        # "TLP:AMBER+STRICT", "TLP:RED", or "" / None to disable.
        default_marking_raw = get_config_variable(
            "VIGILINTEL_DEFAULT_MARKING",
            ["vigilintel", "default_marking"],
            config,
            default="TLP:AMBER",
        )
        self.default_marking_id = self._resolve_marking_id(default_marking_raw)

        # Import options
        self.import_threat_actors = get_config_variable("VIGILINTEL_IMPORT_THREAT_ACTORS", ["vigilintel", "import_threat_actors"], config, default=True)
        self.import_vulnerabilities = get_config_variable("VIGILINTEL_IMPORT_VULNERABILITIES", ["vigilintel", "import_vulnerabilities"], config, default=True)
        self.import_incidents = get_config_variable("VIGILINTEL_IMPORT_INCIDENTS", ["vigilintel", "import_incidents"], config, default=True)
        self.import_articles = get_config_variable("VIGILINTEL_IMPORT_ARTICLES", ["vigilintel", "import_articles"], config, default=True)
        self.import_geopolitical = get_config_variable("VIGILINTEL_IMPORT_GEOPOLITICAL", ["vigilintel", "import_geopolitical"], config, default=True)
        self.import_analysis = get_config_variable("VIGILINTEL_IMPORT_ANALYSIS", ["vigilintel", "import_analysis"], config, default=True)
        self.import_from_date = get_config_variable("VIGILINTEL_IMPORT_FROM_DATE", ["vigilintel", "import_from_date"], config, default=None)
        self.days_to_import = get_config_variable("VIGILINTEL_DAYS_TO_IMPORT", ["vigilintel", "days_to_import"], config, default=1, isNumber=True)

        # Identity
        self.identity = self.helper.api.identity.create(type="Organization", name="VigilIntel", description="Daily CTI synthesis from open sources by Kidrek")
        self.identity_id = f"identity--{self.identity['standard_id'].split('--')[1]}"

        # IOC patterns
        self.ioc_patterns = {
            "ipv4": r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            "domain": r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
            "url": r'https?://[^\s<>"\']+',
            "sha256": r'\b[a-fA-F0-9]{64}\b',
            "sha1": r'\b[a-fA-F0-9]{40}\b',
            "md5": r'\b[a-fA-F0-9]{32}\b',
        }
        # Mapping from VigilIntel JSON indicator keys to internal ioc types
        self.vigilintel_ioc_mapping = {
            "IPV4": "ipv4",
            "IPV6": "ipv6",
            "DOMAIN": "domain",
            "URL": "url",
            "SHA256": "sha256",
            "FILE_HASH_SHA256": "sha256",
            "HASH_SHA256": "sha256",
            "SHA1": "sha1",
            "HASH_SHA1": "sha1",
            "MD5": "md5",
            "HASH_MD5": "md5",
            "EMAIL": "email",
        }
        self.mitre_pattern = r'T\d{4}(?:\.\d{3})?'

        self.helper.log_info(f"VigilIntel Connector v2 initialized - Format: {self.format}, Language: {self.language}")

    # ─── Marking helpers ──────────────────────────────────────────────

    # Standard STIX 2.1 TLP marking-definition IDs (see oasis-open spec)
    _TLP_STIX_IDS = {
        "TLP:CLEAR": "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "TLP:WHITE": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        "TLP:GREEN": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
        "TLP:AMBER": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
        # AMBER+STRICT and RED are OpenCTI-specific (not in STIX 2.1 spec)
        # OpenCTI generates deterministic IDs for them — we let the platform handle resolution
        # by sending only the standard ones. For AMBER+STRICT/RED we fall back to AMBER here
        # and rely on the helper API for a proper resolution at runtime.
    }

    def _resolve_marking_id(self, value):
        """Resolve a TLP string into a STIX marking-definition ID.

        For standard TLP levels (CLEAR/WHITE/GREEN/AMBER) we use the OASIS-defined IDs.
        For AMBER+STRICT and RED (OpenCTI extensions) we ask the API to resolve/create
        the marking and return its standard_id.
        """
        if not value:
            return None
        v = str(value).strip().upper()
        if v in ("", "NONE", "FALSE"):
            return None
        # Normalise common aliases
        if v in ("CLEAR", "WHITE", "GREEN", "AMBER", "RED"):
            v = f"TLP:{v}"
        if v == "AMBER+STRICT" or v == "TLP:AMBER+STRICT":
            v = "TLP:AMBER+STRICT"

        if v in self._TLP_STIX_IDS:
            self.helper.log_info(f"Default marking set to {v}")
            return self._TLP_STIX_IDS[v]

        # AMBER+STRICT / RED → resolve via OpenCTI API
        try:
            definition_type = "TLP"
            definition = v.split(":", 1)[1] if ":" in v else v
            marking = self.helper.api.marking_definition.read(
                filters={
                    "mode": "and",
                    "filters": [
                        {"key": "definition_type", "values": [definition_type]},
                        {"key": "definition", "values": [definition]},
                    ],
                    "filterGroups": [],
                }
            )
            if marking and marking.get("standard_id"):
                self.helper.log_info(f"Default marking resolved via API: {v} → {marking['standard_id']}")
                return marking["standard_id"]
            self.helper.log_warning(
                f"Could not resolve marking '{v}' via API — default marking disabled"
            )
            return None
        except Exception as e:
            self.helper.log_warning(f"Error resolving marking '{v}': {e} — default marking disabled")
            return None

    # SDO/SRO types that accept object_marking_refs (per STIX 2.1 spec).
    # We exclude bundle, marking-definition itself, language-content, and meta types.
    _MARKABLE_TYPES = {
        "attack-pattern", "campaign", "course-of-action", "grouping",
        "identity", "incident", "indicator", "infrastructure", "intrusion-set",
        "location", "malware", "malware-analysis", "note", "observed-data",
        "opinion", "report", "threat-actor", "tool", "vulnerability",
        "relationship", "sighting",
        # SCOs (observables) also support object_marking_refs in STIX 2.1
        "ipv4-addr", "ipv6-addr", "domain-name", "url", "file", "email-addr",
        "email-message", "mac-addr", "autonomous-system", "directory",
        "network-traffic", "process", "software", "user-account",
        "windows-registry-key", "x509-certificate", "artifact",
    }

    def _apply_marking_to_bundle(self, bundle_data):
        """Inject self.default_marking_id into every markable object of the bundle.

        - Adds the marking-definition object to the bundle if not already present.
        - Appends the marking ref to existing object_marking_refs (no duplication).
        - Skips bundle root, marking-definition objects, and unsupported types.

        Works on a dict bundle (mutated in place) and returns it.
        """
        if not self.default_marking_id:
            return bundle_data
        if not isinstance(bundle_data, dict):
            return bundle_data

        objects = bundle_data.get("objects", [])
        if not objects:
            return bundle_data

        marking_id = self.default_marking_id
        existing_marking_ids = {
            o["id"] for o in objects if o.get("type") == "marking-definition"
        }

        marked_count = 0
        for obj in objects:
            otype = obj.get("type")
            if otype not in self._MARKABLE_TYPES:
                continue
            refs = obj.get("object_marking_refs") or []
            if marking_id not in refs:
                refs = list(refs) + [marking_id]
                obj["object_marking_refs"] = refs
                marked_count += 1

        # Inject the marking-definition object if absent and it's a known TLP
        if marking_id not in existing_marking_ids and marking_id in self._TLP_STIX_IDS.values():
            inv = {v: k for k, v in self._TLP_STIX_IDS.items()}
            tlp_label = inv[marking_id]
            objects.append({
                "type": "marking-definition",
                "spec_version": "2.1",
                "id": marking_id,
                "created": "2022-10-01T00:00:00.000Z",
                "definition_type": "tlp",
                "name": tlp_label,
                "definition": {"tlp": tlp_label.split(":", 1)[1].lower()},
            })

        if marked_count:
            self.helper.log_info(f"Applied default marking to {marked_count} objects")
        return bundle_data

    # ─── Utility helpers ───────────────────────────────────────────────

    def _get_text(self, value: Any, fallback: str = "") -> str:
        """Extract text from a multilingual field {en: ..., fr: ...} or a plain string."""
        if value is None:
            return fallback
        if isinstance(value, str):
            return value
        if isinstance(value, dict):
            return value.get(self.language, value.get("fr", value.get("en", fallback)))
        return str(value) if value else fallback

    def _get_list(self, value: Any) -> List[str]:
        """Extract a list from a multilingual field or a plain list."""
        if value is None:
            return []
        if isinstance(value, list):
            return value
        if isinstance(value, dict):
            result = value.get(self.language, value.get("fr", value.get("en", [])))
            return result if isinstance(result, list) else [result]
        return [str(value)]

    def _build_report_url(self, date: datetime, format_type: str = None) -> str:
        fmt = format_type or self.format
        year, month, date_str = date.strftime("%Y"), date.strftime("%m"), date.strftime("%Y-%m-%d")
        if fmt == "stix":
            filename = f"{date_str}-report-stix.json"
        elif fmt == "md":
            filename = f"{date_str}-report.md"
        else:
            filename = f"{date_str}-report.json"
        return f"{self.github_base_url}/{year}/{month}/{filename}"

    def _get_dates_to_import(self) -> List[datetime]:
        dates, today = [], datetime.now(timezone.utc)
        if self.import_from_date:
            try:
                start = datetime.strptime(self.import_from_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                while start <= today:
                    dates.append(start)
                    start += timedelta(days=1)
            except ValueError:
                dates = [today]
        else:
            for i in range(self.days_to_import):
                dates.append(today - timedelta(days=i))
        return dates

    def _fetch_report(self, url: str) -> Optional[Dict]:
        try:
            self.helper.log_info(f"Fetching: {url}")
            response = requests.get(url, timeout=30)
            return response.json() if response.status_code == 200 else None
        except Exception as e:
            self.helper.log_error(f"Fetch error: {str(e)}")
            return None

    def _compute_content_hash(self, data: Any) -> str:
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

    def _create_external_references(self, sources: Any) -> List[ExternalReference]:
        refs = []
        src_list = sources if isinstance(sources, list) else [sources] if isinstance(sources, str) else []
        for src in src_list:
            if isinstance(src, str) and src.startswith("http"):
                refs.append(ExternalReference(source_name="VigilIntel", url=src))
        return refs

    def _clean_ioc_value(self, value: str) -> str:
        return value.replace("[.]", ".").replace("[:]", ":").replace("hxxp", "http")

    def _create_stix_indicator(self, ioc_type: str, ioc_value: str) -> Optional[Dict]:
        cleaned = self._clean_ioc_value(ioc_value)
        patterns = {
            "ipv4": (f"[ipv4-addr:value = '{cleaned}']", "IPv4-Addr"),
            "ipv6": (f"[ipv6-addr:value = '{cleaned}']", "IPv6-Addr"),
            "domain": (f"[domain-name:value = '{cleaned}']", "Domain-Name"),
            "url": (f"[url:value = '{cleaned.replace(chr(39), chr(92)+chr(39))}']", "Url"),
            "email": (f"[email-addr:value = '{cleaned}']", "Email-Addr"),
            "sha256": (f"[file:hashes.'SHA-256' = '{cleaned}']", "StixFile"),
            "sha1": (f"[file:hashes.'SHA-1' = '{cleaned}']", "StixFile"),
            "md5": (f"[file:hashes.MD5 = '{cleaned}']", "StixFile"),
        }
        if ioc_type in patterns:
            return {"pattern": patterns[ioc_type][0], "pattern_type": "stix", "main_observable_type": patterns[ioc_type][1], "ioc_value": cleaned}
        return None

    def _cvss_to_severity(self, cvss) -> str:
        try:
            score = float(cvss)
            if score >= 9.0: return "critical"
            elif score >= 7.0: return "high"
            elif score >= 4.0: return "medium"
            return "low"
        except (ValueError, TypeError):
            return "unknown"

    def _ts(self, report_date: datetime) -> str:
        """Produce a STIX-compatible timestamp string from a report date."""
        return report_date.strftime("%Y-%m-%dT00:00:00Z")

    def _get_stix_identity(self) -> Identity:
        return Identity(id=self.identity_id, name="VigilIntel", identity_class="organization")

    def _format_recommendations(self, recs: Any) -> str:
        """Format recommendations list (which may be [{en:..,fr:..}, ...] or [str, ...])."""
        if not recs:
            return ""
        if isinstance(recs, str):
            return recs
        parts = []
        for r in recs:
            text = self._get_text(r) if isinstance(r, dict) else str(r)
            if text:
                parts.append(f"- {text}")
        return "\n".join(parts)

    # ─── STIX Bundle processing ───────────────────────────────────────

    def _split_stix_bundle(self, bundle_data: Dict) -> Dict:
        """Split a monolithic STIX bundle into clustered sub-reports.
        
        Strategy:
        1. Identify shared infrastructure (VigilIntel identity, markings, extensions)
        2. Use Notes as cluster seeds — each Note's object_refs define a topic
        3. Flood-fill each cluster via relationships (source/target graph walk)
        4. Standalone notes (Strategic, Geopolitical) stay as-is under the daily report
        5. Entity-bearing notes (Breach, Vulnerability, Threat) get their own sub-Report
        6. The original Report becomes a digest referencing only sub-reports + standalone notes
        """
        objects = bundle_data.get("objects", [])
        obj_map = {o["id"]: o for o in objects}

        # Step 1: Identify shared infrastructure (included in final bundle but not in any cluster)
        shared_types = {"marking-definition", "extension-definition"}
        original_report = None
        vigilintel_identity_id = None
        shared_ids = set()

        for obj in objects:
            if obj["type"] in shared_types:
                shared_ids.add(obj["id"])
            elif obj["type"] == "report":
                original_report = obj
            elif obj["type"] == "identity" and obj.get("name") == "VigilIntel" and obj.get("identity_class") == "organization":
                vigilintel_identity_id = obj["id"]
                shared_ids.add(obj["id"])

        if not original_report:
            return bundle_data  # No report to split, return as-is

        # Step 2: Collect all notes and relationships
        notes = [o for o in objects if o["type"] == "note"]
        relationships = [o for o in objects if o["type"] == "relationship"]

        # Build adjacency: for each object ID, which relationships touch it?
        rel_by_endpoint = {}
        for rel in relationships:
            for endpoint in (rel["source_ref"], rel["target_ref"]):
                rel_by_endpoint.setdefault(endpoint, []).append(rel)

        # Step 3: Classify notes and build clusters
        standalone_prefixes = ("Strategic |", "Geopolitical |")
        standalone_note_ids = []
        clusters = []  # list of {"seed_note": note, "object_ids": set()}

        for note in notes:
            abstract = note.get("abstract", "")
            is_standalone = any(abstract.startswith(p) for p in standalone_prefixes)

            if is_standalone:
                standalone_note_ids.append(note["id"])
                # Also include the note-link relationships for standalone notes
                for rel in rel_by_endpoint.get(note["id"], []):
                    standalone_note_ids.append(rel["id"])
                continue

            # Flood-fill cluster from this note
            cluster_ids = {note["id"]}

            # Add note's object_refs (excluding VigilIntel identity)
            for ref in note.get("object_refs", []):
                if ref != vigilintel_identity_id:
                    cluster_ids.add(ref)

            # Iterative flood-fill via relationships
            changed = True
            while changed:
                changed = False
                for rel in relationships:
                    src, tgt = rel["source_ref"], rel["target_ref"]
                    # If one endpoint is in cluster, pull in the relationship + other endpoint
                    if src in cluster_ids or tgt in cluster_ids:
                        if rel["id"] not in cluster_ids:
                            cluster_ids.add(rel["id"])
                            changed = True
                        # Add the other endpoint (but not the VigilIntel identity)
                        for ep in (src, tgt):
                            if ep not in cluster_ids and ep != vigilintel_identity_id:
                                cluster_ids.add(ep)
                                changed = True

            clusters.append({"seed_note": note, "object_ids": cluster_ids})

        # Step 4: Merge overlapping clusters (in case two notes share entities)
        merged = True
        while merged:
            merged = False
            for i in range(len(clusters)):
                for j in range(i + 1, len(clusters)):
                    if clusters[i]["object_ids"] & clusters[j]["object_ids"]:
                        clusters[i]["object_ids"] |= clusters[j]["object_ids"]
                        # Keep the note with the richer abstract as seed
                        if len(clusters[j]["seed_note"].get("object_refs", [])) > len(clusters[i]["seed_note"].get("object_refs", [])):
                            clusters[i]["seed_note"] = clusters[j]["seed_note"]
                        clusters.pop(j)
                        merged = True
                        break
                if merged:
                    break

        # Step 5: Create sub-reports for each cluster
        report_date = original_report.get("published", original_report.get("created"))
        report_markings = original_report.get("object_marking_refs", [])
        created_by = original_report.get("created_by_ref", vigilintel_identity_id)

        sub_report_ids = []
        new_objects = []

        for cluster in clusters:
            seed = cluster["seed_note"]
            abstract = seed.get("abstract", "Unknown topic")

            # Determine report name from abstract
            # "Threat | Framework de Malware..." → "Framework de Malware..."
            # "Breach | Kash Patel..." → "Kash Patel..."
            # "Vulnerability | CVE-2025-53521..." → "CVE-2025-53521..."
            parts = abstract.split(" | ", 1)
            if len(parts) == 2:
                report_name = parts[1]
                # Remove trailing date if present: " (2026-03-30)"
                report_name = re.sub(r'\s*\(\d{4}-\d{2}-\d{2}\)\s*$', '', report_name)
                report_type_prefix = parts[0]
            else:
                report_name = abstract
                report_type_prefix = "Unknown"

            # Build object_refs for sub-report (only real objects, not the report itself)
            cluster_refs = [oid for oid in cluster["object_ids"] if oid in obj_map]

            # Generate deterministic sub-report ID from original report ID + seed note ID
            sub_id_input = f"{original_report['id']}:{seed['id']}"
            sub_id_hash = hashlib.sha256(sub_id_input.encode()).hexdigest()[:32]
            # Format as UUID v5-like
            sub_report_id = f"report--{sub_id_hash[:8]}-{sub_id_hash[8:12]}-{sub_id_hash[12:16]}-{sub_id_hash[16:20]}-{sub_id_hash[20:32]}"

            sub_report = {
                "type": "report",
                "spec_version": "2.1",
                "id": sub_report_id,
                "created": original_report.get("created"),
                "modified": original_report.get("modified"),
                "created_by_ref": created_by,
                "name": report_name,
                "description": f"VigilIntel - {report_type_prefix}",
                "published": report_date,
                "report_types": ["threat-report"],
                "object_refs": cluster_refs,
                "labels": seed.get("labels", ["vigilintel"]),
            }
            if report_markings:
                sub_report["object_marking_refs"] = report_markings

            # Copy external_references from seed note if present
            if seed.get("external_references"):
                sub_report["external_references"] = seed["external_references"]

            new_objects.append(sub_report)
            sub_report_ids.append(sub_report_id)

        # Step 6: Rewrite original report to reference only sub-reports + standalone notes
        daily_refs = sub_report_ids + standalone_note_ids
        original_report["object_refs"] = daily_refs
        original_report["description"] = f"VigilIntel Daily Digest - {len(clusters)} topics, {len(standalone_note_ids)} standalone notes"

        # Step 7: Rebuild the bundle with all objects + new sub-reports
        final_objects = objects + new_objects
        bundle_data["objects"] = final_objects

        return bundle_data

    def _process_stix_bundle(self, bundle_data: Dict, work_id: str, report_date: datetime) -> Tuple[int, str]:
        try:
            if bundle_data.get("type") != "bundle":
                return 0, "Invalid bundle"
            objects = bundle_data.get("objects", [])
            if not objects:
                return 0, "Empty bundle"

            type_counts = {}
            for obj in objects:
                t = obj.get("type", "unknown")
                type_counts[t] = type_counts.get(t, 0) + 1

            self.helper.log_info(f"STIX Bundle: {len(objects)} objects - {type_counts}")

            # Split into sub-reports
            bundle_data = self._split_stix_bundle(bundle_data)

            # Apply default marking to every markable object (no-op if disabled)
            bundle_data = self._apply_marking_to_bundle(bundle_data)

            split_objects = bundle_data.get("objects", [])
            sub_reports = [o for o in split_objects if o["type"] == "report" and o["id"] != [o2 for o2 in split_objects if o2["type"] == "report" and "Daily" in o2.get("description", "")]]

            # Count new sub-reports
            new_reports = [o for o in split_objects if o["type"] == "report"]
            self.helper.log_info(f"Split bundle: {len(split_objects)} objects, {len(new_reports)} reports (1 daily + {len(new_reports) - 1} sub-reports)")

            self.helper.send_stix2_bundle(json.dumps(bundle_data), update=self.update_existing_data, work_id=work_id)
            return len(split_objects), f"Imported {len(split_objects)} STIX objects ({len(new_reports)} reports)"
        except Exception as e:
            self.helper.log_error(f"STIX error: {str(e)}")
            return 0, f"Error: {str(e)}"

    # ─── JSON Section processors ──────────────────────────────────────

    def _process_json_analysis(self, analysis_data: Dict, report_date: datetime) -> Tuple[List, List]:
        """Process strategic_analysis section."""
        stix_objects, object_refs = [], []
        try:
            # analysis_data is {"analyse": {"en": "...", "fr": "..."}, "date": "..."}
            analyse_field = analysis_data.get("analyse", analysis_data)
            text = self._get_text(analyse_field)
            if text:
                note = Note(
                    abstract=f"Strategic Analysis - {report_date.strftime('%Y-%m-%d')}",
                    content=text,
                    created_by_ref=self.identity_id,
                    object_refs=[self.identity_id],
                    labels=["strategic-analysis", "daily-summary"],
                    created=self._ts(report_date),
                    modified=self._ts(report_date),
                )
                stix_objects.append(note)
                object_refs.append(note.id)
                self.helper.log_info("  Strategic Analysis Note created")
        except Exception as e:
            self.helper.log_error(f"Analysis error: {str(e)}")
        return stix_objects, object_refs

    def _process_json_geopolitical(self, geo_list: List[Dict], report_date: datetime) -> Tuple[List, List]:
        """Process geopolitical_analyse section."""
        stix_objects, object_refs = [], []
        if not isinstance(geo_list, list):
            return stix_objects, object_refs

        for geo in geo_list:
            try:
                theme = self._get_text(geo.get("theme", ""))
                if not theme:
                    continue

                desc = self._get_text(geo.get("description", ""))
                sector = self._get_list(geo.get("sector", geo.get("secteur", "")))
                recs = self._format_recommendations(geo.get("recommandations", []))

                content_parts = []
                if sector:
                    content_parts.append(f"**Sector:** {', '.join(sector)}")
                if desc:
                    content_parts.append(desc)
                if recs:
                    content_parts.append(f"## Recommendations\n{recs}")
                content = "\n\n".join(content_parts)

                tags = [t for t in geo.get("tags", []) if t.lower() not in ("geopolitique", "geopolitic")]
                tags.append("geopolitical-analysis")

                ext_refs = self._create_external_references(geo.get("sources", []))

                note = Note(
                    abstract=f"Geopolitical: {theme[:200]}",
                    content=content,
                    created_by_ref=self.identity_id,
                    object_refs=[self.identity_id],
                    labels=tags,
                    external_references=ext_refs if ext_refs else None,
                    created=self._ts(report_date),
                    modified=self._ts(report_date),
                )
                stix_objects.append(note)
                object_refs.append(note.id)
                self.helper.log_info(f"  Geopolitical: {theme[:50]}...")
            except Exception as e:
                self.helper.log_error(f"Geopolitical error: {str(e)}")
        return stix_objects, object_refs

    def _process_json_breaches(self, incidents_list: List[Dict], report_date: datetime) -> Tuple[List, List]:
        """Process breach_analyse section — creates victims, threat actors, notes, and relationships."""
        stix_objects, object_refs = [], []
        if not isinstance(incidents_list, list):
            return stix_objects, object_refs

        for inc in incidents_list:
            try:
                victim = inc.get("victim", inc.get("victime", ""))
                if not victim:
                    continue

                desc = self._get_text(inc.get("description", ""))
                sector = self._get_list(inc.get("sector", inc.get("secteur", "")))
                ta_name = inc.get("threat_actor", "")
                ta_origin = inc.get("threat_actor_origin", "")
                ta_type = inc.get("threat_actor_type", "")
                ta_aliases = inc.get("threat_actor_aliases", [])
                ttps = inc.get("mitre_ttps", [])
                recs = self._format_recommendations(inc.get("recommandations", []))
                tags = [t for t in inc.get("tags", []) if t.lower() not in ("violation", "breach")]
                tags.append("data-breach")

                ext_refs = self._create_external_references(inc.get("sources", []))

                # Build content
                content_parts = []
                if sector:
                    content_parts.append(f"**Sector:** {', '.join(sector)}")
                if ta_name and ta_name.lower() != "unknown":
                    content_parts.append(f"**Threat Actor:** {ta_name}")
                    if ta_origin:
                        content_parts.append(f"**Origin:** {ta_origin}")
                    if ta_type:
                        content_parts.append(f"**Type:** {ta_type}")
                if desc:
                    content_parts.append(f"\n{desc}")
                if recs:
                    content_parts.append(f"\n## Recommendations\n{recs}")
                content = "\n".join(content_parts)

                note_obj_refs = []

                # Create victim identity
                victim_id = Identity(
                    name=victim,
                    identity_class="organization",
                    created_by_ref=self.identity_id,
                )
                stix_objects.append(victim_id)
                note_obj_refs.append(victim_id.id)

                # Create threat actor if known
                ta_obj = None
                if ta_name and ta_name.lower() != "unknown":
                    ta_obj = ThreatActor(
                        name=ta_name,
                        created_by_ref=self.identity_id,
                        aliases=ta_aliases if ta_aliases else None,
                        labels=tags if tags else None,
                        created=self._ts(report_date),
                        modified=self._ts(report_date),
                    )
                    stix_objects.append(ta_obj)
                    note_obj_refs.append(ta_obj.id)

                    # targets relationship
                    rel = Relationship(
                        relationship_type="targets",
                        source_ref=ta_obj.id,
                        target_ref=victim_id.id,
                        created_by_ref=self.identity_id,
                        labels=tags,
                        created=self._ts(report_date),
                        modified=self._ts(report_date),
                    )
                    stix_objects.append(rel)

                # Create attack patterns for TTPs
                for ttp in ttps:
                    matches = re.findall(self.mitre_pattern, ttp)
                    for tech_id in matches:
                        ap = AttackPattern(
                            name=tech_id,
                            created_by_ref=self.identity_id,
                            external_references=[ExternalReference(source_name="mitre-attack", external_id=tech_id)],
                        )
                        stix_objects.append(ap)
                        note_obj_refs.append(ap.id)
                        # Link threat actor to attack pattern
                        if ta_obj:
                            rel_ttp = Relationship(
                                relationship_type="uses",
                                source_ref=ta_obj.id,
                                target_ref=ap.id,
                                created_by_ref=self.identity_id,
                                created=self._ts(report_date),
                                modified=self._ts(report_date),
                            )
                            stix_objects.append(rel_ttp)

                # Create note
                note = Note(
                    abstract=f"Data Breach: {victim}",
                    content=content,
                    created_by_ref=self.identity_id,
                    object_refs=note_obj_refs if note_obj_refs else [self.identity_id],
                    labels=tags,
                    external_references=ext_refs if ext_refs else None,
                    created=self._ts(report_date),
                    modified=self._ts(report_date),
                )
                stix_objects.append(note)
                object_refs.extend([note.id, victim_id.id])
                if ta_obj:
                    object_refs.append(ta_obj.id)
                self.helper.log_info(f"  Breach: {victim}")
            except Exception as e:
                self.helper.log_error(f"Breach error: {str(e)}")
        return stix_objects, object_refs

    def _process_json_vulnerabilities(self, vulns_list: List[Dict], report_date: datetime) -> Tuple[List, List]:
        """Process vulnerabilities_analyse section — with CVSS, CPE, CISA KEV, vendor/product."""
        stix_objects, object_refs = [], []
        if not isinstance(vulns_list, list):
            return stix_objects, object_refs

        for vuln in vulns_list:
            try:
                cve_id = vuln.get("cve_id", "")
                if not cve_id:
                    continue

                cvss = vuln.get("cvss", "")
                epss = vuln.get("epss", "")
                cisa_kev = str(vuln.get("cisa_kev", "")).upper() == "TRUE"
                product = vuln.get("product", "")
                vendor = vuln.get("vendor", "")
                cpe = vuln.get("cpe", "")
                desc = self._get_text(vuln.get("description", ""))
                ttps = vuln.get("mitre_ttps", [])
                recs = self._format_recommendations(vuln.get("recommandations", []))
                tags = [t for t in vuln.get("tags", []) if t.lower() not in ("vulnerabilite", "vulnerability")]
                if cisa_kev:
                    tags.append("cisa-kev")

                # Build description
                full_desc_parts = [desc] if desc else []
                if product:
                    full_desc_parts.append(f"**Product:** {product}")
                if vendor:
                    full_desc_parts.append(f"**Vendor:** {vendor}")
                if cvss:
                    full_desc_parts.append(f"**CVSS:** {cvss}")
                if epss:
                    full_desc_parts.append(f"**EPSS:** {epss}")
                if cpe:
                    full_desc_parts.append(f"**CPE:** {cpe}")
                if cisa_kev:
                    full_desc_parts.append("**CISA KEV:** Yes")
                if recs:
                    full_desc_parts.append(f"\n## Recommendations\n{recs}")
                full_desc = "\n\n".join(full_desc_parts)

                # External references
                ext_refs = [ExternalReference(source_name="cve", external_id=cve_id.upper())]
                ext_refs.append(ExternalReference(source_name="nvd", url=f"https://nvd.nist.gov/vuln/detail/{cve_id.upper()}"))
                ext_refs.extend(self._create_external_references(vuln.get("sources", [])))

                # Build custom properties for OpenCTI
                custom_props = {}
                if cvss:
                    try:
                        custom_props["x_opencti_cvss_base_score"] = float(cvss)
                        custom_props["x_opencti_cvss_base_severity"] = self._cvss_to_severity(cvss)
                    except (ValueError, TypeError):
                        pass
                if cisa_kev:
                    custom_props["x_opencti_cisa_kev"] = True

                v = Vulnerability(
                    name=cve_id.upper(),
                    description=full_desc if full_desc else None,
                    created_by_ref=self.identity_id,
                    labels=tags if tags else None,
                    external_references=ext_refs,
                    created=self._ts(report_date),
                    modified=self._ts(report_date),
                    allow_custom=True,
                    **custom_props,
                )
                stix_objects.append(v)
                object_refs.append(v.id)

                # Create Software object if vendor/product/CPE available
                if product and vendor:
                    sw_kwargs = {
                        "name": product,
                        "vendor": vendor,
                    }
                    if cpe:
                        sw_kwargs["cpe"] = cpe
                    sw = Software(**sw_kwargs)
                    stix_objects.append(sw)
                    object_refs.append(sw.id)

                    # Vulnerability → Software relationship
                    rel = Relationship(
                        relationship_type="related-to",
                        source_ref=v.id,
                        target_ref=sw.id,
                        description="Affected software identified from vendor/product/CPE metadata",
                        created_by_ref=self.identity_id,
                        created=self._ts(report_date),
                        modified=self._ts(report_date),
                    )
                    stix_objects.append(rel)

                # Create attack patterns for TTPs
                for ttp in ttps:
                    matches = re.findall(self.mitre_pattern, ttp)
                    for tech_id in matches:
                        ap = AttackPattern(
                            name=tech_id,
                            created_by_ref=self.identity_id,
                            external_references=[ExternalReference(source_name="mitre-attack", external_id=tech_id)],
                        )
                        stix_objects.append(ap)
                        object_refs.append(ap.id)

                self.helper.log_info(f"  Vulnerability: {cve_id} (CVSS: {cvss}, CISA KEV: {cisa_kev})")
            except Exception as e:
                self.helper.log_error(f"Vulnerability error: {str(e)}")
        return stix_objects, object_refs

    def _process_json_threats(self, articles_list: List[Dict], report_date: datetime) -> Tuple[List, List]:
        """Process threats_analyse section — full threat reports with IOCs, TTPs, tools."""
        stix_objects, object_refs = [], []
        if not isinstance(articles_list, list):
            return stix_objects, object_refs

        for article in articles_list:
            try:
                title = self._get_text(article.get("title", ""))
                if not title:
                    continue

                desc = self._get_text(article.get("description", ""))
                analysis = self._get_text(article.get("analyse", ""))
                recs = self._format_recommendations(article.get("recommandations", []))
                tags = article.get("tags", [])
                sources = article.get("sources", [])
                indicators = article.get("indicators", article.get("indicator_of_compromise", {}))
                ttps = article.get("mitre_ttps", [])
                ta_name = article.get("threat_actor", "")
                ta_origin = article.get("threat_actor_origin", "")
                ta_type = article.get("threat_actor_type", "")
                ta_aliases = article.get("threat_actor_aliases", [])
                sector = self._get_list(article.get("sector", ""))

                article_refs = []
                ext_refs = self._create_external_references(sources)

                # Build note content
                content_parts = []
                if sector:
                    content_parts.append(f"**Sector:** {', '.join(sector)}")
                if desc:
                    content_parts.append(f"## Description\n{desc}")
                if analysis:
                    content_parts.append(f"## Analysis\n{analysis}")
                if recs:
                    content_parts.append(f"## Recommendations\n{recs}")

                # Threat actor
                ta_obj = None
                if ta_name and ta_name.lower() not in ("unknown", "unknown (individual developer)", ""):
                    ta_obj = ThreatActor(
                        name=ta_name,
                        created_by_ref=self.identity_id,
                        aliases=ta_aliases if ta_aliases else None,
                        labels=tags if tags else None,
                        created=self._ts(report_date),
                        modified=self._ts(report_date),
                    )
                    stix_objects.append(ta_obj)
                    article_refs.append(ta_obj.id)

                # Tools from indicators.TOOLS
                if isinstance(indicators, dict):
                    tools_list = indicators.get("TOOLS", [])
                    for tool_name in tools_list:
                        if not tool_name:
                            continue
                        tool = Tool(
                            name=tool_name,
                            created_by_ref=self.identity_id,
                            labels=tags if tags else None,
                            created=self._ts(report_date),
                            modified=self._ts(report_date),
                        )
                        stix_objects.append(tool)
                        article_refs.append(tool.id)
                        # threat actor uses tool
                        if ta_obj:
                            rel = Relationship(
                                relationship_type="uses",
                                source_ref=ta_obj.id,
                                target_ref=tool.id,
                                created_by_ref=self.identity_id,
                                created=self._ts(report_date),
                                modified=self._ts(report_date),
                            )
                            stix_objects.append(rel)

                # IOCs (all indicator keys except TOOLS)
                if self.create_indicators and isinstance(indicators, dict):
                    for cat, vals in indicators.items():
                        if cat.upper() == "TOOLS":
                            continue
                        if not isinstance(vals, list):
                            continue
                        ioc_type = self.vigilintel_ioc_mapping.get(cat.upper(), cat.lower())
                        for val in vals:
                            if not val:
                                continue
                            ind_data = self._create_stix_indicator(ioc_type, val)
                            if ind_data:
                                ind = Indicator(
                                    name=f"{ioc_type.upper()}: {ind_data['ioc_value']}",
                                    pattern=ind_data["pattern"],
                                    pattern_type="stix",
                                    created_by_ref=self.identity_id,
                                    labels=tags if tags else None,
                                    external_references=ext_refs if ext_refs else None,
                                    valid_from=self._ts(report_date),
                                    confidence=50,
                                )
                                stix_objects.append(ind)
                                article_refs.append(ind.id)

                # TTPs
                for ttp in ttps:
                    matches = re.findall(self.mitre_pattern, ttp)
                    for tech_id in matches:
                        ap = AttackPattern(
                            name=tech_id,
                            created_by_ref=self.identity_id,
                            external_references=[ExternalReference(source_name="mitre-attack", external_id=tech_id)],
                        )
                        stix_objects.append(ap)
                        article_refs.append(ap.id)
                        if ta_obj:
                            rel = Relationship(
                                relationship_type="uses",
                                source_ref=ta_obj.id,
                                target_ref=ap.id,
                                created_by_ref=self.identity_id,
                                created=self._ts(report_date),
                                modified=self._ts(report_date),
                            )
                            stix_objects.append(rel)

                content = "\n\n".join(content_parts)

                # Note
                note = Note(
                    abstract=title[:250],
                    content=content,
                    created_by_ref=self.identity_id,
                    object_refs=article_refs if article_refs else [self.identity_id],
                    external_references=ext_refs if ext_refs else None,
                    created=self._ts(report_date),
                    modified=self._ts(report_date),
                )
                stix_objects.append(note)
                article_refs.append(note.id)

                # Report per threat article
                report = Report(
                    name=title,
                    description=desc[:500] if desc else None,
                    published=self._ts(report_date),
                    created_by_ref=self.identity_id,
                    object_refs=article_refs if article_refs else [self.identity_id],
                    labels=tags if tags else ["vigilintel"],
                    external_references=ext_refs if ext_refs else None,
                    report_types=["threat-report"],
                )
                stix_objects.append(report)
                object_refs.append(report.id)
                object_refs.extend(article_refs)
                self.helper.log_info(f"  Threat: {title[:50]}... ({len(article_refs)} refs)")
            except Exception as e:
                self.helper.log_error(f"Threat article error: {str(e)}")
        return stix_objects, object_refs

    # ─── JSON orchestrator ─────────────────────────────────────────────

    def _process_json_full(self, json_data: Dict, work_id: str, report_date: datetime) -> Tuple[int, str]:
        """Process the actual VigilIntel JSON format with top-level section keys."""
        try:
            all_objects, all_refs, stats = [self._get_stix_identity()], [], {}

            # Actual VigilIntel JSON section mappings
            # Maps: (internal_name, json_key, import_flag, processor_method)
            section_defs = [
                ("analysis",        "strategic_analysis",      self.import_analysis,         self._process_json_analysis),
                ("geopolitical",    "geopolitical_analyse",    self.import_geopolitical,     self._process_json_geopolitical),
                ("breaches",        "breach_analyse",          self.import_incidents,        self._process_json_breaches),
                ("vulnerabilities", "vulnerabilities_analyse", self.import_vulnerabilities,  self._process_json_vulnerabilities),
                ("threats",         "threats_analyse",         self.import_articles,         self._process_json_threats),
            ]

            # Also try legacy format with language-wrapped keys (FR/EN → section names)
            # for backward compatibility with older VigilIntel JSON exports
            legacy_data = None
            lang_key = self.language.upper()
            for lk in [lang_key, "FR", "EN"]:
                if lk in json_data:
                    legacy_data = json_data[lk]
                    self.helper.log_info(f"Detected legacy JSON format with language key '{lk}'")
                    break

            if legacy_data:
                # Legacy format: data[LANG][section_name_in_french]
                legacy_mappings = {
                    "analysis":        ["Analyse transversale"],
                    "geopolitical":    ["Synthèse de l'actualité géopolitique", "Synthese de l'actualite geopolitique"],
                    "breaches":        ["Synthèse des violations de données", "Synthese des violations de donnees"],
                    "vulnerabilities": ["Synthèse des vulnérabilités", "Synthese des vulnerabilites"],
                    "threats":         ["Articles"],
                }
                for stat_name, json_key, enabled, processor in section_defs:
                    if not enabled:
                        continue
                    section_data = None
                    for key in legacy_mappings.get(stat_name, []):
                        if key in legacy_data:
                            section_data = legacy_data[key]
                            break
                    if section_data:
                        self.helper.log_info(f"Processing (legacy): {stat_name}")
                        objects, refs = processor(section_data, report_date)
                        all_objects.extend(objects)
                        all_refs.extend(refs)
                        stats[stat_name] = len(objects)
            else:
                # Current format: top-level section keys
                for stat_name, json_key, enabled, processor in section_defs:
                    if not enabled:
                        continue
                    section_data = json_data.get(json_key)
                    if section_data:
                        self.helper.log_info(f"Processing: {stat_name}")
                        objects, refs = processor(section_data, report_date)
                        all_objects.extend(objects)
                        all_refs.extend(refs)
                        stats[stat_name] = len(objects)

            if len(all_objects) <= 1:
                return 0, "No objects created"

            # Daily report
            daily = Report(
                name=f"VigilIntel Daily Report - {report_date.strftime('%Y-%m-%d')}",
                description=f"Daily CTI synthesis ({self.language.upper()})",
                published=self._ts(report_date),
                created_by_ref=self.identity_id,
                object_refs=list(set(all_refs)) if all_refs else [self.identity_id],
                labels=["vigilintel", "daily-report"],
                report_types=["threat-report"],
            )
            all_objects.append(daily)

            bundle = Bundle(objects=all_objects, allow_custom=True)

            # Apply default marking (round-trip via dict to mutate immutable stix2 objects)
            if self.default_marking_id:
                bundle_dict = json.loads(bundle.serialize())
                bundle_dict = self._apply_marking_to_bundle(bundle_dict)
                self.helper.send_stix2_bundle(json.dumps(bundle_dict), update=self.update_existing_data, work_id=work_id)
            else:
                self.helper.send_stix2_bundle(bundle.serialize(), update=self.update_existing_data, work_id=work_id)

            status = f"Imported {len(all_objects)} objects ({stats})"
            self.helper.log_info(status)
            return len(all_objects), status
        except Exception as e:
            import traceback
            self.helper.log_error(f"JSON error: {str(e)}\n{traceback.format_exc()}")
            return 0, f"Error: {str(e)}"

    # ─── Report processing & scheduling ────────────────────────────────

    def _process_report(self, report_date: datetime, work_id: str) -> Tuple[bool, str]:
        date_str = report_date.strftime("%Y-%m-%d")
        self.helper.log_info(f"Processing {date_str} (format: {self.format})")

        data = self._fetch_report(self._build_report_url(report_date))
        if not data:
            self.helper.log_info(f"No report available for {date_str}, will retry next interval")
            return False, f"No report for {date_str}"

        content_hash = self._compute_content_hash(data)
        state = self.helper.get_state() or {}
        processed = state.get("processed_hashes", {})

        if processed.get(date_str) == content_hash:
            return True, f"Already processed {date_str}"

        if self.format == "stix":
            count, status = self._process_stix_bundle(data, work_id, report_date)
        else:
            count, status = self._process_json_full(data, work_id, report_date)

        if count > 0:
            processed[date_str] = content_hash
            state["processed_hashes"] = processed
            self.helper.set_state(state)

        return count > 0, status

    def _run_import(self) -> str:
        work_id = self.helper.api.work.initiate_work(self.helper.connect_id, f"VigilIntel Import ({self.format.upper()})")
        try:
            dates = self._get_dates_to_import()
            results = [f"{d.strftime('%Y-%m-%d')}: {self._process_report(d, work_id)[1]}" for d in dates]
            status = " | ".join(results)
            self.helper.api.work.to_processed(work_id, status)
            return status
        except Exception as e:
            self.helper.api.work.to_processed(work_id, f"Error: {str(e)}")
            return f"Error: {str(e)}"
        finally:
            # Always update last_run so we respect the interval even when
            # no report was available (404) or nothing was imported.
            state = self.helper.get_state() or {}
            state["last_run"] = int(datetime.now(timezone.utc).timestamp())
            self.helper.set_state(state)

    def run(self):
        self.helper.log_info(f"VigilIntel Connector v2 Starting - Format: {self.format}, Language: {self.language}")
        while True:
            try:
                state = self.helper.get_state() or {}
                last_run = state.get("last_run")
                should_run = True

                if last_run is not None:
                    # Handle both int timestamp and string ISO format
                    if isinstance(last_run, int):
                        last_run_ts = last_run
                    elif isinstance(last_run, str):
                        last_run_ts = datetime.fromisoformat(last_run.replace("Z", "+00:00")).timestamp()
                    else:
                        last_run_ts = 0

                    elapsed = int(datetime.now(timezone.utc).timestamp()) - last_run_ts
                    if elapsed < self.interval:
                        should_run = False
                        self.helper.log_info(f"Next run in {self.interval - elapsed}s")

                if should_run:
                    self._run_import()

                time.sleep(60)
            except (KeyboardInterrupt, SystemExit):
                break
            except Exception as e:
                self.helper.log_error(f"Loop error: {str(e)}")
                time.sleep(60)


if __name__ == "__main__":
    VigilIntelConnector().run()
