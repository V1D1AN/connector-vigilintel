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
        filename = f"{date_str}-report.stix_{self.language}.json" if fmt == "stix" else f"{date_str}-report_{self.language}.json"
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
            self.helper.send_stix2_bundle(json.dumps(bundle_data), update=self.update_existing_data, work_id=work_id)
            return len(objects), f"Imported {len(objects)} STIX objects"
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
            state["last_run"] = int(datetime.now(timezone.utc).timestamp())
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
