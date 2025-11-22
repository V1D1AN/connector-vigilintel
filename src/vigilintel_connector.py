#!/usr/bin/env python3

import os
import sys
import time
import yaml
import requests
import re
from datetime import datetime
from typing import Dict, List, Optional

from stix2 import Bundle, Report, Identity, ExternalReference, TLP_WHITE
from pycti import OpenCTIConnectorHelper, get_config_variable


class SimpleVigilIntelConnector:
    """
    Simple VigilIntel Connector for OpenCTI
    
    Fetches the last_report.md from GitHub and creates a Report in OpenCTI
    """
    
    def __init__(self):
        # Load config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        
        # Configuration
        self.github_base_url = "https://raw.githubusercontent.com/kidrek/VigilIntel/main"
        self.interval = get_config_variable(
            "VIGILINTEL_INTERVAL", ["vigilintel", "interval"], config, 24
        )
        
        # Handle language configuration separately to avoid int conversion
        language_config = os.getenv("VIGILINTEL_LANGUAGE", "FR")
        if not language_config:
            # Try from YAML config if env var not set
            language_config = config.get("vigilintel", {}).get("language", "FR")
        self.language = str(language_config).upper()
        
        # Log configuration for debugging
        self.helper.log_info(f"VigilIntel Connector initialized")
        self.helper.log_info(f"Configured language preference: {self.language}")
        self.helper.log_info(f"Interval: {self.interval} hours")
        
    def _get_todays_report_url(self) -> str:
        """Generate today's JSON report URL"""
        today = datetime.now()
        year = today.year
        month = today.strftime('%m')  # Zero-padded month
        date_str = today.strftime('%Y-%m-%d')
        
        url = f"{self.github_base_url}/{year}/{month}/{date_str}-report.json"
        return url
    
    def _fetch_report_content(self) -> Optional[Dict]:
        """Fetch the JSON report from GitHub"""
        try:
            today_url = self._get_todays_report_url()
            self.helper.log_info(f"Fetching JSON report from: {today_url}")
            
            response = requests.get(today_url, timeout=30)
            self.helper.log_info(f"GitHub response status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                self.helper.log_info(f"Successfully fetched JSON report ({len(response.text)} characters)")
                self.helper.log_info(f"Report contains {len(data.get('articles', []))} articles")
                return data
            elif response.status_code == 404:
                # Try yesterday's report if today's doesn't exist yet
                yesterday = datetime.now() - timedelta(days=1)
                year = yesterday.year
                month = yesterday.strftime('%m')
                date_str = yesterday.strftime('%Y-%m-%d')
                yesterday_url = f"{self.github_base_url}/{year}/{month}/{date_str}-report.json"
                
                self.helper.log_info(f"Today's report not found, trying yesterday: {yesterday_url}")
                response = requests.get(yesterday_url, timeout=30)
                
                if response.status_code == 200:
                    data = response.json()
                    self.helper.log_info(f"Successfully fetched yesterday's JSON report ({len(response.text)} characters)")
                    self.helper.log_info(f"Report contains {len(data.get('articles', []))} articles")
                    return data
                else:
                    self.helper.log_error(f"Neither today's nor yesterday's report found")
                    return None
            else:
                self.helper.log_error(f"Failed to fetch report: HTTP {response.status_code}")
                self.helper.log_error(f"Response: {response.text}")
                return None
        except Exception as e:
            self.helper.log_error(f"Error fetching report: {str(e)}")
            return None
    
    def _parse_articles_from_json(self, json_data: Dict) -> List[Dict[str, str]]:
        """Parse articles from JSON format with FR/EN structure"""
        articles = []
        
        # Handle FR/EN structure based on user configuration
        target_data = None
        
        # First try the configured language
        if self.language == "FR" and 'FR' in json_data:
            target_data = json_data['FR']
            self.helper.log_info(f"Using configured language: French (FR)")
        elif self.language == "EN" and 'EN' in json_data:
            target_data = json_data['EN']
            self.helper.log_info(f"Using configured language: English (EN)")
        
        # Fallback to any available language
        elif 'FR' in json_data and 'EN' in json_data:
            # Both languages available, choose based on preference or default to FR
            preferred_lang = self.language if self.language in ['FR', 'EN'] else 'FR'
            target_data = json_data[preferred_lang]
            self.helper.log_info(f"Both languages available, using: {preferred_lang}")
        elif 'FR' in json_data:
            target_data = json_data['FR']
            self.helper.log_info("Only French (FR) available, using FR")
        elif 'EN' in json_data:
            target_data = json_data['EN']
            self.helper.log_info("Only English (EN) available, using EN")
        elif 'Articles' in json_data:
            target_data = json_data
            self.helper.log_info("Using direct Articles structure")
        elif 'articles' in json_data:
            target_data = json_data
            self.helper.log_info("Using direct articles structure")
        else:
            self.helper.log_warning("No recognized structure found in JSON data")
            self.helper.log_info(f"Available keys: {list(json_data.keys())}")
            return articles
        
        # Try both 'Articles' (capital A) and 'articles' (lowercase)
        json_articles = target_data.get('Articles', target_data.get('articles', []))
        
        if not json_articles:
            self.helper.log_warning("No articles found in target section")
            self.helper.log_info(f"Available keys in target section: {list(target_data.keys()) if target_data else 'None'}")
            return articles
        
        self.helper.log_info(f"Found {len(json_articles)} articles in JSON")
        
        for i, article_data in enumerate(json_articles):
            try:
                # Extract article information using actual VigilIntel field names
                title = article_data.get('title', f'Article {i+1}')
                description = article_data.get('description', '')
                analysis = article_data.get('analyse', '')  # French field name
                recommendations = article_data.get('recommandations', '')
                
                # Extract source URLs
                sources = article_data.get('sources', [])
                source_url = ''
                if isinstance(sources, list) and sources:
                    source_url = sources[0] if isinstance(sources[0], str) else ''
                elif isinstance(sources, str):
                    source_url = sources
                
                # Combine all content fields for full description
                content_parts = []
                if description:
                    content_parts.append(f"Description:\n{description}")
                if analysis:
                    content_parts.append(f"Analyse:\n{analysis}")
                if recommendations:
                    content_parts.append(f"Recommandations:\n{recommendations}")
                
                full_content = "\n\n".join(content_parts).strip()
                
                if title and full_content:
                    articles.append({
                        'title': title,
                        'content': full_content,
                        'url': source_url,
                        'json_data': article_data  # Keep original JSON for IOC extraction
                    })
                    
                    self.helper.log_info(f"Parsed article: {title[:50]}... ({len(full_content)} chars)")
                else:
                    self.helper.log_warning(f"Article {i+1} missing title or content")
                    self.helper.log_info(f"Article keys: {list(article_data.keys())}")
                    
            except Exception as e:
                self.helper.log_error(f"Error parsing article {i+1}: {str(e)}")
                continue
        
        self.helper.log_info(f"Successfully parsed {len(articles)} articles from JSON")
        return articles
    
    def _extract_iocs_from_json_article(self, article_json: Dict) -> Dict[str, List[str]]:
        """Extract IOCs from JSON article data using VigilIntel structure"""
        iocs = {}
        
        # Look for IOCs in different locations specific to VigilIntel structure
        ioc_sources = []
        
        # 1. Main IOC field: 'indicator_of_compromise'
        ioc_field = article_json.get('indicator_of_compromise', '')
        if ioc_field:
            ioc_sources.append(('indicator_of_compromise', ioc_field))
            self.helper.log_info(f"Found 'indicator_of_compromise' field: {type(ioc_field)}")
        
        # 2. Analysis field (might contain IOCs)
        analysis_field = article_json.get('analyse', '')
        if analysis_field:
            ioc_sources.append(('analyse', analysis_field))
        
        # 3. Description field (might mention IOCs)
        description_field = article_json.get('description', '')
        if description_field:
            ioc_sources.append(('description', description_field))
        
        # 4. Legacy direct IOCs field (if exists)
        direct_iocs = article_json.get('iocs', article_json.get('IOCs', {}))
        if direct_iocs:
            ioc_sources.append(('direct_iocs', direct_iocs))
        
        self.helper.log_info(f"Found {len(ioc_sources)} IOC sources in JSON article")
        
        for source_name, source_data in ioc_sources:
            self.helper.log_info(f"Processing IOC source: {source_name}")
            
            if not source_data:
                continue
            
            # Handle different data types
            if isinstance(source_data, list):
                # VigilIntel uses lists for indicator_of_compromise
                self.helper.log_info(f"  Processing list with {len(source_data)} items")
                for item in source_data:
                    if isinstance(item, str) and item.strip():
                        # Skip negative indicators
                        item_lower = item.lower()
                        if any(skip_phrase in item_lower for skip_phrase in [
                            "aucun ioc", "no ioc", "no specific", "non fourni", 
                            "not provided", "non disponible", "unavailable"
                        ]):
                            self.helper.log_info(f"    Skipping negative indicator: {item}")
                            continue
                        
                        # Clean brackets notation ([.] -> .)
                        cleaned_item = item.replace('[.]', '.').replace('[:]', ':')
                        
                        # Try to extract IOCs using regex patterns
                        extracted_iocs = self._extract_iocs_from_text(cleaned_item)
                        if extracted_iocs:
                            for ioc_type, values in extracted_iocs.items():
                                if values:
                                    iocs.setdefault(ioc_type, []).extend(values)
                                    self.helper.log_info(f"    Extracted {len(values)} {ioc_type}s: {values}")
                        else:
                            # If no regex match but looks like a valid IOC, try individual patterns
                            cleaned_lower = cleaned_item.lower().strip()
                            
                            # Check if it's a hash (MD5, SHA1, SHA256)
                            if len(cleaned_item) == 32 and all(c in '0123456789abcdefABCDEF' for c in cleaned_item):
                                iocs.setdefault('md5', []).append(cleaned_item.lower())
                                self.helper.log_info(f"    Added MD5 hash: {cleaned_item}")
                            elif len(cleaned_item) == 40 and all(c in '0123456789abcdefABCDEF' for c in cleaned_item):
                                iocs.setdefault('sha1', []).append(cleaned_item.lower())
                                self.helper.log_info(f"    Added SHA1 hash: {cleaned_item}")
                            elif len(cleaned_item) == 64 and all(c in '0123456789abcdefABCDEF' for c in cleaned_item):
                                iocs.setdefault('sha256', []).append(cleaned_item.lower())
                                self.helper.log_info(f"    Added SHA256 hash: {cleaned_item}")
                            # Check if it's a domain (contains dots and valid TLD)
                            elif ('.' in cleaned_item and 
                                  not cleaned_item.startswith('http') and 
                                  len(cleaned_item.split('.')) >= 2 and
                                  not any(char in cleaned_item for char in [' ', '\n', '\t']) and
                                  len(cleaned_item) < 100):
                                iocs.setdefault('domain', []).append(cleaned_item)
                                self.helper.log_info(f"    Added domain: {cleaned_item}")
                            # If none of the above but contains useful info, treat as malware name
                            elif (len(cleaned_item) > 2 and 
                                  not any(char in cleaned_item for char in ['http', '://', '@']) and
                                  len(cleaned_item) < 50):
                                # Only add as malware name if it looks like one
                                if not ('.' in cleaned_item and len(cleaned_item.split('.')) > 2):
                                    iocs.setdefault('malware_name', []).append(cleaned_item)
                                    self.helper.log_info(f"    Added malware name: {cleaned_item}")
            
            elif isinstance(source_data, str):
                # Text content - extract using regex
                if len(source_data.strip()) > 0:
                    extracted_iocs = self._extract_iocs_from_text(source_data)
                    for ioc_type, values in extracted_iocs.items():
                        if values:
                            iocs.setdefault(ioc_type, []).extend(values)
                            self.helper.log_info(f"  Extracted {len(values)} {ioc_type}s from {source_name}")
            
            elif isinstance(source_data, dict):
                # Structured IOC data
                ioc_mapping = {
                    'domains': 'domain',
                    'domain': 'domain',
                    'domaines': 'domain',
                    'ips': 'ip', 
                    'ip': 'ip',
                    'urls': 'url',
                    'url': 'url',
                    'hashes': 'hash',
                    'hash': 'hash',
                    'emails': 'email',
                    'email': 'email',
                    'cves': 'cve',
                    'cve': 'cve',
                    'files': 'file_path',
                    'file': 'file_path',
                    'registry_keys': 'registry_key',
                    'registry': 'registry_key'
                }
                
                for json_key, values in source_data.items():
                    our_key = ioc_mapping.get(json_key.lower(), json_key.lower())
                    
                    if isinstance(values, list) and values:
                        filtered_values = self._filter_iocs_by_type(values, our_key)
                        if filtered_values:
                            iocs.setdefault(our_key, []).extend(filtered_values)
                            self.helper.log_info(f"  Extracted {len(filtered_values)} {our_key}s from {source_name}.{json_key}")
                    
                    elif isinstance(values, dict) and json_key.lower() == 'hashes':
                        # Handle nested hash structure
                        for hash_type, hash_values in values.items():
                            if isinstance(hash_values, list):
                                filtered_values = self._filter_iocs_by_type(hash_values, hash_type)
                                if filtered_values:
                                    iocs.setdefault(hash_type, []).extend(filtered_values)
                                    self.helper.log_info(f"  Extracted {len(filtered_values)} {hash_type}s from {source_name}")
                    
                    elif isinstance(values, str) and values.strip():
                        # Single value as string
                        filtered_values = self._filter_iocs_by_type([values], our_key)
                        if filtered_values:
                            iocs.setdefault(our_key, []).extend(filtered_values)
        
        # Deduplicate all IOCs
        for ioc_type in iocs:
            iocs[ioc_type] = list(set(iocs[ioc_type]))
        
        total_iocs = sum(len(v) for v in iocs.values())
        self.helper.log_info(f"Extracted {total_iocs} total IOCs from JSON article")
        
        if iocs:
            for ioc_type, values in iocs.items():
                self.helper.log_info(f"  - {ioc_type}: {len(values)} items")
                for value in values:
                    self.helper.log_info(f"    * {value}")
        else:
            self.helper.log_info("No IOCs extracted from this article")
        
        return iocs
    
    def _extract_iocs_from_text(self, text: str) -> Dict[str, List[str]]:
        """Extract IOCs from text using regex patterns"""
        iocs = {}
        
        patterns = {
            'ip': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            'domain': re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'),
            'url': re.compile(r'https?://[^\s\'"<>\]\)]+'),
            'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
            'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
            'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'cve': re.compile(r'CVE-\d{4}-\d{4,7}'),
        }
        
        for ioc_type, pattern in patterns.items():
            matches = pattern.findall(text)
            if matches:
                filtered = self._filter_iocs_by_type(matches, ioc_type)
                if filtered:
                    iocs[ioc_type] = filtered
        
        return iocs
    
    def _extract_mitre_ttps_from_json_article(self, article_json: Dict) -> List[Dict[str, str]]:
        """Extract MITRE TTPs from JSON article data"""
        ttps = []
        
        mitre_ttps_field = article_json.get('mitre_ttps', [])
        if not mitre_ttps_field:
            self.helper.log_info("No MITRE TTPs found in article")
            return ttps
        
        self.helper.log_info(f"Found {len(mitre_ttps_field)} MITRE TTPs in article")
        
        for ttp_entry in mitre_ttps_field:
            if not isinstance(ttp_entry, str):
                continue
                
            try:
                # Parse TTP format: "TA0001:Initial Access" or "T1566.001:Phishing (Social Engineering)"
                if ':' in ttp_entry:
                    technique_id, technique_name = ttp_entry.split(':', 1)
                    technique_id = technique_id.strip()
                    technique_name = technique_name.strip()
                    
                    # Clean technique name (remove parentheses content)
                    if '(' in technique_name:
                        technique_name = technique_name.split('(')[0].strip()
                    
                    ttps.append({
                        'id': technique_id,
                        'name': technique_name,
                        'full_description': ttp_entry
                    })
                    
                    self.helper.log_info(f"Parsed TTP: {technique_id} - {technique_name}")
                else:
                    # Fallback for non-standard format
                    ttps.append({
                        'id': ttp_entry,
                        'name': ttp_entry,
                        'full_description': ttp_entry
                    })
                    
            except Exception as e:
                self.helper.log_warning(f"Error parsing TTP '{ttp_entry}': {str(e)}")
                continue
        
        self.helper.log_info(f"Successfully parsed {len(ttps)} MITRE TTPs")
        return ttps
    
    def _create_attack_patterns_from_ttps(self, ttps: List[Dict[str, str]], article_title: str) -> List:
        """Create STIX2 Attack Patterns from MITRE TTPs"""
        attack_patterns = []
        
        for ttp in ttps:
            try:
                from stix2 import AttackPattern
                
                # Create external reference to MITRE ATT&CK
                external_refs = []
                technique_id = ttp['id']
                
                # Only add MITRE reference for valid technique IDs
                if technique_id.startswith('T'):
                    external_refs.append({
                        'source_name': 'mitre-attack',
                        'external_id': technique_id,
                        'url': f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}"
                    })
                elif technique_id.startswith('TA'):
                    external_refs.append({
                        'source_name': 'mitre-attack',
                        'external_id': technique_id,
                        'url': f"https://attack.mitre.org/tactics/{technique_id}"
                    })
                
                # Create Attack Pattern
                attack_pattern = AttackPattern(
                    name=ttp['name'],
                    description=f"MITRE ATT&CK technique {ttp['full_description']} identified in VigilIntel article: {article_title}",
                    external_references=external_refs,
                    custom_properties={
                        "x_opencti_detection": True,
                        "x_mitre_id": technique_id,
                        "x_vigilintel_article_title": article_title,
                        "x_vigilintel_ttp_description": ttp['full_description'],
                    }
                )
                
                attack_patterns.append(attack_pattern)
                self.helper.log_info(f"Created Attack Pattern for: {technique_id} - {ttp['name']}")
                
            except Exception as e:
                self.helper.log_warning(f"Failed to create Attack Pattern for TTP '{ttp['id']}': {str(e)}")
                continue
        
        return attack_patterns
        """Extract IOCs from text using regex patterns"""
        iocs = {}
        
        patterns = {
            'ip': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            'domain': re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'),
            'url': re.compile(r'https?://[^\s\'"<>\]\)]+'),
            'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
            'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
            'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'cve': re.compile(r'CVE-\d{4}-\d{4,7}'),
        }
        
        for ioc_type, pattern in patterns.items():
            matches = pattern.findall(text)
            if matches:
                filtered = self._filter_iocs_by_type(matches, ioc_type)
                if filtered:
                    iocs[ioc_type] = filtered
        
        return iocs
    
    def _filter_iocs_by_type(self, values: List[str], ioc_type: str) -> List[str]:
        """Filter IOCs based on their type"""
        filtered = []
        
        for value in values:
            if not value or not isinstance(value, str):
                continue
                
            value = value.strip()
            
            if ioc_type == 'ip':
                if not self._is_private_ip(value) and '.' in value:
                    filtered.append(value)
            elif ioc_type == 'domain':
                clean_domain = value.lower().strip('.,;:!?)')
                if (len(clean_domain) > 4 and 
                    '.' in clean_domain and
                    not clean_domain.startswith('.') and
                    len(clean_domain.split('.')[-1]) >= 2):
                    filtered.append(clean_domain)
            elif ioc_type == 'url':
                clean_url = value.rstrip('.,;:!?)"\'')
                if len(clean_url) > 10 and clean_url.startswith('http'):
                    filtered.append(clean_url)
            elif ioc_type in ['md5', 'sha1', 'sha256', 'sha512', 'hash']:
                # Validate hash format
                if re.match(r'^[a-fA-F0-9]+$', value):
                    filtered.append(value.lower())
            else:
                # For other types (email, cve, file_path, etc.), minimal filtering
                filtered.append(value)
        
        return list(set(filtered))  # Remove duplicates
    
    def _extract_url_from_content(self, content: str) -> str:
        """Extract URL from article content"""
        import re
        # Chercher une URL dans le contenu
        url_pattern = r'https?://[^\s\)]+' 
        urls = re.findall(url_pattern, content)
        return urls[0] if urls else ""
    
    def _extract_iocs_from_article(self, content: str) -> Dict[str, List[str]]:
        """Extract IOCs only from the IOC section of the article"""
        iocs = {}
        
        # Find the IOC section in the article
        lines = content.split('\n')
        ioc_section_content = []
        in_ioc_section = False
        
        for line in lines:
            # Detect start of IOC section
            if "### Indicateurs de compromission (IoCs)" in line:
                in_ioc_section = True
                self.helper.log_info("Found IOC section in article")
                continue
            
            # Detect end of IOC section (next ### section or ## section)
            if in_ioc_section and (line.startswith('###') or line.startswith('##')):
                break
            
            # Collect IOC section content
            if in_ioc_section:
                ioc_section_content.append(line)
        
        if not ioc_section_content:
            self.helper.log_info("No IOC section found in article")
            return iocs
        
        # Join IOC section content
        ioc_text = '\n'.join(ioc_section_content).strip()
        self.helper.log_info(f"IOC section content: {len(ioc_text)} characters")
        
        if len(ioc_text) < 10:  # Very short or empty IOC section
            return iocs
        
        # IOC patterns optimisés pour le contenu d'IOCs
        patterns = {
            'ip': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            'domain': re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'),
            'url': re.compile(r'https?://[^\s\'"<>\]\)]+'),
            'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
            'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
            'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'cve': re.compile(r'CVE-\d{4}-\d{4,7}'),
            'file_path': re.compile(r'[A-Za-z]:\\[^<>:"|?*\s]+\.[a-zA-Z]{2,4}'),
            'registry_key': re.compile(r'(?:HKEY_|HKLM\\|HKCU\\)[^\\<>:"|?*\s]+'),
            'mutex': re.compile(r'\\Sessions\\[0-9]+\\BaseNamedObjects\\[a-zA-Z0-9_-]+'),
        }
        
        # Exclusions minimales pour IOCs (car c'est du contenu spécifique IOC)
        excluded_domains = {
            'example.com', 'test.com', 'localhost', 'domain.com',
            'email.com', 'website.com', 'company.com', 'sample.com'
        }
        
        excluded_ips = {
            '0.0.0.0', '127.0.0.1', '255.255.255.255'
        }
        
        for ioc_type, pattern in patterns.items():
            matches = pattern.findall(ioc_text)
            if matches:
                filtered_matches = []
                
                for match in matches:
                    # Filtrage minimal car on est dans une section IOC dédiée
                    if ioc_type == 'ip':
                        if not self._is_private_ip(match) and match not in excluded_ips:
                            filtered_matches.append(match)
                    elif ioc_type == 'domain':
                        clean_domain = match.lower().strip('.,;:!?)')
                        if (clean_domain not in excluded_domains and 
                            len(clean_domain) > 4 and
                            not clean_domain.startswith('.') and
                            '.' in clean_domain and
                            # Validation minimale pour les domaines IOC
                            len(clean_domain.split('.')[-1]) >= 2):
                            filtered_matches.append(clean_domain)
                    elif ioc_type == 'url':
                        clean_url = match.rstrip('.,;:!?)"\'')
                        if len(clean_url) > 10:
                            filtered_matches.append(clean_url)
                    elif ioc_type in ['md5', 'sha1', 'sha256']:
                        if not any(char.isalpha() and char.lower() not in 'abcdef' for char in match.lower()):
                            filtered_matches.append(match.lower())
                    else:
                        filtered_matches.append(match)
                
                if filtered_matches:
                    iocs[ioc_type] = list(set(filtered_matches))  # Déduplication
        
        self.helper.log_info(f"Extracted IOCs from IOC section: {sum(len(v) for v in iocs.values())} total")
        
        return iocs
    
    def _is_private_ip(self, ip_str: str) -> bool:
        """Check if IP is private/internal"""
        try:
            import ipaddress
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private or ip.is_loopback or ip.is_multicast
        except:
            return True
    
    def _create_vulnerabilities_from_cves(self, cves: List[str], article_title: str, article_url: str) -> List:
        """Create STIX2 Vulnerability entities from CVE IOCs"""
        vulnerabilities = []
        
        for cve in cves:
            try:
                from stix2 import Vulnerability
                
                # Create external reference to MITRE CVE
                external_refs = []
                external_refs.append({
                    'source_name': 'cve',
                    'external_id': cve,
                    'url': f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}"
                })
                
                # Create Vulnerability
                vulnerability = Vulnerability(
                    name=cve,
                    description=f"CVE vulnerability {cve} identified in VigilIntel article: {article_title}",
                    external_references=external_refs,
                    custom_properties={
                        "x_opencti_cvss_base_score": 7.5,  # Default score, can be updated
                        "x_vigilintel_article_title": article_title,
                        "x_vigilintel_source_url": article_url,
                    }
                )
                
                vulnerabilities.append(vulnerability)
                self.helper.log_info(f"Created Vulnerability for: {cve}")
                
            except Exception as e:
                self.helper.log_warning(f"Failed to create Vulnerability for CVE '{cve}': {str(e)}")
                continue
        
        return vulnerabilities
    
    def _create_indicators_from_iocs(self, iocs: Dict[str, List[str]], article_title: str, article_url: str) -> List:
        """Create STIX2 Indicators from extracted IOCs"""
        indicators = []
        
        # Mapping IOC types vers STIX patterns
        def create_file_path_pattern(x):
            escaped_path = x.replace('\\', '\\\\')
            return f"[file:parent_directory_ref.path = '{escaped_path}']"
        
        stix_patterns = {
            'ip': lambda x: f"[ipv4-addr:value = '{x}']",
            'domain': lambda x: f"[domain-name:value = '{x}']", 
            'url': lambda x: f"[url:value = '{x}']",
            'md5': lambda x: f"[file:hashes.MD5 = '{x}']",
            'sha1': lambda x: f"[file:hashes.SHA1 = '{x}']",
            'sha256': lambda x: f"[file:hashes.SHA256 = '{x}']",
            'email': lambda x: f"[email-addr:value = '{x}']",
            'file_path': create_file_path_pattern,
            'registry_key': lambda x: f"[windows-registry-key:key = '{x}']",
            'malware_name': lambda x: f"[malware:name = '{x}']",
        }
        
        for ioc_type, values in iocs.items():
            if ioc_type not in stix_patterns:
                self.helper.log_warning(f"Unsupported IOC type for STIX pattern: {ioc_type}")
                continue
                
            for value in values:
                try:
                    pattern = stix_patterns[ioc_type](value)
                    
                    # Déterminer les labels appropriés
                    labels = ["malicious-activity"]
                    if ioc_type in ['ip', 'domain', 'url']:
                        labels.append("malicious-infrastructure")
                    elif ioc_type in ['md5', 'sha1', 'sha256']:
                        labels.append("malware")
                    elif ioc_type == 'cve':
                        labels = ["vulnerability"]
                    elif ioc_type == 'malware_name':
                        labels = ["malicious-activity", "malware"]
                    
                    # Créer l'indicateur
                    from stix2 import Indicator
                    indicator = Indicator(
                        pattern=pattern,
                        pattern_type="stix",
                        labels=labels,
                        description=f"{ioc_type.upper().replace('_', ' ')} extracted from VigilIntel article: {article_title}",
                        custom_properties={
                            "x_opencti_score": 70,
                            "x_opencti_detection": True,
                            "x_vigilintel_article_title": article_title,
                            "x_vigilintel_source_url": article_url,
                            "x_vigilintel_ioc_type": ioc_type,
                        }
                    )
                    indicators.append(indicator)
                    self.helper.log_info(f"Created indicator for {ioc_type}: {value}")
                    
                except Exception as e:
                    self.helper.log_warning(f"Failed to create indicator for {ioc_type} '{value}': {str(e)}")
                    continue
        
        return indicators
        """Extract title and date from markdown content"""
        lines = content.split('\n')
        
        # Look for meaningful title (skip table of contents and generic titles)
        title = "VigilIntel Daily Report"
        skip_titles = ['table des matières', 'table of contents', 'sommaire', 'index']
        
        for line in lines[:20]:  # Check first 20 lines
            if line.startswith('# '):
                potential_title = line[2:].strip().lower()
                # Skip generic titles
                if not any(skip in potential_title for skip in skip_titles):
                    title = line[2:].strip()
                    break
        
        # If no good title found, try to create one from date
        date_match = re.search(r'\d{4}-\d{2}-\d{2}', content)
        if date_match and title == "VigilIntel Daily Report":
            date_str = date_match.group()
            title = f"VigilIntel Daily Report - {date_str}"
        
        # Format date for STIX2
        if date_match:
            try:
                date_str = date_match.group()
                # Parse date and add time + Z suffix for STIX2
                parsed_date = datetime.strptime(date_str, '%Y-%m-%d')
                date = parsed_date.strftime('%Y-%m-%dT%H:%M:%SZ')
            except:
                date = datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')
        else:
            date = datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')
            
        return title, date
    
    def _create_article_stix_bundle_from_json(self, article: Dict[str, str]) -> Optional[Bundle]:
        """Create STIX2 Bundle for an individual article from JSON data"""
        
        try:
            # Clean and prepare article data
            article_title = article['title'].strip()
            article_content = article['content'].strip()
            article_url = article['url']
            article_json = article.get('json_data', {})
            
            if not article_title or not article_content:
                self.helper.log_warning(f"Skipping article with missing title or content")
                return None
            
            # Extract IOCs from JSON data
            self.helper.log_info(f"Extracting IOCs from JSON article: {article_title[:50]}...")
            iocs = self._extract_iocs_from_json_article(article_json)
            
            # Extract MITRE TTPs from JSON data
            self.helper.log_info(f"Extracting MITRE TTPs from JSON article: {article_title[:50]}...")
            ttps = self._extract_mitre_ttps_from_json_article(article_json)
            
            # Separate CVEs from other IOCs
            cves = iocs.pop('cve', [])  # Remove CVEs from IOCs dict
            
            # Create indicators from non-CVE IOCs
            indicators = self._create_indicators_from_iocs(iocs, article_title, article_url)
            
            # Create vulnerabilities from CVEs
            vulnerabilities = self._create_vulnerabilities_from_cves(cves, article_title, article_url)
            
            # Create attack patterns from TTPs
            attack_patterns = self._create_attack_patterns_from_ttps(ttps, article_title)
            
            self.helper.log_info(f"Found {len(indicators)} indicators from {sum(len(v) for v in iocs.values())} non-CVE IOCs")
            self.helper.log_info(f"Found {len(vulnerabilities)} vulnerabilities from {len(cves)} CVEs")
            self.helper.log_info(f"Found {len(attack_patterns)} attack patterns from {len(ttps)} TTPs")
            
            if iocs:
                for ioc_type, values in iocs.items():
                    self.helper.log_info(f"  - {ioc_type}: {len(values)} items")
            
            if cves:
                self.helper.log_info(f"  - CVEs: {len(cves)} items")
                for cve in cves:
                    self.helper.log_info(f"    * {cve}")
            
            if ttps:
                for ttp in ttps:
                    self.helper.log_info(f"  - TTP: {ttp['id']} - {ttp['name']}")
            
            # Create author identity for VigilIntel
            author = Identity(
                name="VigilIntel",
                identity_class="organization",
                description="Cyber Threat Intelligence aggregation platform providing daily threat summaries"
            )
            
            # Create external references
            external_refs = []
            
            # Add GitHub source reference (today's report)
            today_url = self._get_todays_report_url()
            external_refs.append(
                ExternalReference(
                    source_name="VigilIntel GitHub JSON",
                    url=today_url,
                    description="VigilIntel daily threat intelligence report in JSON format"
                )
            )
            
            # Add original article URL if available
            if article_url:
                external_refs.append(
                    ExternalReference(
                        source_name="Original Article",
                        url=article_url,
                        description="Source article referenced in VigilIntel report"
                    )
                )
            
            # Get current date for report
            current_date = datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')
            
            # Create object references (author + indicators + vulnerabilities + attack patterns)
            object_refs = [author.id] + [indicator.id for indicator in indicators] + [vuln.id for vuln in vulnerabilities] + [ap.id for ap in attack_patterns]
            
            # Create the report object for this article
            report = Report(
                name=article_title,
                description=article_content,  # Full article content goes in description
                published=current_date,
                report_types=["threat-report"],
                created_by_ref=author.id,
                object_refs=object_refs,
                external_references=external_refs,
                object_marking_refs=[TLP_WHITE],
                custom_properties={
                    "x_opencti_report_status": 3,  # Published
                    "x_opencti_main_observable_type": "Report",
                    "x_vigilintel_source": "github-json",
                    "x_vigilintel_article_url": article_url,
                    "x_vigilintel_content_length": len(article_content),
                    "x_vigilintel_iocs_count": sum(len(v) for v in iocs.values()),
                    "x_vigilintel_cves_count": len(cves),
                    "x_vigilintel_indicators_count": len(indicators),
                    "x_vigilintel_vulnerabilities_count": len(vulnerabilities),
                    "x_vigilintel_ttps_count": len(ttps),
                    "x_vigilintel_attack_patterns_count": len(attack_patterns),
                    "x_vigilintel_report_date": datetime.now().strftime('%Y-%m-%d'),
                }
            )
            
            # Create bundle with all objects
            bundle_objects = [author, report] + indicators + vulnerabilities + attack_patterns
            bundle = Bundle(objects=bundle_objects, allow_custom=True)
            
            self.helper.log_info(f"Created bundle with {len(bundle_objects)} objects (1 author + 1 report + {len(indicators)} indicators + {len(vulnerabilities)} vulnerabilities + {len(attack_patterns)} attack patterns)")
            
            return bundle
            
        except Exception as e:
            self.helper.log_error(f"Error creating bundle for article '{article.get('title', 'unknown')}': {str(e)}")
            return None
        """Create STIX2 Bundle for an individual article with IOC extraction"""
        
        try:
            # Clean and prepare article data
            article_title = article['title'].strip()
            article_content = article['content'].strip()
            article_url = article['url']
            
            if not article_title or not article_content:
                self.helper.log_warning(f"Skipping article with missing title or content")
                return None
            
            # Extract IOCs from article content
            self.helper.log_info(f"Extracting IOCs from article: {article_title[:50]}...")
            iocs = self._extract_iocs_from_article(article_content)
            
            # Create indicators from IOCs
            indicators = self._create_indicators_from_iocs(iocs, article_title, article_url)
            
            self.helper.log_info(f"Found {len(indicators)} indicators from {sum(len(v) for v in iocs.values())} IOCs")
            if iocs:
                for ioc_type, values in iocs.items():
                    self.helper.log_info(f"  - {ioc_type}: {len(values)} items")
            
            # Create author identity for VigilIntel
            author = Identity(
                name="VigilIntel",
                identity_class="organization",
                description="Cyber Threat Intelligence aggregation platform providing daily threat summaries"
            )
            
            # Create external references
            external_refs = []
            
            # Add GitHub source reference (today's report)
            today_url = self._get_todays_report_url()
            external_refs.append(
                ExternalReference(
                    source_name="VigilIntel GitHub JSON",
                    url=today_url,
                    description="VigilIntel daily threat intelligence report in JSON format"
                )
            )
            
            # Add original article URL if available
            if article_url:
                external_refs.append(
                    ExternalReference(
                        source_name="Original Article",
                        url=article_url,
                        description="Source article referenced in VigilIntel report"
                    )
                )
            
            # Get current date for report
            current_date = datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')
            
            # Create object references (author + indicators)
            object_refs = [author.id] + [indicator.id for indicator in indicators]
            
            # Create the report object for this article
            report = Report(
                name=article_title,
                description=article_content,  # Full article content goes in description
                published=current_date,
                report_types=["threat-report"],
                created_by_ref=author.id,
                object_refs=object_refs,
                external_references=external_refs,
                object_marking_refs=[TLP_WHITE],
                custom_properties={
                    "x_opencti_report_status": 3,  # Published
                    "x_opencti_main_observable_type": "Report",
                    "x_vigilintel_source": "github",
                    "x_vigilintel_article_url": article_url,
                    "x_vigilintel_content_length": len(article_content),
                    "x_vigilintel_iocs_count": sum(len(v) for v in iocs.values()),
                    "x_vigilintel_indicators_count": len(indicators),
                }
            )
            
            # Create bundle with all objects
            bundle_objects = [author, report] + indicators
            bundle = Bundle(objects=bundle_objects, allow_custom=True)
            
            self.helper.log_info(f"Created bundle with {len(bundle_objects)} objects (1 author + 1 report + {len(indicators)} indicators)")
            
            return bundle
            
        except Exception as e:
            self.helper.log_error(f"Error creating bundle for article '{article.get('title', 'unknown')}': {str(e)}")
            return None
        """Create STIX2 Bundle from markdown content"""
        
        self.helper.log_info("Extracting title and date from content...")
        title, report_date = self._extract_title_and_date(content)
        self.helper.log_info(f"Extracted - Title: {title}, Date: {report_date}")
        
        # Create author identity for VigilIntel
        author = Identity(
            name="VigilIntel",
            identity_class="organization", 
            description="Cyber Threat Intelligence aggregation platform providing daily threat summaries"
        )
        self.helper.log_info(f"Created author identity: {author.id}")
        
        # Create external reference
        external_refs = [
            ExternalReference(
                source_name="VigilIntel GitHub (Legacy)",
                url=f"{self.github_base_url}/last_report.md",
                description="VigilIntel legacy markdown report (fallback)"
            )
        ]
        
        # Create the report object
        self.helper.log_info("Creating report object...")
        report = Report(
            name=title,
            description="Daily threat intelligence report aggregated from RSS feeds",
            published=report_date,
            report_types=["threat-report"],
            created_by_ref=author.id,  # Reference to the author
            object_refs=[author.id],  # Objects referenced by this report
            external_references=external_refs,
            object_marking_refs=[TLP_WHITE],
            custom_properties={
                "x_opencti_report_status": 3,  # Published
                "x_opencti_main_observable_type": "Report",
                "x_vigilintel_source": "github",
                "x_vigilintel_content": content[:10000],  # Store content (limit to 10k chars)
            }
        )
        self.helper.log_info(f"Created report: {report.id}")
        
        bundle = Bundle(objects=[author, report], allow_custom=True)
        self.helper.log_info(f"Created bundle: {bundle.id}")
        return bundle
    
    def _process_message(self, data: Dict) -> str:
        """Process the JSON report and create individual reports for each article"""
        self.helper.log_info("Fetching VigilIntel JSON report from GitHub...")
        
        # Fetch JSON content
        json_data = self._fetch_report_content()
        if not json_data:
            return "Failed to fetch JSON report content"
        
        # Create a unique hash for the report
        import json
        content_str = json.dumps(json_data, sort_keys=True)
        content_hash = hash(content_str)
        current_state = self.helper.get_state()
        
        self.helper.log_info(f"Content hash: {content_hash}")
        if current_state:
            self.helper.log_info(f"Previous hash: {current_state.get('last_content_hash', 'None')}")
        
        if current_state and current_state.get("last_content_hash") == content_hash:
            return "No new content detected (hash unchanged)"
        
        try:
            self.helper.log_info("Parsing articles from JSON...")
            
            # Parse individual articles from JSON
            articles = self._parse_articles_from_json(json_data)
            
            if not articles:
                return "No articles found in JSON data"
            
            self.helper.log_info(f"Found {len(articles)} articles to process")
            
            processed_count = 0
            total_indicators = 0
            total_vulnerabilities = 0
            total_attack_patterns = 0
            
            # Create a report for each article
            for i, article in enumerate(articles):
                try:
                    self.helper.log_info(f"Processing article {i+1}/{len(articles)}: {article['title'][:50]}...")
                    
                    # Create STIX bundle for this article
                    bundle = self._create_article_stix_bundle_from_json(article)
                    
                    if bundle:
                        # Send to OpenCTI
                        bundle_str = bundle.serialize(pretty=True)
                        
                        result = self.helper.send_stix2_bundle(
                            bundle_str,
                            update=False,
                            work_id=data.get("work_id")
                        )
                        
                        processed_count += 1
                        
                        # Count different object types in this bundle
                        indicators_count = len([obj for obj in bundle.objects if obj._type == 'indicator'])
                        vulnerabilities_count = len([obj for obj in bundle.objects if obj._type == 'vulnerability'])
                        attack_patterns_count = len([obj for obj in bundle.objects if obj._type == 'attack-pattern'])
                        total_indicators += indicators_count
                        total_vulnerabilities += vulnerabilities_count
                        total_attack_patterns += attack_patterns_count
                        
                        self.helper.log_info(f"Successfully created report for: {article['title'][:50]} ({indicators_count} indicators, {vulnerabilities_count} vulnerabilities, {attack_patterns_count} attack patterns)")
                        
                        # Small delay to avoid overwhelming OpenCTI
                        time.sleep(0.5)
                    
                except Exception as e:
                    self.helper.log_error(f"Error processing article '{article['title'][:50]}': {str(e)}")
                    continue
            
            # Update state
            new_state = current_state or {}
            new_state["last_content_hash"] = content_hash
            new_state["last_update"] = datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')
            new_state["last_articles_count"] = len(articles)
            new_state["last_processed_count"] = processed_count
            new_state["last_indicators_count"] = total_indicators
            new_state["last_vulnerabilities_count"] = total_vulnerabilities
            new_state["last_attack_patterns_count"] = total_attack_patterns
            self.helper.set_state(new_state)
            
            return f"Successfully processed {processed_count}/{len(articles)} articles with {total_indicators} indicators, {total_vulnerabilities} vulnerabilities and {total_attack_patterns} attack patterns"
            
        except Exception as e:
            self.helper.log_error(f"Error processing JSON articles: {str(e)}")
            import traceback
            self.helper.log_error(f"Full traceback: {traceback.format_exc()}")
            return f"Error: {str(e)}"
    
    def run(self):
        """Main connector loop"""
        self.helper.log_info("Starting Simple VigilIntel connector...")
        self.helper.log_info(f"GitHub Base URL: {self.github_base_url}")
        self.helper.log_info(f"Check interval: {self.interval} hours")
        
        while True:
            try:
                timestamp = int(time.time())
                current_state = self.helper.get_state()
                
                if current_state and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    self.helper.log_info(f"Last run: {datetime.fromtimestamp(last_run)}")
                else:
                    last_run = None
                    self.helper.log_info("First run")
                
                # Check if we need to run
                force_run = os.getenv('FORCE_RUN', 'false').lower() == 'true'
                
                if force_run or last_run is None or (timestamp - last_run) >= (self.interval * 3600):
                    
                    # Create work
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, "VigilIntel GitHub report import"
                    )
                    
                    # Process report
                    result = self._process_message({"work_id": work_id})
                    
                    # Update state
                    if not current_state:
                        current_state = {}
                    current_state["last_run"] = timestamp
                    self.helper.set_state(current_state)
                    
                    # Complete work
                    self.helper.api.work.to_processed(work_id, result)
                    
                    self.helper.log_info(f"Completed: {result}")
                else:
                    next_run = (self.interval * 3600) - (timestamp - last_run)
                    self.helper.log_info(f"Next run in {next_run/3600:.1f} hours")
                
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stopped")
                sys.exit(0)
            except Exception as e:
                self.helper.log_error(f"Error: {str(e)}")
            
            time.sleep(300)  # Check every 5 minutes


if __name__ == "__main__":
    try:
        connector = SimpleVigilIntelConnector()
        connector.run()
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)
