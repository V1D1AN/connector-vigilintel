# VigilIntel Connector v2 for OpenCTI

Import daily threat intelligence from [VigilIntel](https://github.com/kidrek/VigilIntel) into OpenCTI.

## Features

### Dual Format Support

| Format | Description | Data Imported |
|--------|-------------|---------------|
| **STIX** | Direct STIX 2.1 bundle import | All objects as-is (threat actors, vulns, software, tools, incidents, TTPs, reports, notes, relationships, TLP/PAP markings) |
| **JSON** | Full JSON parsing with multilingual support | All 5 sections parsed and converted to enriched STIX objects |

### JSON Sections (when format=json)

| JSON Key | OpenCTI Objects Created |
|----------|------------------------|
| `strategic_analysis` | Note (strategic-analysis, daily-summary) |
| `geopolitical_analyse` | Note (geopolitical-analysis) with sector and recommendations |
| `breach_analyse` | Identity (victim) + ThreatActor (with aliases) + Note (data-breach) + AttackPattern (TTPs) + Relationships (targets, uses) |
| `vulnerabilities_analyse` | Vulnerability (with CVSS, CISA KEV, custom OpenCTI properties) + Software (with vendor, CPE) + AttackPattern (TTPs) + Relationships |
| `threats_analyse` | Report + Note + ThreatActor + Tool (from TOOLS indicators) + Indicator (IOCs with confidence score) + AttackPattern (TTPs) + Relationships (uses) |

### STIX Enrichment (JSON mode)

The connector generates rich STIX 2.1 objects from the JSON format:

- **Multilingual support**: Extracts `en` or `fr` content based on `VIGILINTEL_LANGUAGE` setting
- **Vulnerability custom properties**: `x_opencti_cvss_base_score`, `x_opencti_cvss_base_severity`, `x_opencti_cisa_kev`
- **Software objects**: Created from `vendor`, `product`, and `cpe` fields with `related-to` relationships to vulnerabilities
- **Tool objects**: Extracted from `indicators.TOOLS` lists with `uses` relationships to threat actors
- **Threat actor enrichment**: Aliases, origin, and type from breach and threat data
- **Attack patterns**: MITRE ATT&CK techniques linked to threat actors via `uses` relationships
- **Indicators**: IOCs (IPv4, IPv6, domain, URL, email, SHA-256, SHA-1, MD5) with `confidence=50`
- **Recommendations**: Included in Note content from all sections

### Deduplication

Content-hash based deduplication prevents re-importing unchanged reports. Hashes are stored per date in the connector state.

## Quick Start

```bash
cp .env.sample .env
nano .env  # Set OPENCTI_URL and OPENCTI_TOKEN
docker-compose up -d
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `VIGILINTEL_FORMAT` | `stix` | `stix` or `json` |
| `VIGILINTEL_LANGUAGE` | `en` | `en` or `fr` (used for multilingual field extraction in JSON mode) |
| `VIGILINTEL_DAYS_TO_IMPORT` | `1` | Days to look back |
| `VIGILINTEL_INTERVAL` | `86400` | Check interval in seconds |
| `VIGILINTEL_IMPORT_FROM_DATE` | *(none)* | Import all reports from this date (format: `YYYY-MM-DD`), overrides `DAYS_TO_IMPORT` |
| `VIGILINTEL_GITHUB_URL` | `https://raw.githubusercontent.com/kidrek/VigilIntel/main` | Base URL for report files |

### JSON-specific import toggles

| Variable | Default | Description |
|----------|---------|-------------|
| `VIGILINTEL_IMPORT_ANALYSIS` | `true` | Import strategic analysis (`strategic_analysis`) |
| `VIGILINTEL_IMPORT_GEOPOLITICAL` | `true` | Import geopolitical notes (`geopolitical_analyse`) |
| `VIGILINTEL_IMPORT_INCIDENTS` | `true` | Import data breaches (`breach_analyse`) |
| `VIGILINTEL_IMPORT_VULNERABILITIES` | `true` | Import CVEs (`vulnerabilities_analyse`) |
| `VIGILINTEL_IMPORT_ARTICLES` | `true` | Import threat reports (`threats_analyse`) |
| `VIGILINTEL_CREATE_INDICATORS` | `true` | Create STIX Indicators from IOCs in threat reports |

## Format Recommendation

**Use `VIGILINTEL_FORMAT=stix`** when available — it imports the complete STIX bundle directly without transformation, preserving all relationships, custom properties, TLP/PAP markings, and extension definitions.

Use `VIGILINTEL_FORMAT=json` if you need granular control over which sections to import, or if STIX files are not available for certain dates. The JSON parser maintains backward compatibility with older VigilIntel JSON formats (language-wrapped keys).

## Requirements

- OpenCTI >= 6.x
- `pycti >= 6.0.0, < 7.0.0`
- Python 3.10+

## Credits

- [VigilIntel by Kidrek](https://github.com/kidrek/VigilIntel)
- [OpenCTI Platform](https://github.com/OpenCTI-Platform)
