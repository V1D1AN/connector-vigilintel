# VigilIntel Connector v2 for OpenCTI

Import daily threat intelligence from [VigilIntel](https://github.com/kidrek/VigilIntel) into OpenCTI.

## Features

### Dual Format Support

| Format | Description | Data Imported |
|--------|-------------|---------------|
| **STIX** | Direct STIX 2.1 bundle import | All objects as-is (threat actors, vulns, incidents, TTPs, reports, notes, relationships) |
| **JSON** | Full JSON parsing | All 6 sections parsed and converted to STIX |

### JSON Sections (when format=json)

| Section | OpenCTI Objects Created |
|---------|------------------------|
| `Analyse transversale` | Note (strategic-analysis) |
| `Synthèse des acteurs malveillants` | ThreatActor |
| `Synthèse des vulnérabilités` | Vulnerability (with CVSS) |
| `Synthèse des violations de données` | Identity (victim) + Note (data-breach) |
| `Synthèse de l'actualité géopolitique` | Note (geopolitical-analysis) |
| `Articles` | Report + Note + Indicator + AttackPattern |

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
| `VIGILINTEL_LANGUAGE` | `en` | `en` or `fr` |
| `VIGILINTEL_DAYS_TO_IMPORT` | `1` | Days to look back |
| `VIGILINTEL_INTERVAL` | `86400` | Check interval (seconds) |

### JSON-specific options

| Variable | Default | Description |
|----------|---------|-------------|
| `VIGILINTEL_IMPORT_THREAT_ACTORS` | `true` | Import threat actors |
| `VIGILINTEL_IMPORT_VULNERABILITIES` | `true` | Import CVEs |
| `VIGILINTEL_IMPORT_INCIDENTS` | `true` | Import data breaches |
| `VIGILINTEL_IMPORT_ARTICLES` | `true` | Import articles |
| `VIGILINTEL_IMPORT_GEOPOLITICAL` | `true` | Import geopolitical notes |
| `VIGILINTEL_IMPORT_ANALYSIS` | `true` | Import strategic analysis |
| `VIGILINTEL_CREATE_INDICATORS` | `true` | Create indicators from IOCs |

## Recommendation

**Use `VIGILINTEL_FORMAT=stix`** when available - it imports the complete STIX bundle directly without transformation, preserving all relationships and custom properties.

Use `VIGILINTEL_FORMAT=json` if you need granular control over which sections to import, or if STIX files are not available for certain dates.

## Credits

- [VigilIntel by Kidrek](https://github.com/kidrek/VigilIntel)
- [OpenCTI Platform](https://github.com/OpenCTI-Platform)
