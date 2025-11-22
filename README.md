# VigilIntel Connector for OpenCTI

Ce connecteur importe les rapports quotidiens de threat intelligence depuis [VigilIntel](https://github.com/kidrek/VigilIntel) dans OpenCTI.

## Fonctionnalités

- ✅ **Import automatique** des rapports quotidiens JSON depuis GitHub
- ✅ **Extraction intelligente des IOCs** : IPs, domaines, hashes, URLs, CVEs
- ✅ **Support bilingue** : Français (FR) et Anglais (EN)  
- ✅ **Création d'entités OpenCTI** : Reports, Indicators, Observables
- ✅ **Relations STIX** : Threat Actors, Attack Patterns, Vulnerabilities
- ✅ **Logging détaillé** pour le debug

## Configuration

### Variables d'environnement

```bash
# OpenCTI Configuration
OPENCTI_URL=http://localhost:8080
OPENCTI_TOKEN=your_token_here

# Connector Configuration  
CONNECTOR_ID=vigilintel-unique-id
VIGILINTEL_INTERVAL=24  # Heures entre chaque exécution
VIGILINTEL_LANGUAGE=FR  # Language: FR (Français) ou EN (English)

# Optional: Force immediate run
FORCE_RUN=true
```

### Choix de la langue

Le connecteur supporte le **français** et **l'anglais** :

- **`VIGILINTEL_LANGUAGE=FR`** : Utilise la section française des rapports
- **`VIGILINTEL_LANGUAGE=EN`** : Utilise la section anglaise des rapports  
- **Défaut** : FR si non spécifié

**Note** : Si la langue configurée n'est pas disponible dans un rapport, le connecteur utilisera automatiquement la langue disponible.

## Installation et démarrage

```bash
# 1. Cloner et configurer
git clone <ce-repo>
cd vigilintel-connector

# 2. Configurer les variables
cp .env.example .env
# Éditer .env avec vos paramètres

# 3. Démarrer le connecteur
docker-compose up -d

# 4. Voir les logs
docker-compose logs -f vigilintel
```

## Utilisation des langues

### Exemples de configuration

**Pour utiliser le français :**
```bash
echo "VIGILINTEL_LANGUAGE=FR" >> .env
```

**Pour utiliser l'anglais :**
```bash
echo "VIGILINTEL_LANGUAGE=EN" >> .env
```

### Logs d'exemple

```
[INFO] Configured language preference: FR
[INFO] Using configured language: French (FR)
[INFO] Processing 15 articles from JSON report
[INFO] Creating report: Analyse transversale cyber du 2025-11-20
[INFO] Extracted 45 SHA256 hashes from article
[INFO] Extracted 30 domains from article  
[INFO] Created 150+ indicators and observables
```

## Structure des données VigilIntel

Le connecteur traite automatiquement la structure FR/EN :

```json
{
  "FR": {
    "Articles": [...],
    "Synthèse des acteurs malveillants": [...],
    "Synthèse des vulnérabilités": [...]
  },
  "EN": {
    "Articles": [...], 
    "Malicious actors summary": [...],
    "Vulnerabilities summary": [...]
  }
}
```

## Types d'IOCs extraits

Le connecteur détecte intelligemment :

- **Hashes** : MD5 (32 chars), SHA1 (40 chars), SHA256 (64 chars)
- **Domaines** : `example.com`, `sub.domain.org`
- **URLs** : `https://example.com/path` 
- **IPs** : `192.168.1.1`, `2001:db8::1`
- **CVEs** : `CVE-2025-1234`
- **Emails** : `user@domain.com`

## Debugging

Pour débugger l'extraction des IOCs :
```bash
docker-compose logs -f vigilintel | grep -E "(Extracted|Added|Processing)"
```
