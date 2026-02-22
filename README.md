# Plateforme de Priorisation des Vulnérabilités IoT

Plateforme d'analyse et de priorisation des vulnérabilités CVE pour les équipements IoT Hikvision.  
Elle combine trois sources de données de référence pour produire un **score de risque composite**, permettant de concentrer les efforts de remédiation sur les vulnérabilités les plus dangereuses — pas seulement les plus sévères.

---

## Problématique

Un score CVSS élevé ne suffit pas à prioriser efficacement. Une CVE avec un CVSS de 7.5 activement exploitée dans la nature est bien plus urgente qu'une CVE de 9.8 théorique sans exploitation connue. Ce projet résout ce problème en croisant trois signaux complémentaires.

---

## Architecture

```
NVD (NIST)          →  Liste des CVEs Hikvision + score CVSS
EPSS (FIRST.org)    →  Probabilité d'exploitation dans les 30 prochains jours
CISA KEV            →  Exploitation confirmée dans la nature
         ↓
   Score de Risque Composite (0–100)
         ↓
   hikvision_risk_report.json  (trié par priorité réelle)
```

---

## Installation

Installer les dépendances nécessaires
```
pip install requirements.txt
```

Lancer la rechercher de CVE ainsi que le tri des CVE
```
python NVD_vulne_search.py
python hikvision_risk_score.py
```

les données trouvées sont stockées réspectivement dans `hickvision_cves.json` et `hikvision_risk_report.json`.

## Usage
Pour lancer le site, il faut utiliser streamlit :
```
streamlit run app.py
```

## 👤 Auteur

**Kyle Dottin**

**Léo RACLET**

**Martin JOUBERT DE LA MOTTE**
