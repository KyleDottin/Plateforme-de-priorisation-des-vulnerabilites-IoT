# Plateforme d’analyse et de priorisation des vulnérabilités IoT Hikvision

Cette plateforme permet d’analyser et de prioriser les vulnérabilités CVE affectant les équipements IoT de la marque Hikvision. En croisant trois sources de données de référence, elle génère un **score de risque composite** qui aide à cibler les actions de correction sur les vulnérabilités les plus critiques — et non simplement les plus sévères sur le papier.

---

## Pourquoi cette approche ?

Un score CVSS élevé ne reflète pas toujours l’urgence réelle. Par exemple, une vulnérabilité avec un CVSS de 7,5 mais activement exploitée dans la nature doit être traitée avant une faille théorique notée 9,8 sans preuve d’exploitation. Ce projet répond à ce défi en combinant trois indicateurs clés pour une évaluation plus précise.

---

## Fonctionnement de la plateforme

Les données proviennent de trois sources principales :
- **NVD (NIST)** : liste des CVE Hikvision et leurs scores CVSS
- **EPSS (FIRST.org)** : probabilité d’exploitation dans les 30 prochains jours
- **CISA KEV** : confirmation d’une exploitation active dans la nature

Ces informations sont agrégées pour produire un **score de risque composite** (sur 100), puis classées dans un rapport JSON trié par ordre de priorité réelle : *hikvision_risk_report.json*.

## Architecture

Le schéma ci-dessous illustre simplement le flux de traitement des données au sein de notre application.

```text
NVD (NIST)          →  Liste des CVEs Hikvision + score CVSS
EPSS (FIRST.org)    →  Probabilité d'exploitation dans les 30 prochains jours
CISA KEV            →  Exploitation confirmée dans la nature
         ↓
   Score de Risque Composite (0–100)
         ↓
   hikvision_risk_report.json  (trié par priorité réelle)
```

---

## Utilisation

L’application est déployée via **Docker**. Pour l’utiliser, placez-vous dans le répertoire du projet et exécutez les commandes suivantes :

```bash
sudo docker build -t my-streamlit-background-app .
sudo docker run -p 80:80 my-streamlit-background-app
```

---

## Auteurs

- **Kyle DOTTIN**
- **Léo RACLET**
- **Martin JOUBERT DE LA MOTTE**
- **Romain LE SOURD**
