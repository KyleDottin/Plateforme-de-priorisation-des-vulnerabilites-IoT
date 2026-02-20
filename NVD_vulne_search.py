#!/usr/bin/env python3
"""
Script de recherche de vulnérabilités Hikvision via l'API NVD (NIST)
Enrichi avec :
  - Score EPSS (probabilité d'exploitation) via l'API FIRST.org
  - Vérification de présence dans le catalogue KEV de la CISA

APIs utilisées :
  - NVD   : https://nvd.nist.gov/developers/vulnerabilities
  - EPSS  : https://api.first.org/data/v1/epss
  - KEV   : https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""

import requests
import json
import time
from datetime import datetime

# Configuration 
NVD_API_URL= "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_URL= "https://api.first.org/data/v1/epss"
KEV_URL= "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

API_KEY= ""    # Clé NVD optionnelle → https://nvd.nist.gov/developers/request-an-api-key
keyword = "Hikvision"
Max_res = 2000  # Max autorisé par l'API NVD
EPSS_BATCH_SIZE  = 100   # Nb de CVEs envoyées par requête EPSS


# NVD 

def fetch_cves(keyword: str, api_key: str = "") -> list:
    """Récupère toutes les CVE contenant le mot-clé depuis l'API NVD."""
    all_cves    = []
    start_index = 0
    total_results = None
    headers = {"apiKey": api_key} if api_key else {}

    print(f"[*] Recherche NVD pour le mot-clé : '{keyword}'")

    while True:
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": Max_res,
            "startIndex": start_index,
        }
        try:
            r = requests.get(NVD_API_URL, params=params, headers=headers, timeout=30)
            r.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"[!] Erreur NVD : {e}")
            break

        data = r.json()
        if total_results is None:
            total_results = data.get("totalResults", 0)
            print(f"[+] {total_results} CVEs trouvées\n")

        vulns = data.get("vulnerabilities", [])
        all_cves.extend(vulns)
        print(f"Récupéré {len(all_cves)} / {total_results}")

        start_index += len(vulns)
        if start_index >= total_results or not vulns:
            break

        time.sleep(1 if api_key else 6)  # Respect du rate-limit NVD

    return all_cves


def parse_cve(vuln: dict) -> dict:
    """Extrait les champs essentiels d'une entrée NVD."""
    cve = vuln.get("cve", {})
    cve_id = cve.get("id", "N/A")

    descriptions = cve.get("descriptions", [])
    description= next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        "Pas de description disponible"
    )

    metrics = cve.get("metrics", {})
    cvss_score = "N/A"
    severity = "N/A"

    for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if version in metrics:
            m= metrics[version][0]
            cvss_data= m.get("cvssData", {})
            cvss_score= cvss_data.get("baseScore", "N/A")
            severity= m.get("baseSeverity", cvss_data.get("baseSeverity", "N/A"))
            break

    published= cve.get("published", "N/A")
    last_modified = cve.get("lastModified", "N/A")
    references= [ref.get("url", "") for ref in cve.get("references", [])]

    return {
        "cve_id":          cve_id,
        "description":     description,
        "cvss_score":      cvss_score,
        "severity":        severity,
        "published":       published[:10]     if published != "N/A" else "N/A",
        "last_modified":   last_modified[:10] if last_modified != "N/A" else "N/A",
        "references":      references,
        # Champs enrichis (remplis plus tard)
        "epss_score":      "N/A",
        "epss_percentile": "N/A",
        "in_kev":          False,
        "kev_date_added":  "N/A",
        "kev_ransomware":  "N/A",
    }


# EPSS

def fetch_epss_scores(cve_ids: list) -> dict:
    """
    Interroge l'API EPSS pour une liste de CVE IDs.
    Retourne un dict { cve_id: { score, percentile } }.
    Traite par lots de EPSS_BATCH_SIZE pour éviter les URLs trop longues.
    """
    epss_map = {}
    total    = len(cve_ids)

    print(f"\n[*] Récupération des scores EPSS pour {total} CVEs (par lots de {EPSS_BATCH_SIZE})...")

    for i in range(0, total, EPSS_BATCH_SIZE):
        batch= cve_ids[i:i + EPSS_BATCH_SIZE]
        params= {"cve": ",".join(batch), "limit": EPSS_BATCH_SIZE}

        try:
            r = requests.get(EPSS_API_URL, params=params, timeout=30)
            r.raise_for_status()
            data = r.json()
            for entry in data.get("data", []):
                cid = entry.get("cve", "").upper()
                epss_map[cid] = {
                    "score":round(float(entry.get("epss", 0)) * 100, 4),   # En %
                    "percentile":round(float(entry.get("percentile", 0)) * 100, 2),
                }
        except requests.exceptions.RequestException as e:
            print(f"[!] Erreur EPSS (lot {i//EPSS_BATCH_SIZE + 1}) : {e}")

        processed = min(i + EPSS_BATCH_SIZE, total)
        print(f"EPSS : {processed} / {total}")
        time.sleep(0.5)

    return epss_map


# CISA KEV

def fetch_kev_catalog() -> dict:
    """
    Télécharge le catalogue KEV de la CISA.
    Retourne un dict { cve_id: { dateAdded, ransomwareCampaign } }.
    """
    print(f"\n[*] Téléchargement du catalogue KEV (CISA)...")
    try:
        r = requests.get(KEV_URL, timeout=30)
        r.raise_for_status()
        data = r.json()
        kev_map = {}
        for vuln in data.get("vulnerabilities", []):
            cid = vuln.get("cveID", "").upper()
            kev_map[cid] = {
                "dateAdded":          vuln.get("dateAdded", "N/A"),
                "ransomwareCampaign": vuln.get("knownRansomwareCampaignUse", "Unknown"),
            }
        print(f"[+] {len(kev_map)} entrées KEV chargées")
        return kev_map
    except requests.exceptions.RequestException as e:
        print(f"[!] Erreur KEV : {e}")
        return {}


# Enrichissement

def enrich_cves(parsed_cves: list, epss_map: dict, kev_map: dict) -> list:
    """Injecte les données EPSS et KEV dans chaque CVE."""
    for cve in parsed_cves:
        cid = cve["cve_id"].upper()

        if cid in epss_map:
            cve["epss_score"]      = epss_map[cid]["score"]
            cve["epss_percentile"] = epss_map[cid]["percentile"]

        if cid in kev_map:
            cve["in_kev"]         = True
            cve["kev_date_added"] = kev_map[cid]["dateAdded"]
            cve["kev_ransomware"] = kev_map[cid]["ransomwareCampaign"]

    return parsed_cves


# Affichage

SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[93m",
    "MEDIUM":   "\033[94m",
    "LOW":      "\033[92m",
}
RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"


def epss_label(score) -> str:
    """Retourne une étiquette colorée selon le score EPSS (en %)."""
    if score == "N/A":
        return "N/A"
    if score >= 10:
        return f"{RED}{score:.4f}%{RESET}"
    if score >= 1:
        return f"{YELLOW}{score:.4f}%{RESET}"
    return f"{GREEN}{score:.4f}%{RESET}"


def display_cves(cves: list) -> list:
    """Affiche les CVE enrichies, triées par criticité composite."""
    print(f"\n{'='*75}")
    print(f"  {BOLD}RAPPORT HIKVISION — {datetime.now().strftime('%Y-%m-%d %H:%M')}{RESET}")
    print(f"{'='*75}\n")

    # Tri : KEV en tête, puis EPSS décroissant, puis CVSS décroissant
    def sort_key(c):
        kev = 1 if c["in_kev"] else 0
        epss = float(c["epss_score"]) if c["epss_score"] != "N/A" else 0
        cvss = float(c["cvss_score"]) if c["cvss_score"] != "N/A" else 0
        return (kev, epss, cvss)

    cves.sort(key=sort_key, reverse=True)

    for i, cve in enumerate(cves, 1):
        sev_color = SEVERITY_COLORS.get(str(cve["severity"]).upper(), "")
        kev_badge = f" {RED}{BOLD}[KEV ⚠]{RESET}" if cve["in_kev"] else ""

        print(f"{BOLD}[{i}] {cve['cve_id']}{RESET}{kev_badge}")

        epss_str = epss_label(cve["epss_score"])
        pct_str = f"  (percentile {cve['epss_percentile']}%)" if cve["epss_percentile"] != "N/A" else ""
        print(f"    CVSS   : {sev_color}{cve['cvss_score']} ({cve['severity']}){RESET}  |  EPSS : {epss_str}{pct_str}")
        print(f"    Publié : {cve['published']}  |  Modifié : {cve['last_modified']}")

        if cve["in_kev"]:
            print(f"    {RED}KEV    : Ajouté le {cve['kev_date_added']} — Ransomware : {cve['kev_ransomware']}{RESET}")

        desc = cve["description"]
        print(f"    Desc.  : {desc[:200]}{'...' if len(desc) > 200 else ''}")
        if cve["references"]:
            print(f"    Réf.   : {CYAN}{cve['references'][0]}{RESET}")
        print()

    return cves


# Résumé

def generate_summary(cves: list):
    print(f"\n{'='*75}")
    print(f"  {BOLD}RÉSUMÉ{RESET}")
    print(f"{'='*75}")

    sev_counts= {}
    cvss_scores, epss_scores= [], []
    kev_count = sum(1 for c in cves if c["in_kev"])

    for c in cves:
        sev = str(c["severity"]).upper()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        if c["cvss_score"] != "N/A":
            cvss_scores.append(float(c["cvss_score"]))
        if c["epss_score"] != "N/A":
            epss_scores.append(float(c["epss_score"]))

    print(f"  Total CVEs: {len(cves)}")
    print(f"  {RED}Dans le KEV (CISA): {kev_count}{RESET}  ← exploitation confirmée dans la nature")
    print()

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "N/A"]:
        count = sev_counts.get(sev, 0)
        if count:
            color = SEVERITY_COLORS.get(sev, "")
            print(f"  {color}{sev:<25}{RESET}: {count}")

    if cvss_scores:
        print(f"\n CVSS moyen: {sum(cvss_scores)/len(cvss_scores):.1f}")
        print(f"CVSS max: {max(cvss_scores)}")

    if epss_scores:
        high_epss = sum(1 for s in epss_scores if s >= 1)
        crit_epss = sum(1 for s in epss_scores if s >= 10)
        print(f"\n EPSS moyen: {sum(epss_scores)/len(epss_scores):.4f}%")
        print(f"EPSS max: {max(epss_scores):.4f}%")
        print(f"EPSS ≥ 1%  (risque élevé): {high_epss}")
        print(f"EPSS ≥ 10% (risque critique): {crit_epss}")
    print()


# Export JSON

def save_results(cves: list, filename: str = "hikvision_cves.json"):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(cves, f, ensure_ascii=False, indent=2)
    print(f"[+] Résultats sauvegardés → {filename}")


# Main

if __name__ == "__main__":
    # Étape 1 : NVD
    raw_cves = fetch_cves(keyword, API_KEY)
    if not raw_cves:
        print("[!] Aucune vulnérabilité trouvée ou erreur API.")
        exit(1)

    parsed  = [parse_cve(v) for v in raw_cves]
    cve_ids = [c["cve_id"] for c in parsed]

    # Étape 2 : EPSS
    epss_map = fetch_epss_scores(cve_ids)

    # Étape 3 : CISA KEV
    kev_map = fetch_kev_catalog()

    # Étape 4 : Enrichissement
    enriched = enrich_cves(parsed, epss_map, kev_map)

    # Étape 5 : Affichage
    display_cves(enriched)

    # Étape 6 : Résumé
    generate_summary(enriched)

    # Étape 7 : Export JSON
    save_results(enriched, "hikvision_cves.json")