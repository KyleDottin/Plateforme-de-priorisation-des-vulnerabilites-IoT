"""
Calcule un Score de Risque composite pour les CVEs Hikvision.
Lit hikvision_cves.json, produit hikvision_risk_report.json.

Formule :
  RiskScore = (CVSS_norm × 0.30) + (KEV × 0.40) + (EPSS_log_norm × 0.30) × 100

  - CVSS  30% : impact technique brut, normalisé linéairement (score / 10)
  - KEV   40% : exploitation confirmée dans la nature (signal le plus fort, binaire)
  - EPSS  30% : probabilité d'exploitation, normalisée via courbe log
"""

import json
import sys
import math
from datetime import datetime

# Configuration
INPUT_FILE  = "hikvision_cves.json"
OUTPUT_FILE = "hikvision_risk_report.json"

W_CVSS= 0.3
W_KEV= 0.4
W_EPSS= 0.3

risk_thresholds = {
    "CRITIQUE":80,
    "ÉLEVÉ":60,
    "MODÉRÉ":40,
    "FAIBLE":0,
}


# Normalisation

def normalize_cvss(cvss) -> float:
    try:
        return float(cvss)/10.0
    except (TypeError, ValueError):
        return 0.0


def normalize_epss(epss_pct) -> float:
    """Normalisation log pour amplifier les petites valeurs réalistes."""
    try:
        p = float(epss_pct)/100.0
        if p <= 0:
            return 0.0
        return math.log(1 + 99 * p)/math.log(100)
    except (TypeError, ValueError):
        return 0.0


# Scoring

def compute_risk_score(cve: dict) -> dict:
    cvss_n = normalize_cvss(cve.get("cvss_score"))
    epss_n = normalize_epss(cve.get("epss_score"))
    kev_n = 1.0 if cve.get("in_kev", False) else 0.0

    risk_score = round((cvss_n * W_CVSS + kev_n * W_KEV + epss_n * W_EPSS) * 100, 2)

    risk_level = "FAIBLE"
    for level, threshold in risk_thresholds.items():
        if risk_score >= threshold:
            risk_level = level
            break

    return {
        **cve,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_components": {
            "cvss_contribution": round(cvss_n * W_CVSS * 100, 2),
            "kev_contribution":  round(kev_n  * W_KEV  * 100, 2),
            "epss_contribution": round(epss_n * W_EPSS * 100, 2),
        },
    }


# Export

def save_report(scored_cves: list, filename: str):
    scores = [c["risk_score"] for c in scored_cves]
    level_dist = {}
    for c in scored_cves:
        level_dist[c["risk_level"]] = level_dist.get(c["risk_level"], 0) + 1

    report = {
        "generated_at": datetime.now().isoformat(),
        "total_cves":   len(scored_cves),
        "formula": {
            "description": "RiskScore = (CVSS_norm×W_CVSS + KEV×W_KEV + EPSS_log_norm×W_EPSS) × 100",
            "weights": {"cvss": W_CVSS, "kev": W_KEV, "epss": W_EPSS},
        },
        "summary": {
            "risk_score_avg": round(sum(scores) / len(scores), 2) if scores else 0,
            "risk_score_max": max(scores) if scores else 0,
            "risk_score_min": min(scores) if scores else 0,
            "level_distribution": level_dist,
            "kev_count": sum(1 for c in scored_cves if c["in_kev"]),
        },
        "vulnerabilities": scored_cves,
    }
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)


# Main

if __name__ == "__main__":
    input_path = sys.argv[1] if len(sys.argv) > 1 else INPUT_FILE

    try:
        with open(input_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError:
        sys.stderr.write(f"Fichier introuvable : {input_path}\n")
        sys.exit(1)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"Erreur JSON : {e}\n")
        sys.exit(1)

    cves   = raw if isinstance(raw, list) else raw.get("vulnerabilities", [])
    scored = [compute_risk_score(c) for c in cves]
    scored.sort(key=lambda x: x["risk_score"], reverse=True)

    save_report(scored, OUTPUT_FILE)