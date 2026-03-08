import json

import numpy as np
import pandas as pd
import streamlit as st
from streamlit.runtime.state.common import WidgetArgs

from hikvision_risk_score import main as analyse_date
from NVD_vulne_search import main as fetch_data

pd.set_option("future.no_silent_downcasting", True)

# Config page web
st.set_page_config(page_title="Sécurité Hikvision", page_icon="🛡️", layout="wide")

# Récupération du rapport JSON
REPORT_FILE = "hikvision_risk_report.json"


@st.dialog("En détails", width="large")
def details(data):
    st.title(data["cve_id"])
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Score composite", data["risk_score"], border=True)
    col2.metric("EPSS (%)", data["epss_score"], border=True)
    col3.metric("CVSS", data["cvss_score"], border=True)
    col4.metric("Niveau de Risque", data["risk_level"], border=True)
    st.divider()
    st.badge("Date", color="red", icon=":material/calendar_clock:")
    st.markdown(data["published"])
    st.badge("Description", icon=":material/description:")
    st.markdown(f"**{data['description']}**")
    st.badge("References", color="green", icon=":material/quick_reference:")
    for e in data["references"]:
        st.page_link(e, label=e, icon=":material/link:")


# Fonction pour charger les données du rapport
@st.cache_data(ttl=300)
def load_data():
    fetch_data()
    analyse_date()

    with open(REPORT_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


# Fonction pour déterminer l'action requise selon le niveau de risque et la présence dans le KEV
def determine_action(row):
    if row.get("in_kev", False) or row.get("risk_level") == "CRITIQUE":
        return "Agir Maintenant"
    elif row.get("risk_level") == "ÉLEVÉ":
        return "Planifier une action"
    else:
        return "À surveiller"


st.title("Tableau de Bord des Vulnérabilités - Hikvision")
st.markdown(
    "Analyse des CVE basée sur les scores CVSS, l'exploitabilité (EPSS) et les menaces actives (KEV CISA)."
)

# Données du rapport
tab1, tab2 = st.tabs(["Tableau de bord", "Recommandations"])

# Onglet 1 : Tableau de bord des vulnérabilités
with tab1:
    st.header("Résumé des Risques")

    data = load_data()

    # Affichage des métriques clés (total CVEs, nombre dans le KEV, score max et moyen)
    summary = data.get("summary", {})
    cves = data.get("vulnerabilities", [])

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total CVEs", summary.get("total_cves", len(cves)))
    col2.metric(
        "Dans le KEV (Exploitées)",
        summary.get("kev_count", sum(1 for c in cves if c.get("in_kev"))),
    )
    col3.metric("Score Max", summary.get("risk_score_max", 0))
    col4.metric("Score Moyen", summary.get("risk_score_avg", 0))

    st.divider()

    st.subheader("Détail des Vulnérabilités")

    # Préparation du DataFrame pour l'affichage avec pandas
    if cves:
        df = pd.DataFrame(cves)

        df["Action Requise"] = df.apply(determine_action, axis=1)
        df["cvss_score"] = df["cvss_score"].replace("N/A", np.nan)

        display_df = df[
            [
                "published",
                "cve_id",
                "risk_score",
                "risk_level",
                "in_kev",
                "cvss_score",
                "epss_score",
                "Action Requise",
            ]
        ].copy()

        display_df.columns = [
            "Date",
            "CVE ID",
            "Score Composite",
            "Niveau de Risque",
            "Présent KEV",
            "CVSS",
            "EPSS (%)",
            "Action Requise",
        ]

        config = {
            "Date": st.column_config.DateColumn("Date", format="DD / MM / YYYY"),
            "EPSS (%)": st.column_config.NumberColumn("EPSS (%)", format="%.2f %%"),
        }

        # Affichage du tableau avec Streamlit
        event = st.dataframe(
            display_df,
            column_config=config,
            width="stretch",
            hide_index=True,
            on_select="rerun",
            selection_mode="single-row",
        )
        if event.selection.rows:
            filtered_df = df.iloc[event.selection.rows[0]]
            details(filtered_df)
    else:
        st.info("Aucune vulnérabilité trouvée dans le rapport.")

# Onglet 2 : Plan d'action et recommandations
with tab2:
    st.header("Plan d'Action et Recommandations (IoT)")
    st.markdown("""
    Pour sécuriser les caméras IP Hikvision contre les vulnérabilités identifiées, voici les actions prioritaires :

    * **Patching (Mise à jour immédiate) :** Appliquez systématiquement les dernières mises à jour du firmware fournies par le constructeur. C'est la seule mitigation définitive pour les failles référencées.
    * **Segmentation Réseau :** Ne connectez jamais les caméras sur le même réseau que vos équipements personnels ou professionnels sensibles. Placez-les sur un **VLAN dédié** (Virtual Local Area Network) avec des règles de pare-feu strictes bloquant les flux entrants depuis internet.
    * **Configuration de Sécurité :**
        * Désactivez immédiatement l'**UPnP** (Universal Plug and Play) sur votre routeur et sur la caméra.
        * Désactivez le P2P / Cloud Hikvision si vous n'en avez pas l'utilité absolue.
        * Modifiez les identifiants d'usine dès le premier démarrage.

    > **Référence Normative : ETSI EN 303 645**
    > Ces recommandations s'appuient sur la norme européenne de cybersécurité pour l'IoT grand public.
    > * **Provision 5.1 :** Exige l'absence de *"mots de passe par défaut universels"*. Les mots de passe d'usine doivent être uniques par appareil ou forcer le changement à l'initialisation.
    > * **Provision 5.3 :** Exige que le logiciel puisse être mis à jour de manière sécurisée.
    """)
