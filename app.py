"""
app.py
-------
Ye Streamlit dashboard hai - browser mein chalne wala UI
is Threat Intelligence Agent ke liye.

Chalane ka tarika: streamlit run app.py
"""

import os
import streamlit as st
from dotenv import load_dotenv
from groq import Groq

from cve_fetcher import fetch_recent_cves
from ai_analyst import analyze_cves_batch, generate_daily_summary
from virustotal_checker import check_ip, check_domain, check_file_hash


# Page settings
st.set_page_config(
    page_title="Threat Intelligence Dashboard",
    page_icon="🛡️",
    layout="centered"
)

load_dotenv()


def get_severity_color(severity):
    """Severity ke hisaab se color return karta hai."""
    colors = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢",
    }
    return colors.get(str(severity).upper(), "⚪")


# Session state mein data store karte hain, taaki page refresh pe data na khoye
if "cve_list" not in st.session_state:
    st.session_state.cve_list = []
if "analyses" not in st.session_state:
    st.session_state.analyses = {}
if "daily_summary" not in st.session_state:
    st.session_state.daily_summary = None


# ---------- HEADER ----------
st.title("🛡️ Threat Intelligence Dashboard")
st.caption("AI-powered CVE monitoring aur analysis")


# ---------- SIDEBAR SETTINGS ----------
with st.sidebar:
    st.header("⚙️ Settings")
    days_back = st.slider("Kitne din pehle tak ki CVEs?", 1, 7, 2)
    results_limit = st.slider("Maximum kitni CVEs?", 3, 20, 5)

    st.divider()
    st.caption("API key .env file se load hoti hai")


# ---------- SCAN BUTTON ----------
if st.button("🔍 Scan chalao", type="primary", use_container_width=True):
    groq_api_key = os.getenv("GROQ_API_KEY")
    nvd_api_key = os.getenv("NVD_API_KEY") or None

    if not groq_api_key:
        st.error("GROQ_API_KEY nahi mili. .env file check karo.")
    else:
        model = Groq(api_key=groq_api_key)

        with st.spinner("CVEs fetch kar rahe hain..."):
            cve_list = fetch_recent_cves(
                api_key=nvd_api_key,
                days_back=days_back,
                results_limit=results_limit
            )

        if not cve_list:
            st.warning("Is date range mein koi CVE nahi mili. Days badha kar try karo.")
        else:
            with st.spinner(f"AI se {len(cve_list)} CVEs ka analysis ho raha hai (1 hi request mein)..."):
                analyses = analyze_cves_batch(model, cve_list)

            with st.spinner("Daily summary bana rahe hain..."):
                daily_summary = generate_daily_summary(model, cve_list)

            # Results ko session state mein save karo
            st.session_state.cve_list = cve_list
            st.session_state.analyses = analyses
            st.session_state.daily_summary = daily_summary

            st.success(f"Scan complete! {len(cve_list)} CVEs analyze hui.")


# ---------- STATS ----------
if st.session_state.cve_list:
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Total CVEs", len(st.session_state.cve_list))
    with col2:
        # Critical/High count nikalte hain
        high_risk_count = sum(
            1 for cve in st.session_state.cve_list
            if str(cve.get("severity", "")).upper() in ["CRITICAL", "HIGH"]
        )
        st.metric("High Risk CVEs", high_risk_count)

    st.divider()

    # ---------- DAILY SUMMARY ----------
    st.subheader("📊 Executive Summary")
    st.info(st.session_state.daily_summary)

    st.divider()

    # ---------- CVE LIST ----------
    st.subheader("🔍 Detailed Analysis")

    for cve in st.session_state.cve_list:
        severity_icon = get_severity_color(cve["severity"])
        analysis = st.session_state.analyses.get(cve["cve_id"], "Analysis not available.")
        with st.expander(f"{severity_icon} {cve['cve_id']} — {cve['severity']} (Score: {cve['cvss_score']})"):
            st.markdown(analysis)

else:
    st.info("👆 'Scan chalao' button dabao shuru karne ke liye")


# ---------- VIRUSTOTAL CHECKER ----------
st.divider()
st.subheader("🦠 IP / Domain / File check karo (VirusTotal)")
st.caption("Kisi suspicious IP, domain, ya file hash ki reputation check karo")

vt_col1, vt_col2 = st.columns([3, 1])
with vt_col1:
    vt_input = st.text_input(
        "IP address, domain, ya file hash daalo",
        placeholder="e.g. 8.8.8.8 ya example.com"
    )
with vt_col2:
    vt_type = st.selectbox("Type", ["IP", "Domain", "File Hash"])

if st.button("Check karo", use_container_width=True):
    vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")

    if not vt_api_key:
        st.error("VIRUSTOTAL_API_KEY nahi mili. .env file check karo.")
    elif not vt_input.strip():
        st.warning("Kuch value daalo check karne ke liye.")
    else:
        with st.spinner("VirusTotal se check kar rahe hain..."):
            try:
                if vt_type == "IP":
                    result = check_ip(vt_input.strip(), vt_api_key)
                elif vt_type == "Domain":
                    result = check_domain(vt_input.strip(), vt_api_key)
                else:
                    result = check_file_hash(vt_input.strip(), vt_api_key)

                if not result.get("found"):
                    st.info(result.get("message", "Kuch nahi mila."))
                else:
                    st.markdown(f"### {result['verdict']}")
                    c1, c2, c3 = st.columns(3)
                    c1.metric("Malicious", result["malicious_count"])
                    c2.metric("Suspicious", result["suspicious_count"])
                    c3.metric("Total Engines", result["total_engines"])

            except Exception as e:
                st.error(f"Error: {e}")