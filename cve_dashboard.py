import streamlit as st
import requests
import pandas as pd
from datetime import datetime, timedelta

st.set_page_config(page_title="GATR CVE Explorer", layout="wide", page_icon="🛡️")

# Gator Logo
st.image("https://i.imgur.com/5eXBb.jpg", width=180)  # Fun Gator eating software

st.title("🛡️ GATR Multi-Source CVE Explorer")
st.markdown("**All Major Open-Source + Vendor Databases** • Powered by the Gator")

# ====================== COMPANY & COUNTRY ======================
vendor_db = {
    "apache": {"company": "The Apache Software Foundation", "country": "United States"},
    "microsoft": {"company": "Microsoft Corporation", "country": "United States"},
    "oracle": {"company": "Oracle Corporation", "country": "United States"},
    "google": {"company": "Google LLC", "country": "United States"},
    "amazon": {"company": "Amazon.com, Inc.", "country": "United States"},
    "redhat": {"company": "Red Hat, Inc.", "country": "United States"},
    "ibm": {"company": "IBM", "country": "United States"},
    "cisco": {"company": "Cisco Systems", "country": "United States"},
    "apple": {"company": "Apple Inc.", "country": "United States"},
    "sap": {"company": "SAP SE", "country": "Germany"},
    "huawei": {"company": "Huawei Technologies", "country": "China"},
    "nginx": {"company": "F5, Inc.", "country": "United States"},
}

def get_company_info(vendor):
    if not vendor:
        return "N/A", "N/A", "N/A"
    v = vendor.lower().strip()
    info = vendor_db.get(v)
    if info:
        return info["company"], info["country"], "Local DB"
    for key in vendor_db:
        if key in v or v in key:
            info = vendor_db[key]
            return info["company"], info["country"], "Local DB"
    return "Unknown", "Unknown", "Not Found"

# ====================== VERSION EXTRACTION ======================
def extract_versions_nvd(cve):
    versions = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"): continue
                parts = []
                if match.get("versionStartIncluding"): parts.append(f">= {match['versionStartIncluding']}")
                if match.get("versionEndIncluding"): parts.append(f"<= {match['versionEndIncluding']}")
                if parts: versions.append(" ".join(parts))
    return " | ".join(versions[:4]) if versions else "Not specified"

def extract_versions_osv(vuln):
    affected = []
    for item in vuln.get("affected", []):
        for r in item.get("ranges", []):
            for event in r.get("events", []):
                if "introduced" in event: affected.append(f">= {event['introduced']}")
                if "fixed" in event: affected.append(f"< {event['fixed']}")
        affected.extend(item.get("versions", [])[:5])
    return " | ".join(affected[:6]) if affected else "Not specified"

# ====================== FETCH FUNCTIONS (same as before) ======================
# ... [All fetch functions from previous version: fetch_nvd, fetch_osv, fetch_cisa_kev, fetch_vendor_specific]

# (For brevity, paste your previous fetch functions here)

# ====================== SIDEBAR & MAIN LOGIC ======================
# ... (Keep the sidebar and main logic from the previous complete version)

st.sidebar.caption("🦖 GATR - Devouring Vulnerabilities Since 2026")
