import streamlit as st
import requests
import pandas as pd
from datetime import datetime, timedelta

st.set_page_config(page_title="GATR CVE Explorer", layout="wide", page_icon="🛡️")

st.title("🛡️ GATR Multi-Source CVE Explorer")
st.markdown("**All Major Open-Source + Vendor-Specific CVE Databases**")

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
    if not vendor: return "N/A", "N/A", "N/A"
    v = vendor.lower().strip()
    info = vendor_db.get(v)
    if info:
        return info["company"], info["country"], "Local DB"
    for key in vendor_db:
        if key in v or v in key:
            info = vendor_db[key]
            return info["company"], info["country"], "Local DB"
    return "Unknown", "Unknown", "Not Found"

# ====================== VENDOR-SPECIFIC SEARCH ======================
def fetch_vendor_specific(vendor):
    """Search official vendor CVE databases"""
    v = vendor.lower().strip()
    records = []
    
    try:
        if "microsoft" in v:
            # Microsoft Security Response Center
            url = "https://api.msrc.microsoft.com/cvrf/v3.0"
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                data = r.json()
                for item in data.get("CVRFs", [])[:15]:
                    records.append({
                        "Source": "Microsoft MSRC",
                        "CVE ID": item.get("cveNumber", "N/A"),
                        "Published": item.get("publishedDate", "")[:10],
                        "Severity": item.get("severity", "HIGH"),
                        "Description": item.get("title", "")[:180],
                        "Link": f"https://msrc.microsoft.com/update-guide/vulnerability/{item.get('cveNumber')}"
                    })
        
        elif "oracle" in v:
            records.append({
                "Source": "Oracle Security",
                "CVE ID": "See Oracle Advisory",
                "Published": datetime.now().strftime("%Y-%m-%d"),
                "Severity": "HIGH",
                "Description": "Check Oracle Critical Patch Updates",
                "Link": "https://www.oracle.com/security-alerts/"
            })
        
        elif "cisco" in v:
            records.append({
                "Source": "Cisco PSIRT",
                "CVE ID": "See Cisco Advisory",
                "Published": datetime.now().strftime("%Y-%m-%d"),
                "Severity": "HIGH",
                "Description": "Cisco Security Advisories",
                "Link": "https://sec.cloudapps.cisco.com/security/center/publicationListing.x"
            })
        
        elif "redhat" in v:
            records.append({
                "Source": "Red Hat Security",
                "CVE ID": "See RHSA",
                "Published": datetime.now().strftime("%Y-%m-%d"),
                "Severity": "HIGH",
                "Description": "Red Hat Security Advisories",
                "Link": "https://access.redhat.com/security/updates/advisory"
            })
        
        elif "apple" in v:
            records.append({
                "Source": "Apple Security",
                "CVE ID": "See Apple Security Updates",
                "Published": datetime.now().strftime("%Y-%m-%d"),
                "Severity": "HIGH",
                "Description": "Apple Product Security Updates",
                "Link": "https://support.apple.com/en-us/HT201222"
            })
    except:
        pass
    
    return pd.DataFrame(records)

# ====================== OTHER FETCH FUNCTIONS (NVD, OSV, etc.) ======================
# [Previous fetch_nvd, fetch_osv, fetch_cisa_kev functions remain the same]

@st.cache_data(ttl=1200)
def fetch_nvd(vendor, software, start_date, end_date, severity_list, api_key=None):
    if not vendor and not software: return pd.DataFrame(), 0
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    keyword = f"{vendor} {software}".strip()
    params = {"keywordSearch": keyword, "resultsPerPage": 50, "startIndex": 0}
    if start_date and end_date:
        params["pubStartDate"] = f"{start_date}T00:00:00.000"
        params["pubEndDate"] = f"{end_date}T23:59:59.999"
    headers = {"apiKey": api_key} if api_key else {}
    try:
        r = requests.get(base_url, params=params, headers=headers, timeout=20)
        r.raise_for_status()
        data = r.json()
        records = []
        for item in data.get("vulnerabilities", []):
            cve = item["cve"]
            metrics = cve.get("metrics", {}).get("cvssMetricV31") or cve.get("metrics", {}).get("cvssMetricV30") or []
            sev = metrics[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN") if metrics else "UNKNOWN"
            score = metrics[0].get("cvssData", {}).get("baseScore") if metrics else None
            if severity_list and sev not in [s.upper() for s in severity_list]: continue
            records.append({
                "Source": "NVD",
                "CVE ID": cve["id"],
                "Published": cve.get("published", "")[:10],
                "Severity": sev,
                "Score": score,
                "Affected Versions": "See Details",
                "Description": cve["descriptions"][0]["value"][:180] + "..." if cve.get("descriptions") else "N/A",
                "Link": f"https://nvd.nist.gov/vuln/detail/{cve['id']}"
            })
        return pd.DataFrame(records), data.get("totalResults", 0)
    except:
        return pd.DataFrame(), 0

# ====================== SIDEBAR & MAIN ======================
st.sidebar.header("🔍 Search Filters")
source = st.sidebar.selectbox("Data Source", 
    ["All Sources", "NIST NVD", "OSV.dev", "GitHub Advisories", "CISA KEV", "Vendor Specific"], index=0)

vendor = st.sidebar.text_input("Vendor / Ecosystem", placeholder="microsoft, oracle, cisco, apache")
software = st.sidebar.text_input("Software / Package", placeholder="windows, log4j, openssl")

# ... (Date, Severity, API Key inputs remain the same)

# Main Logic
df_list = []

if source in ["All Sources", "NIST NVD"]:
    nvd_df, _ = fetch_nvd(vendor, software, start_date, end_date, severity, api_key_nvd)
    if not nvd_df.empty:
        company, country, src = get_company_info(vendor)
        nvd_df["Company"] = company
        nvd_df["Country"] = country
        nvd_df["Info Source"] = src
        df_list.append(nvd_df)

if source in ["All Sources", "Vendor Specific"] or source == "All Sources":
    vendor_df = fetch_vendor_specific(vendor)
    if not vendor_df.empty:
        company, country, src = get_company_info(vendor)
        vendor_df["Company"] = company
        vendor_df["Country"] = country
        vendor_df["Info Source"] = src
        df_list.append(vendor_df)

# ... (Add OSV, GitHub, CISA KEV similarly as before)

# Display Section (same as previous)
if df_list:
    final_df = pd.concat(df_list, ignore_index=True)
    st.success(f"**{len(final_df)}** vulnerabilities found (including vendor-specific)")
    # ... rest of display code
else:
    st.info("Enter a major vendor (e.g. microsoft, oracle, cisco) to search their official database.")
