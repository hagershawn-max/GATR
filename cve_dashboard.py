import streamlit as st
import requests
import pandas as pd
from datetime import datetime, timedelta

st.set_page_config(page_title="GATR CVE Explorer", layout="wide", page_icon="🛡️")

# =============== GATOR LOGO ===============
col_logo, col_title = st.columns([1, 5])
with col_logo:
    st.image("https://i.imgur.com/5eXBb.jpg", width=140)  # Gator eating software
with col_title:
    st.title("🛡️ GATR Multi-Source CVE Explorer")
    st.markdown("*Devouring vulnerabilities one byte at a time* 🐊")

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

# ====================== VERSION HELPERS ======================
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

# ====================== FETCH FUNCTIONS ======================
@st.cache_data(ttl=1200)
def fetch_nvd(vendor, software, start_date, end_date, severity_list, api_key=None):
    if not vendor and not software:
        return pd.DataFrame(), 0
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
                "Affected Versions": extract_versions_nvd(cve),
                "Description": cve["descriptions"][0]["value"][:180] + "..." if cve.get("descriptions") else "N/A",
                "Link": f"https://nvd.nist.gov/vuln/detail/{cve['id']}"
            })
        return pd.DataFrame(records), data.get("totalResults", 0)
    except:
        return pd.DataFrame(), 0

@st.cache_data(ttl=1800)
def fetch_osv(vendor, software, severity_list):
    if not software: return pd.DataFrame()
    url = "https://api.osv.dev/v1/query"
    payload = {"package": {"name": software}}
    if vendor: payload["package"]["ecosystem"] = vendor.upper()
    try:
        r = requests.post(url, json=payload, timeout=15)
        data = r.json()
        records = []
        for vuln in data.get("vulns", []):
            sev = vuln.get("database_specific", {}).get("severity", "UNKNOWN")
            records.append({
                "Source": "OSV.dev",
                "CVE ID": vuln.get("id"),
                "Published": vuln.get("published", "")[:10],
                "Severity": sev,
                "Score": None,
                "Affected Versions": extract_versions_osv(vuln),
                "Description": vuln.get("details", "")[:180] + "...",
                "Link": f"https://osv.dev/vulnerability/{vuln.get('id')}"
            })
        return pd.DataFrame(records)
    except:
        return pd.DataFrame()

@st.cache_data(ttl=3600)
def fetch_cisa_kev():
    try:
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        r = requests.get(url, timeout=15)
        data = r.json()
        records = []
        for item in data.get("vulnerabilities", []):
            records.append({
                "Source": "CISA KEV",
                "CVE ID": item.get("cveID"),
                "Published": item.get("dateAdded", "")[:10],
                "Severity": "HIGH (Exploited)",
                "Score": None,
                "Affected Versions": "Exploited in Wild",
                "Description": item.get("shortDescription", "")[:180],
                "Link": f"https://nvd.nist.gov/vuln/detail/{item.get('cveID')}"
            })
        return pd.DataFrame(records)
    except:
        return pd.DataFrame()

def fetch_vendor_specific(vendor):
    v = vendor.lower().strip() if vendor else ""
    records = []
    if "microsoft" in v:
        records.append({"Source": "Microsoft MSRC", "CVE ID": "Latest Updates", "Published": datetime.now().strftime("%Y-%m-%d"), "Severity": "HIGH", "Score": None, "Affected Versions": "Various", "Description": "Microsoft Security Response Center", "Link": "https://msrc.microsoft.com/update-guide"})
    elif "oracle" in v:
        records.append({"Source": "Oracle CPU", "CVE ID": "Critical Patch Update", "Published": datetime.now().strftime("%Y-%m-%d"), "Severity": "CRITICAL", "Score": None, "Affected Versions": "Multiple", "Description": "Oracle Security Alerts", "Link": "https://www.oracle.com/security-alerts/"})
    # Add more vendors as needed
    return pd.DataFrame(records)

# ====================== SIDEBAR ======================
st.sidebar.header("🔍 Search Filters")
source = st.sidebar.selectbox("Data Source", ["All Sources", "NIST NVD", "OSV.dev", "CISA KEV", "Vendor Specific"], index=0)

vendor = st.sidebar.text_input("Vendor / Ecosystem", placeholder="microsoft, oracle, apache")
software = st.sidebar.text_input("Software / Package", placeholder="windows, log4j, openssl")

st.sidebar.subheader("Date Range (NVD only)")
col1, col2 = st.sidebar.columns(2)
end_date = col2.date_input("To", datetime.now().date())
start_date = col1.date_input("From", end_date - timedelta(days=90))

severity = st.sidebar.multiselect("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH"])
api_key_nvd = st.sidebar.text_input("NVD API Key (optional)", type="password")

# ====================== MAIN LOGIC ======================
df_list = []

if source in ["All Sources", "NIST NVD"]:
    nvd_df, _ = fetch_nvd(vendor, software, start_date, end_date, severity, api_key_nvd)
    if not nvd_df.empty:
        company, country, src = get_company_info(vendor)
        nvd_df["Company"] = company
        nvd_df["Country"] = country
        nvd_df["Info Source"] = src
        df_list.append(nvd_df)

if source in ["All Sources", "OSV.dev"]:
    osv_df = fetch_osv(vendor, software, severity)
    if not osv_df.empty:
        company, country, src = get_company_info(vendor)
        osv_df["Company"] = company
        osv_df["Country"] = country
        osv_df["Info Source"] = src
        df_list.append(osv_df)

if source in ["All Sources", "CISA KEV"]:
    kev_df = fetch_cisa_kev()
    if not kev_df.empty:
        company, country, src = get_company_info(vendor)
        kev_df["Company"] = company
        kev_df["Country"] = country
        kev_df["Info Source"] = src
        df_list.append(kev_df)

if source in ["All Sources", "Vendor Specific"]:
    vendor_df = fetch_vendor_specific(vendor)
    if not vendor_df.empty:
        company, country, src = get_company_info(vendor)
        vendor_df["Company"] = company
        vendor_df["Country"] = country
        vendor_df["Info Source"] = src
        df_list.append(vendor_df)

# ====================== DISPLAY ======================
if df_list:
    final_df = pd.concat(df_list, ignore_index=True)
    st.success(f"**{len(final_df)}** vulnerabilities found")

    csv = final_df.to_csv(index=False).encode()
    st.download_button("📥 Download CSV", csv, "gatr_cve_export.csv", "text/csv")

    st.dataframe(
        final_df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Affected Versions": st.column_config.TextColumn(width="medium"),
            "Description": st.column_config.TextColumn(width="large"),
            "Company": st.column_config.TextColumn(width="medium"),
            "Country": st.column_config.TextColumn(width="small"),
        }
    )
else:
    st.info("👈 Enter Vendor and/or Software to begin searching.")

st.sidebar.caption("🐊 GATR CVE Dashboard")
