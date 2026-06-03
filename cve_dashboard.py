import streamlit as st
import requests
import pandas as pd
from datetime import datetime, timedelta

st.set_page_config(page_title="GATR CVE Explorer", layout="wide", page_icon="🛡️")

st.title("🛡️ GATR Multi-Source CVE Explorer")
st.markdown("**Version Info • Company • Country of Origin** | NVD + OSV + GitHub")

# ====================== COMPANY & COUNTRY DATABASE ======================
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
    "intel": {"company": "Intel Corporation", "country": "United States"},
    "canonical": {"company": "Canonical Ltd.", "country": "United Kingdom"},
    "nginx": {"company": "F5, Inc.", "country": "United States"},
    "wordpress": {"company": "Automattic", "country": "United States"},
    "mozilla": {"company": "Mozilla Foundation", "country": "United States"},
    "sap": {"company": "SAP SE", "country": "Germany"},
    "huawei": {"company": "Huawei Technologies Co., Ltd.", "country": "China"},
    "alibaba": {"company": "Alibaba Group", "country": "China"},
    "vmware": {"company": "VMware, Inc.", "country": "United States"},
    "docker": {"company": "Docker, Inc.", "country": "United States"},
}

def get_company_info(vendor):
    if not vendor:
        return "N/A", "N/A", "N/A"
    v = vendor.lower().strip()
    
    info = vendor_db.get(v)
    if info:
        return info["company"], info["country"], "Local Database"
    
    # Fuzzy matching
    for key in vendor_db:
        if key in v or v in key:
            info = vendor_db[key]
            return info["company"], info["country"], "Local Database (fuzzy)"
    
    return "Unknown", "Unknown", "Not Found"

# ====================== VERSION EXTRACTION ======================
def extract_versions_nvd(cve):
    versions = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                parts = []
                if match.get("versionStartIncluding"):
                    parts.append(f">= {match['versionStartIncluding']}")
                if match.get("versionEndIncluding"):
                    parts.append(f"<= {match['versionEndIncluding']}")
                if parts:
                    versions.append(" ".join(parts))
    return " | ".join(versions[:4]) if versions else "Not specified"

def extract_versions_osv(vuln):
    affected = []
    for item in vuln.get("affected", []):
        for r in item.get("ranges", []):
            for event in r.get("events", []):
                if "introduced" in event:
                    affected.append(f">= {event['introduced']}")
                if "fixed" in event:
                    affected.append(f"< {event['fixed']}")
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

            if severity_list and sev not in [s.upper() for s in severity_list]:
                continue

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
    if not software:
        return pd.DataFrame()
    url = "https://api.osv.dev/v1/query"
    payload = {"package": {"name": software}}
    if vendor:
        payload["package"]["ecosystem"] = vendor.upper()
    try:
        r = requests.post(url, json=payload, timeout=15)
        data = r.json()
        records = []
        for vuln in data.get("vulns", []):
            sev = vuln.get("database_specific", {}).get("severity", "UNKNOWN")
            records.append({
                "Source": "OSV",
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

# ====================== SIDEBAR ======================
st.sidebar.header("🔍 Search Filters")
source = st.sidebar.selectbox("Data Source", ["All Sources", "NIST NVD", "OSV.dev", "GitHub Advisories"], index=0)

vendor = st.sidebar.text_input("Vendor / Ecosystem", placeholder="apache, microsoft, oracle")
software = st.sidebar.text_input("Software / Package", placeholder="log4j, openssl, django")

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

if source in ["All Sources", "GitHub Advisories"]:
    try:
        gh_url = "https://api.github.com/advisories"
        params = {"per_page": 30}
        if software:
            params["package"] = software
        gh_r = requests.get(gh_url, headers={"Accept": "application/vnd.github+json"}, params=params, timeout=10)
        if gh_r.status_code == 200:
            gh_data = gh_r.json()
            gh_records = []
            for adv in gh_data:
                gh_records.append({
                    "Source": "GitHub",
                    "CVE ID": adv.get("cve_id") or adv.get("ghsa_id"),
                    "Published": adv.get("published_at", "")[:10],
                    "Severity": adv.get("severity", "UNKNOWN").upper(),
                    "Score": None,
                    "Affected Versions": str(adv.get("vulnerabilities", [{}])[0].get("vulnerable_version_range", "")),
                    "Description": adv.get("summary", "")[:180],
                    "Link": adv.get("html_url")
                })
            gh_df = pd.DataFrame(gh_records)
            if not gh_df.empty:
                company, country, src = get_company_info(vendor)
                gh_df["Company"] = company
                gh_df["Country"] = country
                gh_df["Info Source"] = src
                df_list.append(gh_df)
    except:
        pass

# ====================== DISPLAY ======================
if df_list:
    final_df = pd.concat(df_list, ignore_index=True)
    
    st.success(f"**{len(final_df)}** vulnerabilities found")

    csv = final_df.to_csv(index=False).encode()
    st.download_button("📥 Download Full CSV", csv, "cve_export_full.csv", "text/csv")

    st.dataframe(
        final_df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Affected Versions": st.column_config.TextColumn(width="medium"),
            "Description": st.column_config.TextColumn(width="large"),
            "Company": st.column_config.TextColumn(width="medium"),
            "Country": st.column_config.TextColumn(width="small"),
            "Info Source": st.column_config.TextColumn(width="small"),
        }
    )

    st.subheader("🔗 Quick Links")
    for _, row in final_df.iterrows():
        st.markdown(f"**{row['CVE ID']}** ({row['Source']}) — [View]({row['Link']})")
else:
    st.info("👈 Enter **Vendor** and/or **Software** above to search CVEs.")

st.sidebar.caption("✅ Version Info + Company + Country of Origin Added")
