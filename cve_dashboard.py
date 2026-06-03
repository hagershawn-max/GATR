import streamlit as st
import requests
import pandas as pd
from datetime import datetime, timedelta

st.set_page_config(page_title="GATR CVE Explorer", layout="wide", page_icon="🛡️")

st.title("🛡️ GATR Multi-Source CVE Explorer")
st.markdown("**NVD + OSV.dev + GitHub Advisories** with Detailed Version Info")

# Sidebar
st.sidebar.header("🔍 Search Filters")
source = st.sidebar.selectbox(
    "Data Source",
    ["All Sources", "NIST NVD", "OSV.dev", "GitHub Advisories"],
    index=0
)

vendor = st.sidebar.text_input("Vendor / Ecosystem", placeholder="apache, PyPI, npm, microsoft")
software = st.sidebar.text_input("Software / Package", placeholder="log4j, openssl, django")

st.sidebar.subheader("Date Range (NVD only)")
col1, col2 = st.sidebar.columns(2)
end_date = col2.date_input("To", datetime.now().date())
start_date = col1.date_input("From", end_date - timedelta(days=90))

severity = st.sidebar.multiselect(
    "Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH"]
)

results_per_page = st.sidebar.slider("Results per page", 10, 100, 50)
api_key_nvd = st.sidebar.text_input("NVD API Key (optional)", type="password")

# ==================== IMPROVED VERSION EXTRACTION ====================

def extract_versions_nvd(cve):
    versions = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                range_parts = []
                if match.get("versionStartIncluding"):
                    range_parts.append(f">= {match['versionStartIncluding']}")
                if match.get("versionStartExcluding"):
                    range_parts.append(f"> {match['versionStartExcluding']}")
                if match.get("versionEndIncluding"):
                    range_parts.append(f"<= {match['versionEndIncluding']}")
                if match.get("versionEndExcluding"):
                    range_parts.append(f"< {match['versionEndExcluding']}")
                if range_parts:
                    versions.append(" ".join(range_parts))
                elif match.get("criteria"):
                    # Fallback to CPE version
                    parts = match["criteria"].split(":")
                    if len(parts) > 5 and parts[5] != "*":
                        versions.append(parts[5])
    return " | ".join(versions[:4]) if versions else "Not specified"

def extract_versions_osv(vuln):
    affected_list = []
    for affected in vuln.get("affected", []):
        # Try version ranges first
        for r in affected.get("ranges", []):
            for event in r.get("events", []):
                if "introduced" in event:
                    affected_list.append(f">= {event['introduced']}")
                if "fixed" in event:
                    affected_list.append(f"< {event['fixed']}")
        
        # Add specific versions
        for v in affected.get("versions", [])[:5]:
            if v not in affected_list:
                affected_list.append(v)
    
    return " | ".join(affected_list[:6]) if affected_list else "Not specified"

def extract_versions_github(adv):
    versions = []
    for vuln in adv.get("vulnerabilities", []):
        if vuln.get("vulnerable_version_range"):
            versions.append(vuln["vulnerable_version_range"])
        if vuln.get("package"):
            versions.append(vuln["package"].get("version", ""))
    return " | ".join(versions[:4]) if versions else "Not specified"

# ==================== FETCH FUNCTIONS ====================

@st.cache_data(ttl=1200)
def fetch_nvd(vendor, software, start_date, end_date, severity_list, page=0, api_key=None):
    if not vendor and not software:
        return pd.DataFrame(), 0
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    keyword = f"{vendor} {software}".strip()
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": results_per_page,
        "startIndex": page * results_per_page,
    }
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
            sev = metrics[0]["cvssData"]["baseSeverity"] if metrics else "UNKNOWN"
            score = metrics[0]["cvssData"]["baseScore"] if metrics else None

            if severity_list and sev not in [s.upper() for s in severity_list]:
                continue

            records.append({
                "Source": "NVD",
                "CVE ID": cve["id"],
                "Published": cve.get("published", "")[:10],
                "Severity": sev,
                "Score": score,
                "Affected Versions": extract_versions_nvd(cve),
                "Description": cve["descriptions"][0]["value"][:180] + "..." if cve.get("descriptions") else "",
                "Link": f"https://nvd.nist.gov/vuln/detail/{cve['id']}"
            })
        return pd.DataFrame(records), data.get("totalResults", 0)
    except Exception:
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

# ==================== MAIN LOGIC ====================

df_list = []

if source in ["All Sources", "NIST NVD"]:
    nvd_df, total_nvd = fetch_nvd(vendor, software, start_date, end_date, severity, 0, api_key_nvd)
    if not nvd_df.empty:
        df_list.append(nvd_df)

if source in ["All Sources", "OSV.dev"]:
    osv_df = fetch_osv(vendor, software, severity)
    if not osv_df.empty:
        df_list.append(osv_df)

if source in ["All Sources", "GitHub Advisories"]:
    try:
        gh_url = "https://api.github.com/advisories"
        params = {"per_page": results_per_page}
        if software:
            params["package"] = software
        if vendor:
            params["ecosystem"] = vendor
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
                    "Affected Versions": extract_versions_github(adv),
                    "Description": adv.get("summary", "")[:180],
                    "Link": adv.get("html_url")
                })
            df_list.append(pd.DataFrame(gh_records))
    except:
        pass

# Combine and display
if df_list:
    final_df = pd.concat(df_list, ignore_index=True)
    st.success(f"**{len(final_df)}** vulnerabilities found across sources")

    csv = final_df.to_csv(index=False).encode()
    st.download_button("📥 Download CSV", csv, "cve_export.csv", "text/csv")

    st.dataframe(
        final_df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Affected Versions": st.column_config.TextColumn(width="medium"),
            "Description": st.column_config.TextColumn(width="large"),
            "Score": st.column_config.NumberColumn(format="%.1f"),
        }
    )

    st.subheader("🔗 Quick Links")
    for _, row in final_df.iterrows():
        st.markdown(f"**{row['CVE ID']}** ({row['Source']}) — [View]({row['Link']})")
else:
    st.info("Enter search terms above. Try: Vendor=`apache`, Software=`log4j`")

st.sidebar.caption("Enhanced Version Information • Multi-Source CVE Aggregator")
