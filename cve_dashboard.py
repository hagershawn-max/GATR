import streamlit as st
import requests
import pandas as pd
from datetime import datetime, timedelta

st.set_page_config(page_title="GATR CVE Explorer", layout="wide", page_icon="🛡️")

st.title("🛡️ GATR CVE Explorer")
st.markdown("Vendor + Software search with **Affected Versions** • NIST NVD")

# Sidebar
st.sidebar.header("🔍 Search Filters")

vendor = st.sidebar.text_input("Vendor", placeholder="apache, microsoft, oracle")
software = st.sidebar.text_input("Software/Product", placeholder="httpd, windows, log4j")

# Date range (max 120 days)
st.sidebar.subheader("Date Range (max 120 days)")
col1, col2 = st.sidebar.columns(2)
end_date = col2.date_input("To", datetime.now().date())
start_date = col1.date_input("From", end_date - timedelta(days=90))

severity = st.sidebar.multiselect(
    "Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH"]
)

results_per_page = st.sidebar.slider("Results per page", 10, 100, 50)
api_key = st.sidebar.text_input("NVD API Key (recommended)", type="password")

def extract_version_info(cve):
    """Extract affected versions from configurations"""
    versions = []
    configurations = cve.get("configurations", [])
    
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", False):
                    continue
                    
                criteria = match.get("criteria", "")
                # Parse CPE for version
                parts = criteria.split(":")
                if len(parts) > 5:
                    version = parts[5] if parts[5] != "*" else "Any"
                else:
                    version = "Any"
                
                # Check for version ranges
                start_inc = match.get("versionStartIncluding")
                start_exc = match.get("versionStartExcluding")
                end_inc = match.get("versionEndIncluding")
                end_exc = match.get("versionEndExcluding")
                
                range_str = ""
                if start_inc or start_exc or end_inc or end_exc:
                    if start_inc:
                        range_str += f">= {start_inc}"
                    elif start_exc:
                        range_str += f"> {start_exc}"
                    if range_str:
                        range_str += " "
                    if end_inc:
                        range_str += f"<= {end_inc}"
                    elif end_exc:
                        range_str += f"< {end_exc}"
                else:
                    range_str = version
                
                if range_str and range_str not in versions:
                    versions.append(range_str)
    
    return " | ".join(versions[:3]) if versions else "Not specified"

@st.cache_data(ttl=1800)
def search_cves(vendor, software, start_date, end_date, severity_list, page=0, api_key=None):
    if not vendor.strip() and not software.strip():
        return pd.DataFrame(), 0

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    keyword = f"{vendor} {software}".strip()

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": results_per_page,
        "startIndex": page * results_per_page,
    }

    if start_date and end_date:
        days_diff = (end_date - start_date).days
        if days_diff > 120:
            start_date = end_date - timedelta(days=120)
        params["pubStartDate"] = f"{start_date}T00:00:00.000"
        params["pubEndDate"] = f"{end_date}T23:59:59.999"

    headers = {"apiKey": api_key} if api_key else {}

    try:
        resp = requests.get(base_url, params=params, headers=headers, timeout=20)
        resp.raise_for_status()
        data = resp.json()

        vulns = data.get("vulnerabilities", [])
        total = data.get("totalResults", 0)

        records = []
        for item in vulns:
            cve = item["cve"]
            metrics = cve.get("metrics", {}).get("cvssMetricV31") or \
                      cve.get("metrics", {}).get("cvssMetricV30") or []

            sev = "UNKNOWN"
            score = None
            if metrics:
                m = metrics[0]
                sev = m.get("cvssData", {}).get("baseSeverity", "UNKNOWN")
                score = m.get("cvssData", {}).get("baseScore")

            if severity_list and sev not in [s.upper() for s in severity_list]:
                continue

            records.append({
                "CVE ID": cve["id"],
                "Published": cve.get("published", "")[:10],
                "Severity": sev,
                "Score": score,
                "Affected Versions": extract_version_info(cve),
                "Description": cve["descriptions"][0]["value"][:200] + "..." if cve.get("descriptions") else "N/A",
                "Link": f"https://nvd.nist.gov/vuln/detail/{cve['id']}"
            })

        return pd.DataFrame(records), total

    except Exception as e:
        st.error(f"API Error: {str(e)}")
        return pd.DataFrame(), 0

# Main UI
if vendor or software:
    page = st.session_state.get("page", 0)
    df, total_results = search_cves(vendor, software, start_date, end_date, severity, page, api_key)

    if not df.empty:
        st.success(f"**{total_results:,}** vulnerabilities found")

        csv = df.to_csv(index=False).encode('utf-8')
        st.download_button("📥 Download CSV", csv, f"cve_export_{datetime.now().strftime('%Y%m%d')}.csv", "text/csv")

        st.dataframe(
            df.drop(columns=["Link"]),
            use_container_width=True,
            hide_index=True,
            column_config={
                "Affected Versions": st.column_config.TextColumn(width="medium"),
                "Description": st.column_config.TextColumn(width="large"),
                "Score": st.column_config.NumberColumn(format="%.1f"),
            }
        )

        st.subheader("🔗 Quick Links")
        for _, row in df.iterrows():
            st.markdown(f"**{row['CVE ID']}** — [View on NVD]({row['Link']})")

        # Pagination
        total_pages = (total_results + results_per_page - 1) // results_per_page if total_results > 0 else 0
        c1, c2, c3 = st.columns([1, 2, 1])
        with c1:
            if st.button("← Previous") and page > 0:
                st.session_state.page = page - 1
                st.rerun()
        with c2:
            st.write(f"**Page {page+1}** of {total_pages} | Total: **{total_results:,}**")
        with c3:
            if st.button("Next →") and page < total_pages - 1:
                st.session_state.page = page + 1
                st.rerun()
    else:
        st.info("No results found.")
else:
    st.info("👈 Enter Vendor and/or Software in the sidebar.")

st.sidebar.caption("Version info extracted from CPE matches | Max 120 day range")
