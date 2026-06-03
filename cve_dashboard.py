import streamlit as st
import requests
import pandas as pd
from datetime import datetime, timedelta

st.set_page_config(page_title="GATR CVE Explorer", layout="wide", page_icon="🛡️")

st.title("🛡️ GATR CVE Explorer")
st.markdown("Vendor + Software search • NIST NVD")

# Sidebar
st.sidebar.header("🔍 Search Filters")

vendor = st.sidebar.text_input("Vendor", placeholder="apache, microsoft, oracle")
software = st.sidebar.text_input("Software/Product", placeholder="httpd, windows, log4j")

# Date range (max 120 days)
st.sidebar.subheader("Date Range (max 120 days)")
col1, col2 = st.sidebar.columns(2)
end_date = col2.date_input("To", datetime.now().date())
start_date = col1.date_input("From", end_date - timedelta(days=90))  # Default 90 days

severity = st.sidebar.multiselect(
    "Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH"]
)

results_per_page = st.sidebar.slider("Results per page", 10, 100, 50)
api_key = st.sidebar.text_input("NVD API Key (recommended)", type="password")

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

    # Only add dates if both are provided (and within 120 days)
    if start_date and end_date:
        days_diff = (end_date - start_date).days
        if days_diff > 120:
            st.warning("Date range limited to 120 days by NVD API. Adjusting automatically.")
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
            metrics = cve.get("metrics", {}).get("cvssMetricV31") or cve.get("metrics", {}).get("cvssMetricV30") or []

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
                "Description": cve["descriptions"][0]["value"] if cve.get("descriptions") else "N/A",
                "References": len(cve.get("references", [])),
                "Link": f"https://nvd.nist.gov/vuln/detail/{cve['id']}"
            })

        return pd.DataFrame(records), total

    except requests.exceptions.HTTPError as e:
        if resp.status_code == 404:
            st.error("❌ NVD API Error: Invalid parameters (likely date range). Try a shorter range.")
        elif resp.status_code == 429:
            st.error("Rate limited. Add an NVD API key or wait a few seconds.")
        else:
            st.error(f"API Error: {str(e)}")
        return pd.DataFrame(), 0
    except Exception as e:
        st.error(f"Error: {str(e)}")
        return pd.DataFrame(), 0

# Main UI
if vendor or software:
    page = st.session_state.get("page", 0)
    df, total_results = search_cves(vendor, software, start_date, end_date, severity, page, api_key)

    if not df.empty:
        st.success(f"**{total_results:,}** vulnerabilities found")

        csv = df.to_csv(index=False).encode('utf-8')
        st.download_button("📥 Download CSV", csv, f"cve_{datetime.now().strftime('%Y%m%d')}.csv", "text/csv")

        st.dataframe(df.drop(columns=["Link"]), use_container_width=True, hide_index=True)

        st.subheader("🔗 Quick Links")
        for _, row in df.iterrows():
            st.markdown(f"**{row['CVE ID']}** — [View on NVD]({row['Link']})")

        total_pages = (total_results + results_per_page - 1) // results_per_page if total_results > 0 else 0
        c1, c2, c3 = st.columns([1, 2, 1])
        with c1:
            if st.button("← Previous") and page > 0:
                st.session_state.page = page - 1
                st.rerun()
        with c2:
            st.write(f"Page **{page+1}** of {total_pages} | Total: **{total_results:,}**")
        with c3:
            if st.button("Next →") and page < total_pages - 1:
                st.session_state.page = page + 1
                st.rerun()
    else:
        st.info("No results. Try different search terms or shorter date range.")
else:
    st.info("👈 Enter Vendor and/or Software in the sidebar.")

st.sidebar.caption("Fixed: Date range now max 120 days | Get free API key from NVD")
