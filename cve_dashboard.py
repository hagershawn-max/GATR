import streamlit as st
import requests
import pandas as pd
from datetime import datetime, timedelta

st.set_page_config(page_title="GATR CVE Explorer", layout="wide", page_icon="🛡️")

st.title("🛡️ GATR CVE Explorer")
st.markdown("**Vendor + Software** search • NIST NVD • Export support")

# Sidebar
st.sidebar.header("🔍 Search Filters")

vendor = st.sidebar.text_input("Vendor", placeholder="apache, microsoft, oracle, cisco")
software = st.sidebar.text_input("Software/Product", placeholder="httpd, windows, log4j, openssl")

col_date1, col_date2 = st.sidebar.columns(2)
start_date = col_date1.date_input("Published After", datetime.now() - timedelta(days=365*2))
end_date = col_date2.date_input("Published Before", datetime.now())

severity = st.sidebar.multiselect(
    "Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH"]
)

results_per_page = st.sidebar.slider("Results per page", 10, 100, 50)
api_key = st.sidebar.text_input("NVD API Key (optional)", type="password")

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
        "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
    }

    headers = {"apiKey": api_key} if api_key else {}

    try:
        resp = requests.get(base_url, params=params, headers=headers, timeout=25)
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
                "Description": cve["descriptions"][0]["value"] if cve.get("descriptions") else "N/A",
                "References": len(cve.get("references", [])),
                "Link": f"https://nvd.nist.gov/vuln/detail/{cve['id']}"
            })

        return pd.DataFrame(records), total
    except Exception as e:
        st.error(f"API Error: {str(e)}")
        return pd.DataFrame(), 0

# Main Area
if vendor or software:
    page = st.session_state.get("page", 0)
    df, total_results = search_cves(vendor, software, start_date, end_date, severity, page, api_key)

    if not df.empty:
        st.success(f"Found **{total_results:,}** vulnerabilities")

        # Export Button
        csv = df.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Download Results as CSV",
            data=csv,
            file_name=f"cve_export_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv"
        )

        st.dataframe(
            df.drop(columns=["Link"]),
            use_container_width=True,
            hide_index=True
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
        st.info("No results found for the current filters.")
else:
    st.info("👈 Use the sidebar to search by **Vendor** and/or **Software**.")

st.sidebar.markdown("---")
st.sidebar.caption("Powered by NIST NVD API • GATR CVE Explorer")
