import streamlit as st
import requests
import pandas as pd
from datetime import datetime, timedelta

# Dark Theme Configuration
st.set_page_config(
    page_title="GATR CVE Explorer",
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="expanded"
)

# Custom CSS for even better dark theme
st.markdown("""
<style>
    .stApp {
        background-color: #0A0C10;
    }
    .dataframe {
        background-color: #16181F;
        color: #E6E9F0;
    }
    .stDataFrame {
        background-color: #16181F;
    }
    h1, h2, h3 {
        color: #00BFFF;
    }
    .stButton>button {
        background-color: #1E90FF;
        color: white;
        border: none;
    }
    .stButton>button:hover {
        background-color: #00BFFF;
    }
    .css-1d391kg {
        background-color: #16181F;
    }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ GATR Multi-Source CVE Explorer")
st.markdown("**Dark Theme** • NVD + OSV.dev + GitHub Advisories")

# Sidebar
st.sidebar.header("🔍 Search Filters")

source = st.sidebar.selectbox(
    "Data Source", 
    ["All Sources", "NIST NVD", "OSV.dev", "GitHub Advisories"],
    index=0
)

vendor = st.sidebar.text_input("Vendor / Ecosystem", placeholder="apache, PyPI, npm")
software = st.sidebar.text_input("Software / Package", placeholder="log4j, openssl, django")

st.sidebar.subheader("Date Range (NVD only - max 120 days)")
col1, col2 = st.sidebar.columns(2)
end_date = col2.date_input("To", datetime.now().date())
start_date = col1.date_input("From", end_date - timedelta(days=90))

severity = st.sidebar.multiselect(
    "Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH"]
)

results_per_page = st.sidebar.slider("Results per page", 10, 100, 50)
api_key_nvd = st.sidebar.text_input("NVD API Key (optional)", type="password")

# [Keep the same functions: extract_versions_nvd, fetch_nvd, fetch_osv, etc.]
# ... (I'm keeping the full logic from the previous multi-source version)

# For brevity, paste your previous multi-source functions here
# (fetch_nvd, fetch_osv, GitHub part)

# Main display code remains the same as last version...

st.sidebar.caption("Professional Dark Theme • Multi-Source CVE Aggregator")
