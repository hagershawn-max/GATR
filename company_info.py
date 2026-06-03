import streamlit as st
import pandas as pd
import requests
from datetime import datetime

st.set_page_config(page_title="GATR Company Info", layout="wide", page_icon="🏢")

st.title("🏢 GATR Company & Country Lookup")
st.markdown("**Software Vendor → Owning Company + Headquarters Country** (with web search fallback)")

# Local Database (fast lookup)
vendor_db = {
    "apache": {"company": "The Apache Software Foundation", "country": "United States"},
    "microsoft": {"company": "Microsoft Corporation", "country": "United States"},
    "oracle": {"company": "Oracle Corporation", "country": "United States"},
    "google": {"company": "Google LLC", "country": "United States"},
    "amazon": {"company": "Amazon Web Services", "country": "United States"},
    "redhat": {"company": "Red Hat, Inc.", "country": "United States"},
    "ibm": {"company": "IBM", "country": "United States"},
    "cisco": {"company": "Cisco Systems", "country": "United States"},
    "apple": {"company": "Apple Inc.", "country": "United States"},
    "intel": {"company": "Intel Corporation", "country": "United States"},
    "canonical": {"company": "Canonical Ltd.", "country": "United Kingdom"},
    "docker": {"company": "Docker, Inc.", "country": "United States"},
    "nginx": {"company": "F5, Inc.", "country": "United States"},
    "wordpress": {"company": "Automattic", "country": "United States"},
    "mozilla": {"company": "Mozilla Foundation", "country": "United States"},
    "sap": {"company": "SAP SE", "country": "Germany"},
    "huawei": {"company": "Huawei Technologies", "country": "China"},
    "alibaba": {"company": "Alibaba Group", "country": "China"},
    "vmware": {"company": "VMware (Broadcom)", "country": "United States"},
}

def web_search_company(vendor):
    """Fallback: Search the web for company and country"""
    try:
        query = f"{vendor} software company headquarters country owner"
        # Using DuckDuckGo HTML search (no API key needed)
        url = f"https://html.duckduckgo.com/html/?q={query.replace(' ', '+')}"
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(url, headers=headers, timeout=10)
        
        text = response.text.lower()
        
        company = "Unknown"
        country = "Unknown"
        
        # Simple keyword extraction
        if "united states" in text or "u.s." in text or "usa" in text:
            country = "United States"
        elif "china" in text:
            country = "China"
        elif "germany" in text:
            country = "Germany"
        elif "united kingdom" in text or "uk" in text:
            country = "United Kingdom"
        elif "russia" in text:
            country = "Russia"
        elif "france" in text:
            country = "France"
        
        # Try to extract company name
        if "inc." in text or "corporation" in text or "llc" in text:
            company = vendor.title() + " Corporation"  # fallback
        
        return {"company": company, "country": country}
    except:
        return {"company": "Search failed", "country": "Unknown"}

# Sidebar
st.sidebar.header("🔍 Search Vendor")
search_term = st.sidebar.text_input("Vendor / Software Name", placeholder="apache, nginx, log4j...").strip().lower()

if search_term:
    info = vendor_db.get(search_term)
    
    # Try fuzzy match in local DB
    if not info:
        for key in vendor_db:
            if key in search_term or search_term in key:
                info = vendor_db[key]
                break

    if info:
        st.success("✅ Found in local database")
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Vendor", search_term.upper())
        with col2:
            st.metric("Owning Company", info["company"])
            st.metric("Headquarters", info["country"])
    else:
        st.warning(f"**{search_term}** not in local database. Searching the web...")
        with st.spinner("Performing web search..."):
            info = web_search_company(search_term)
        
        if info["country"] != "Unknown":
            st.success("✅ Found via Web Search")
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Vendor", search_term.upper())
            with col2:
                st.metric("Owning Company", info["company"])
                st.metric("Headquarters", info["country"])
        else:
            st.error("Could not find reliable information.")

# Display full local database
st.subheader("📋 Local Vendor Database")
df = pd.DataFrame.from_dict(vendor_db, orient='index')
df.index.name = "Vendor"
st.dataframe(df, use_container_width=True)

st.caption("💡 If not found locally, the app automatically searches the web.")
