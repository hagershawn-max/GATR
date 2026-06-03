import streamlit as st
import pandas as pd
import requests
from bs4 import BeautifulSoup
from datetime import datetime

st.set_page_config(page_title="GATR Company Info", layout="wide", page_icon="🏢")

st.title("🏢 GATR Company & Country Lookup")
st.markdown("**Vendor Intelligence** with transparent source attribution")

# Local Database
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

def structured_web_scrape(vendor):
    """Structured scraping with clear source attribution"""
    result = {
        "company": "Unknown",
        "country": "Unknown",
        "source": "Web Search",
        "attribution": "DuckDuckGo + Wikipedia"
    }
    
    try:
        query = f"{vendor} company headquarters country"
        url = f"https://html.duckduckgo.com/html/?q={query.replace(' ', '+')}"
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        
        resp = requests.get(url, headers=headers, timeout=12)
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        snippets = [s.get_text() for s in soup.find_all(['a', 'div']) if s.get_text()]
        text_block = " ".join(snippets[:8]).lower()
        
        # Country detection
        country_map = {
            "united states": "United States", "usa": "United States", "u.s.": "United States",
            "united kingdom": "United Kingdom", "uk": "United Kingdom",
            "germany": "Germany", "china": "China", "france": "France",
            "netherlands": "Netherlands", "canada": "Canada", "india": "India"
        }
        
        for key, full_name in country_map.items():
            if key in text_block:
                result["country"] = full_name
                break
        
        # Company name
        title_tag = soup.find('a', class_='result__a')
        if title_tag:
            result["company"] = title_tag.get_text(strip=True)[:90]
        
        # Wikipedia fallback for higher quality
        if result["country"] == "Unknown":
            try:
                wiki_url = f"https://en.wikipedia.org/wiki/{vendor.replace(' ', '_')}"
                wiki_resp = requests.get(wiki_url, headers=headers, timeout=8)
                if wiki_resp.status_code == 200:
                    wiki_soup = BeautifulSoup(wiki_resp.text, 'html.parser')
                    infobox = wiki_soup.find('table', {'class': 'infobox'})
                    if infobox:
                        wiki_text = infobox.get_text().lower()
                        for key, full_name in country_map.items():
                            if key in wiki_text:
                                result["country"] = full_name
                                result["source"] = "Wikipedia"
                                result["attribution"] = "Wikipedia Infobox"
                                break
                        result["company"] = vendor.title()
            except:
                pass
                
    except Exception as e:
        result["company"] = "Search Error"
        result["attribution"] = f"Error: {str(e)[:60]}"
    
    return result

# Sidebar
st.sidebar.header("🔍 Search")
search_term = st.sidebar.text_input("Vendor / Software Name", placeholder="apache, huawei, nginx, gimp...").strip().lower()

if search_term:
    # Check local database first
    info = vendor_db.get(search_term)
    if not info:
        for key in vendor_db:
            if key in search_term or search_term in key:
                info = vendor_db[key]
                break

    if info:
        st.success("✅ Found in **Local Database**")
        col1, col2, col3 = st.columns([1, 2, 2])
        with col1:
            st.metric("Vendor", search_term.upper())
        with col2:
            st.metric("Company", info["company"])
        with col3:
            st.metric("Headquarters", info["country"])
        st.caption("**Source**: Built-in Local Database")
    else:
        st.info(f"🔍 Searching web for **{search_term}**...")
        with st.spinner("Performing structured web scrape..."):
            info = structured_web_scrape(search_term)
        
        col1, col2, col3 = st.columns([1, 2, 2])
        with col1:
            st.metric("Vendor", search_term.upper())
        with col2:
            st.metric("Company", info["company"])
        with col3:
            st.metric("Headquarters", info["country"])
        
        st.caption(f"**Source**: {info['source']} • {info['attribution']}")

# Database Table
st.subheader("📋 Local Vendor Database")
df = pd.DataFrame.from_dict(vendor_db, orient='index')
df.index.name = "Vendor"
st.dataframe(df, use_container_width=True)

st.caption("💡 Priority: Local Database → Structured Web Scraping (DuckDuckGo + Wikipedia)")
