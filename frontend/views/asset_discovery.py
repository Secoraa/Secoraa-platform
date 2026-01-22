"""
Asset Discovery View - Main asset management interface
"""
import streamlit as st
from api_client import get_domains, create_domain
import pandas as pd


def render_asset_discovery():
    """Render the Asset Discovery page matching the design"""
    
    # Page Title
    st.markdown("# ASSET DISCOVERY")
    st.markdown("---")
    
    # Asset Type Tabs
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "Domains", "Subdomains", "IP Addresses", "URL", "IP Blocks", "Asset Groups"
    ])
    
    # Fetch domains
    try:
        domains_data = get_domains()
        # Handle both list and dict responses
        if isinstance(domains_data, list):
            domains = domains_data
        elif isinstance(domains_data, dict) and "data" in domains_data:
            domains = domains_data["data"]
        else:
            domains = domains_data if domains_data else []
    except Exception as e:
        st.error(f"Failed to load domains: {e}")
        domains = []
    
    # Calculate metrics
    total_domains = len(domains)
    total_subdomains = sum(len(d.get("subdomains", [])) for d in domains)
    
    # Domains Tab
    with tab1:
        # Metrics row
        col1, col2, col3, col4, col5 = st.columns(5)
        col1.metric("Domains", total_domains)
        col2.metric("Subdomains", total_subdomains if total_subdomains < 1000 else "999+")
        col3.metric("IP Addresses", "31")
        col4.metric("URL", "0")
        col5.metric("IP Blocks", "0")
        
        st.markdown("---")
        
        # Filters row
        filter_col1, filter_col2, filter_col3, filter_col4 = st.columns([3, 2, 2, 1])
        with filter_col1:
            search_query = st.text_input("🔍 Search Name", key="domain_search", placeholder="Q Search Name")
        with filter_col2:
            active_filter = st.selectbox("Active", ["All", "Active", "Inactive"], key="active_filter")
        with filter_col3:
            labels_filter = st.selectbox("All Labels", ["All", "Production", "External", "Internal"], key="labels_filter")
        with filter_col4:
            st.markdown("<br>", unsafe_allow_html=True)
            export_btn = st.button("Export", type="primary")
        
        st.markdown("---")
        
        # Filter domains based on search
        filtered_domains = domains
        if search_query:
            filtered_domains = [
                d for d in domains 
                if search_query.lower() in d.get("domain_name", "").lower()
            ]
        
        # Build table data
        table_data = []
        for domain in filtered_domains:
            domain_name = domain.get("domain_name", "")
            subdomains = domain.get("subdomains", [])
            tags = domain.get("tags", [])
            
            # Format asset labels
            asset_labels = ", ".join(tags) if tags else "Manually Added"
            
            # Calculate subdomain count
            subdomain_count = len(subdomains)
            
            # Scan status (placeholder - would need actual scan data)
            scan_status = "🟢 🟢"  # Two green circles (B and D scans)
            
            table_data.append({
                "NAME": domain_name,
                "SCAN STATUS": scan_status,
                "ASSET LABELS": asset_labels,
                "SUBDOMAIN COUNT": subdomain_count,
                "ASN COUNT": 0,  # Placeholder
                "VULNERABILITY COUNT": 0,  # Placeholder - would need vulnerability data
            })
        
        # Display table
        if table_data:
            df = pd.DataFrame(table_data)
            
            # Custom table styling
            st.markdown("""
            <style>
            .dataframe {
                background-color: #1F2937;
                color: #E5E7EB;
            }
            .dataframe th {
                background-color: #111827;
                color: #7C7CFF;
                font-weight: 600;
            }
            .dataframe td {
                background-color: #1F2937;
            }
            </style>
            """, unsafe_allow_html=True)
            
            st.dataframe(
                df,
                use_container_width=True,
                hide_index=True,
                height=400
            )
            
            # Pagination info
            st.markdown(f"**Rows per page:** 5 | **1-{min(5, len(table_data))} of {len(table_data)}**")
        else:
            st.info("No domains found. Create a domain to get started.")
    
    # Subdomains Tab
    with tab2:
        st.info("Subdomains view - Coming soon")
        # Would show all subdomains across all domains
    
    # Other tabs
    with tab3:
        st.info("IP Addresses view - Coming soon")
    with tab4:
        st.info("URL view - Coming soon")
    with tab5:
        st.info("IP Blocks view - Coming soon")
    with tab6:
        st.info("Asset Groups view - Coming soon")
    
    # Add Domain Button (floating or in sidebar)
    with st.sidebar:
        st.markdown("---")
        if st.button("➕ Add Domain", type="primary", use_container_width=True):
            st.session_state["show_add_domain"] = True
    
    # Add Domain Modal
    if st.session_state.get("show_add_domain", False):
        with st.expander("➕ Add New Domain", expanded=True):
            with st.form("add_domain_form"):
                domain_name = st.text_input("Domain Name", placeholder="example.com")
                tags_input = st.text_input("Tags (comma-separated)", placeholder="production, external")
                
                col1, col2 = st.columns(2)
                with col1:
                    submit = st.form_submit_button("Add Domain", type="primary")
                with col2:
                    cancel = st.form_submit_button("Cancel")
                
                if submit and domain_name:
                    try:
                        tags = [t.strip() for t in tags_input.split(",")] if tags_input else []
                        result = create_domain(domain_name, tags)
                        st.success(f"Domain {domain_name} added successfully!")
                        st.session_state["show_add_domain"] = False
                        st.rerun()
                    except Exception as e:
                        st.error(f"Failed to add domain: {e}")
                
                if cancel:
                    st.session_state["show_add_domain"] = False
                    st.rerun()
