"""
Scan View - Run and manage scans
"""
import streamlit as st
from api_client import get_domains, create_scan, get_all_scans, get_scan_results
import pandas as pd


def render_scan_view():
    """Render the Scan page"""
    
    st.markdown("# SCAN")
    st.markdown("---")
    
    # Tabs for Scan Management
    tab1, tab2 = st.tabs(["Run Scan", "Scan History"])
    
    # Run Scan Tab
    with tab1:
        st.markdown("### 🚀 Run New Scan")
        
        # Fetch available domains
        try:
            domains_data = get_domains()
            domains = domains_data if isinstance(domains_data, list) else domains_data.get("data", [])
            domain_names = [d.get("domain_name", "") for d in domains if d.get("domain_name")]
        except Exception as e:
            st.error(f"Failed to load domains: {e}")
            domain_names = []
        
        if not domain_names:
            st.warning("No domains available. Please add a domain in Asset Discovery first.")
            return
        
        # Scan form
        with st.form("run_scan_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                scan_name = st.text_input("Scan Name", placeholder="My Domain Scan")
                scan_type = st.selectbox(
                    "Scan Type",
                    ["dd"],  # Domain Discovery
                    format_func=lambda x: "Domain Discovery (DD)" if x == "dd" else x
                )
            
            with col2:
                domain = st.selectbox("Target Domain", domain_names)
                st.markdown("<br>", unsafe_allow_html=True)  # Spacing
            
            submitted = st.form_submit_button("🚀 Run Scan", type="primary", use_container_width=True)
        
        if submitted:
            if not scan_name:
                st.error("Please enter a scan name")
            else:
                with st.spinner(f"Running scan on {domain}... This may take a few minutes."):
                    try:
                        result = create_scan(scan_name, scan_type, domain)
                        st.success("✅ Scan started successfully!")
                        st.json(result)
                    except Exception as e:
                        st.error(f"❌ Scan failed: {e}")
    
    # Scan History Tab
    with tab2:
        st.markdown("### 📊 Scan History")
        
        try:
            scans_data = get_all_scans()
            scans = scans_data.get("data", []) if isinstance(scans_data, dict) else scans_data
            
            if not scans:
                st.info("No scans found. Run a scan to see history here.")
            else:
                # Build table
                table_data = []
                for scan in scans:
                    table_data.append({
                        "Scan Name": scan.get("scan_name", ""),
                        "Scan Type": scan.get("scan_type", "").upper(),
                        "Status": scan.get("status", ""),
                        "Created At": scan.get("created_at", ""),
                        "Created By": scan.get("created_by", "N/A"),
                    })
                
                df = pd.DataFrame(table_data)
                st.dataframe(df, use_container_width=True, hide_index=True)
                
                # View scan details
                st.markdown("### 📋 View Scan Details")
                selected_scan_name = st.selectbox(
                    "Select Scan",
                    [s.get("scan_name", "") for s in scans]
                )
                
                if selected_scan_name:
                    selected_scan = next(
                        (s for s in scans if s.get("scan_name") == selected_scan_name),
                        None
                    )
                    
                    if selected_scan:
                        scan_id = selected_scan.get("scan_id", "")
                        if st.button("View Results", type="primary"):
                            try:
                                results = get_scan_results(scan_id)
                                st.json(results)
                                
                                # Show subdomains in a table
                                if results.get("subdomains"):
                                    st.markdown("### 🌐 Discovered Subdomains")
                                    subdomains_df = pd.DataFrame({
                                        "Subdomain": results["subdomains"]
                                    })
                                    st.dataframe(subdomains_df, use_container_width=True, hide_index=True)
                            except Exception as e:
                                st.error(f"Failed to load scan results: {e}")
        
        except Exception as e:
            st.error(f"Failed to load scans: {e}")
