"""
Secoraa ASM - Main Application Router
"""
import streamlit as st
from ui.theme import apply_theme
from views.scan import render_scan_view
from views.asset_discovery import render_asset_discovery

# Page configuration
st.set_page_config(
    page_title="Secoraa | ASM",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Apply custom theme
apply_theme()

# Custom sidebar styling
st.markdown("""
<style>
    [data-testid="stSidebar"] {
        background-color: #1F2937;
    }
    [data-testid="stSidebar"] .css-1d391kg {
        padding-top: 1rem;
    }
    .sidebar-header {
        color: #E5E7EB;
        font-size: 1.5rem;
        font-weight: bold;
        margin-bottom: 2rem;
    }
    .sidebar-section {
        color: #9CA3AF;
        font-size: 0.875rem;
        font-weight: 600;
        text-transform: uppercase;
        margin-top: 1.5rem;
        margin-bottom: 0.5rem;
    }
    .sidebar-item {
        color: #E5E7EB;
        padding: 0.5rem 0;
        cursor: pointer;
    }
    .sidebar-item:hover {
        color: #7C7CFF;
    }
    .sidebar-item.active {
        color: #7C7CFF;
        background-color: #111827;
        padding-left: 0.5rem;
        border-left: 3px solid #7C7CFF;
    }
</style>
""", unsafe_allow_html=True)

# Sidebar Navigation
with st.sidebar:
    # Logo and Header
    st.markdown('<div class="sidebar-header">🛡️ Secoraa</div>', unsafe_allow_html=True)
    
    # Organization selector (placeholder)
    st.selectbox("Organization", ["Demo Org"], key="org_selector", label_visibility="collapsed")
    
    st.markdown("---")
    
    # ASM Section
    st.markdown('<div class="sidebar-section">ASM</div>', unsafe_allow_html=True)
    
    # Navigation options
    page = st.radio(
        "Navigation",
        ["Asset Discovery", "Scan", "Vulnerability", "Reporting", "Settings", "Help Center"],
        label_visibility="collapsed",
        key="nav_radio"
    )
    
    st.markdown("---")
    
    # User info (placeholder)
    st.markdown("""
    <div style="position: fixed; bottom: 20px; left: 20px; color: #9CA3AF; font-size: 0.875rem;">
        👤 Jane Smith<br>
        Demo Org
    </div>
    """, unsafe_allow_html=True)

# Main content routing
if page == "Asset Discovery":
    render_asset_discovery()
elif page == "Scan":
    render_scan_view()
elif page == "Vulnerability":
    st.markdown("# VULNERABILITY")
    st.info("Vulnerability management - Coming soon")
elif page == "Reporting":
    st.markdown("# REPORTING")
    st.info("Reporting dashboard - Coming soon")
elif page == "Settings":
    st.markdown("# SETTINGS")
    st.info("Settings - Coming soon")
elif page == "Help Center":
    st.markdown("# HELP CENTER")
    st.info("Help Center - Coming soon")
