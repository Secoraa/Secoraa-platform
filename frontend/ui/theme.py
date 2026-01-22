"""
Secoraa Dark Theme Configuration
"""
import streamlit as st

# Custom CSS for Secoraa branding
SECORAA_CSS = """
<style>
    /* Main container styling */
    .main .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
    }
    
    /* Sidebar styling */
    [data-testid="stSidebar"] {
        background-color: #1F2937;
        color: #E5E7EB;
    }
    
    [data-testid="stSidebar"] .css-1d391kg {
        padding-top: 1rem;
    }
    
    /* Header styling */
    .header-container {
        background-color: #111827;
        padding: 1rem 2rem;
        margin-bottom: 2rem;
        border-bottom: 1px solid #374151;
    }
    
    /* Table styling */
    .asset-table {
        background-color: #1F2937;
        border-radius: 8px;
        padding: 1rem;
    }
    
    /* Tab styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    
    .stTabs [data-baseweb="tab"] {
        background-color: #374151;
        color: #E5E7EB;
        border-radius: 6px 6px 0 0;
        padding: 0.5rem 1rem;
    }
    
    .stTabs [aria-selected="true"] {
        background-color: #111827;
        color: #7C7CFF;
    }
    
    /* Button styling */
    .stButton > button {
        background-color: #7C7CFF;
        color: white;
        border-radius: 6px;
        border: none;
        font-weight: 500;
    }
    
    .stButton > button:hover {
        background-color: #6B6BFF;
    }
    
    /* Status badges */
    .status-badge {
        display: inline-block;
        padding: 0.25rem 0.75rem;
        border-radius: 12px;
        font-size: 0.75rem;
        font-weight: 600;
    }
    
    .status-active {
        background-color: #10B981;
        color: white;
    }
    
    .status-inactive {
        background-color: #EF4444;
        color: white;
    }
    
    /* Metric cards */
    .metric-card {
        background-color: #1F2937;
        padding: 1rem;
        border-radius: 8px;
        border: 1px solid #374151;
    }
</style>
"""

def apply_theme():
    """Apply Secoraa dark theme CSS"""
    st.markdown(SECORAA_CSS, unsafe_allow_html=True)

