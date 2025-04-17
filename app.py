import streamlit as st
import os
import base64
import time
import hashlib
import random
import string
import json
from datetime import datetime
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import plotly.express as px
import plotly.graph_objects as go
from PIL import Image
import io
import uuid
import re

# Import custom modules
from modules.encryption import (
    encrypt_file, decrypt_file, generate_key, 
    determine_encryption_method, simulate_quantum_key
)
from modules.user_management import (
    authenticate_user, create_user, get_user_data,
    update_user_score, get_all_users
)
from modules.file_management import (
    save_file, get_file_info, get_user_files,
    share_file, update_file_access, create_merkle_tree,
    verify_file_integrity, parse_permission_command
)
from modules.ui_components import (
    render_sidebar, render_login_page, render_dashboard,
    render_file_upload, render_file_list, render_file_preview,
    render_encryption_details, render_sharing_options,
    render_user_stats, render_visualization_dashboard
)

# Set page configuration
st.set_page_config(
    page_title="Cipher Cloud",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Load custom CSS
def load_css():
    with open('styles.css') as f:
        st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

# Initialize session state
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'username' not in st.session_state:
    st.session_state.username = None
if 'current_file' not in st.session_state:
    st.session_state.current_file = None
if 'entropy_pool' not in st.session_state:
    st.session_state.entropy_pool = []
if 'mouse_movements' not in st.session_state:
    st.session_state.mouse_movements = []

# Create necessary directories
os.makedirs('data/users', exist_ok=True)
os.makedirs('data/files', exist_ok=True)
os.makedirs('data/keys', exist_ok=True)
os.makedirs('data/access_logs', exist_ok=True)

# Main application
def main():
    try:
        load_css()
    except:
        st.warning("Custom CSS file not found. Using default styling.")
    
    # Collect randomness from user interactions
    collect_randomness()
    
    # Check if user is logged in
    if not st.session_state.logged_in:
        render_login_page()
    else:
        # Render sidebar
        render_sidebar()
        
        # Main content area
        tab1, tab2, tab3, tab4 = st.tabs(["Dashboard", "File Management", "Sharing", "Analytics"])
        
        with tab1:
            render_dashboard()
        
        with tab2:
            col1, col2 = st.columns([1, 2])
            with col1:
                render_file_upload()
            with col2:
                render_file_list()
            
            if st.session_state.current_file:
                render_file_preview()
                render_encryption_details()
        
        with tab3:
            if st.session_state.current_file:
                render_sharing_options()
            else:
                st.info("Please select a file to share")
        
        with tab4:
            render_visualization_dashboard()
            render_user_stats()

# Function to collect randomness from user interactions
def collect_randomness():
    # Simulate collecting entropy from user interactions
    timestamp = datetime.now().timestamp()
    random_value = random.random()
    
    # Add to entropy pool
    if len(st.session_state.entropy_pool) > 1000:
        st.session_state.entropy_pool.pop(0)
    
    st.session_state.entropy_pool.append(f"{timestamp}_{random_value}")

if __name__ == "__main__":
    main()