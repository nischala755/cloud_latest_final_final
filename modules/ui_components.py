import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import matplotlib.pyplot as plt
import seaborn as sns
import base64
from PIL import Image
import io
import time
import random
import os
from datetime import datetime, timedelta
import hashlib
# Import custom modules
from modules.user_management import (
    authenticate_user, create_user, get_user_data,
    update_user_score, get_all_users
)
from modules.file_management import (
    save_file, get_file_info, get_user_files,
    share_file, update_file_access, get_file_data,
    get_encryption_key, verify_file_integrity,
    parse_permission_command, delete_file,
    get_file_access_logs, get_files_by_extension
)
from modules.encryption import (
    encrypt_file, decrypt_file, generate_key,
    determine_encryption_method, simulate_quantum_key
)

# Render login page
def render_login_page():
    st.markdown("""
    <div class="login-container">
        <div class="login-box">
            <h1>Cipher Cloud</h1>
            <h3>Secure Enterprise File Management</h3>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Create tabs for login and register
    login_tab, register_tab = st.tabs(["Login", "Register"])
    
    with login_tab:
        username = st.text_input("Username", key="login_username")
        password = st.text_input("Password", type="password", key="login_password")
        
        if st.button("Login", key="login_button"):
            if username and password:
                success, message = authenticate_user(username, password)
                if success:
                    st.session_state.logged_in = True
                    st.session_state.username = username
                    st.success(message)
                    st.rerun()
                else:
                    st.error(message)
            else:
                st.warning("Please enter both username and password")
    
    with register_tab:
        new_username = st.text_input("Username", key="register_username")
        new_email = st.text_input("Email", key="register_email")
        new_password = st.text_input("Password", type="password", key="register_password")
        confirm_password = st.text_input("Confirm Password", type="password", key="confirm_password")
        
        if st.button("Register", key="register_button"):
            if new_username and new_email and new_password:
                if new_password != confirm_password:
                    st.error("Passwords do not match")
                else:
                    success, message = create_user(new_username, new_password, new_email)
                    if success:
                        st.success(message)
                        st.info("Please login with your new account")
                    else:
                        st.error(message)
            else:
                st.warning("Please fill in all fields")

# Render sidebar
def render_sidebar():
    st.sidebar.title("Cipher Cloud")
    
    # User info
    user_data = get_user_data(st.session_state.username)
    if user_data:
        st.sidebar.markdown(f"**Welcome, {st.session_state.username}!**")
        st.sidebar.markdown(f"**User Score:** {user_data.get('score', 0)}")
        
        # Last login
        last_login = user_data.get("last_login", "Never")
        if last_login != "Never":
            last_login = datetime.fromisoformat(last_login).strftime("%Y-%m-%d %H:%M")
        st.sidebar.markdown(f"**Last Login:** {last_login}")
        
        # File stats
        file_count = len(user_data.get("files", []))
        shared_count = len(user_data.get("shared_files", []))
        st.sidebar.markdown(f"**Files:** {file_count}")
        st.sidebar.markdown(f"**Shared Files:** {shared_count}")
    
    # Navigation
    st.sidebar.markdown("---")
    st.sidebar.markdown("## Navigation")
    
    # Logout button
    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.username = None
        st.rerun()

# Render dashboard
def render_dashboard():
    st.title("Dashboard")
    
    user_data = get_user_data(st.session_state.username)
    if not user_data:
        st.warning("Could not load user data")
        return
    
    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Files", len(user_data.get("files", [])))
    
    with col2:
        st.metric("Shared Files", len(user_data.get("shared_files", [])))
    
    with col3:
        st.metric("User Score", user_data.get("score", 0))
    
    with col4:
        # Calculate activity level based on access history
        activity_count = len(user_data.get("access_history", []))
        activity_level = "Low"
        if activity_count > 50:
            activity_level = "High"
        elif activity_count > 20:
            activity_level = "Medium"
        st.metric("Activity Level", activity_level)
    
    # Recent activity
    st.subheader("Recent Activity")
    
    access_history = user_data.get("access_history", [])
    if access_history:
        # Get the 5 most recent activities
        recent_activities = sorted(
            access_history, 
            key=lambda x: x.get("timestamp", ""), 
            reverse=True
        )[:5]
        
        # Create a DataFrame for display
        activities_df = pd.DataFrame([
            {
                "Action": activity.get("type", ""),
                "File": activity.get("file_name", "N/A"),
                "Timestamp": datetime.fromisoformat(activity.get("timestamp", "")).strftime("%Y-%m-%d %H:%M")
            }
            for activity in recent_activities
        ])
        
        st.dataframe(activities_df, use_container_width=True)
    else:
        st.info("No recent activity")
    
    # File type distribution
    st.subheader("File Type Distribution")
    
    files = user_data.get("files", [])
    if files:
        # Extract file extensions
        extensions = [os.path.splitext(file.get("file_name", ""))[1].lower() for file in files]
        
        # Count occurrences
        extension_counts = {}
        for ext in extensions:
            if ext:
                extension_counts[ext] = extension_counts.get(ext, 0) + 1
            else:
                extension_counts["No extension"] = extension_counts.get("No extension", 0) + 1
        
        # Create pie chart
        fig = px.pie(
            values=list(extension_counts.values()),
            names=list(extension_counts.keys()),
            title="File Types",
            color_discrete_sequence=px.colors.qualitative.Pastel
        )
        fig.update_traces(textposition='inside', textinfo='percent+label')
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No files to analyze")

# Render file upload
def render_file_upload():
    st.subheader("Upload File")
    
    uploaded_file = st.file_uploader("Choose a file", key="file_uploader")
    
    if uploaded_file is not None:
        # Read file data
        file_data = uploaded_file.read()
        file_name = uploaded_file.name
        file_type = os.path.splitext(file_name)[1].lower()
        
        # Determine encryption method
        encryption_method, reason = determine_encryption_method(file_data, file_type)
        
        # Display encryption method
        st.info(f"Selected encryption method: **{encryption_method}**")
        st.caption(f"Reason: {reason}")
        
        # Encrypt button
        if st.button("Encrypt and Upload"):
            with st.spinner("Encrypting and uploading file..."):
                # Generate encryption key
                key = generate_key(st.session_state.entropy_pool)
                
                # Encrypt file
                encrypted_data, encryption_key = encrypt_file(file_data, encryption_method, key)
                
                # Save file
                file_id, file_metadata = save_file(
                    encrypted_data, file_name, st.session_state.username,
                    encryption_method, encryption_key
                )
                
                # Add file to user
                from modules.user_management import add_file_to_user
                add_file_to_user(
                    st.session_state.username, file_id,
                    file_name, encryption_method
                )
                
                # Update user score
                update_user_score(st.session_state.username, "upload")
                
                st.success(f"File '{file_name}' encrypted and uploaded successfully!")
                
                # Show encryption details
                st.json({
                    "file_id": file_id,
                    "file_name": file_name,
                    "encryption_method": encryption_method,
                    "size": len(file_data),
                    "encrypted_size": len(encrypted_data),
                    "uploaded_at": datetime.now().isoformat()
                })

# Render file list
def render_file_list():
    st.subheader("Your Files")
    
    # Get user files
    files = get_user_files(st.session_state.username)
    
    if not files:
        st.info("You don't have any files yet")
        return
    
    # Filter options
    filter_col1, filter_col2 = st.columns([1, 2])
    
    with filter_col1:
        filter_option = st.selectbox(
            "Filter by",
            ["All", "Images", "Documents", "Text", "Other"]
        )
    
    with filter_col2:
        sort_option = st.selectbox(
            "Sort by",
            ["Name", "Date (newest)", "Date (oldest)", "Size"]
        )
    
    # Apply filters
    filtered_files = files
    
    if filter_option == "Images":
        filtered_files = [f for f in files if os.path.splitext(f["file_name"])[1].lower() in ['.jpg', '.jpeg', '.png', '.gif']]
    elif filter_option == "Documents":
        filtered_files = [f for f in files if os.path.splitext(f["file_name"])[1].lower() in ['.pdf', '.docx', '.doc', '.pptx', '.xlsx']]
    elif filter_option == "Text":
        filtered_files = [f for f in files if os.path.splitext(f["file_name"])[1].lower() in ['.txt', '.csv', '.json', '.xml']]
    elif filter_option == "Other":
        filtered_files = [f for f in files if os.path.splitext(f["file_name"])[1].lower() not in [
            '.jpg', '.jpeg', '.png', '.gif', '.pdf', '.docx', '.doc', '.pptx', '.xlsx', '.txt', '.csv', '.json', '.xml'
        ]]
    
    # Apply sorting
    if sort_option == "Name":
        filtered_files = sorted(filtered_files, key=lambda x: x["file_name"])
    elif sort_option == "Date (newest)":
        filtered_files = sorted(filtered_files, key=lambda x: x.get("uploaded_at", ""), reverse=True)
    elif sort_option == "Date (oldest)":
        filtered_files = sorted(filtered_files, key=lambda x: x.get("uploaded_at", ""))
    elif sort_option == "Size":
        filtered_files = sorted(filtered_files, key=lambda x: x.get("size", 0), reverse=True)
    
    # Display files
    for file in filtered_files:
        col1, col2, col3 = st.columns([3, 1, 1])
        
        with col1:
            if st.button(f"{file['file_name']}", key=f"file_{file['file_id']}"):
                st.session_state.current_file = file["file_id"]
                update_file_access(file["file_id"], st.session_state.username, "view")
        
        with col2:
            st.caption(f"Encryption: {file.get('encryption_method', 'Unknown')}")
        
        with col3:
            if file.get("owner") == st.session_state.username:
                st.caption("Owner: You")
            else:
                st.caption(f"Shared by: {file.get('owner', 'Unknown')}")

# Render file preview
def render_file_preview():
    st.subheader("File Preview")
    
    file_id = st.session_state.current_file
    file_metadata = get_file_info(file_id)
    
    if not file_metadata:
        st.warning("File not found")
        return
    
    # Display file info
    st.markdown(f"**File:** {file_metadata['file_name']}")
    st.markdown(f"**Owner:** {file_metadata['owner']}")
    st.markdown(f"**Encryption:** {file_metadata['encryption_method']}")
    
    # Get encrypted file data
    encrypted_data = get_file_data(file_id)
    if not encrypted_data:
        st.warning("File data not found")
        return
    
    # Get encryption key
    encryption_key = get_encryption_key(file_id)
    if not encryption_key:
        st.warning("Encryption key not found")
        return
    
    # Password for decryption
    password = st.text_input("Enter password to decrypt", type="password", key=f"decrypt_password_{file_id}")
    
    if st.button("Decrypt and Preview", key=f"decrypt_button_{file_id}"):
        if not password:
            st.warning("Please enter a password")
            return
        
        # Simple password verification (in a real app, this would be more secure)
        if hashlib.sha256(password.encode()).hexdigest()[:8] != hashlib.sha256(st.session_state.username.encode()).hexdigest()[:8]:
            st.error("Incorrect password")
            return
        
        with st.spinner("Decrypting file..."):
            # Decrypt file
            decrypted_data = decrypt_file(
                encrypted_data, 
                file_metadata["encryption_method"],
                encryption_key
            )
            
            if decrypted_data is None:
                st.error("Failed to decrypt file")
                return
            
            # Verify file integrity
            if not verify_file_integrity(file_id, decrypted_data):
                st.warning("File integrity check done! ")
            
            # Preview based on file type
            file_type = os.path.splitext(file_metadata["file_name"])[1].lower()
            
            if file_type in ['.jpg', '.jpeg', '.png', '.gif']:
                # Image preview
                try:
                    image = Image.open(io.BytesIO(decrypted_data))
                    st.image(image, caption=file_metadata["file_name"])
                except Exception as e:
                    st.error(f"Failed to display image: {e}")
            
            elif file_type in ['.txt', '.csv', '.json', '.xml', '.py', '.html', '.css', '.js']:
                # Text preview
                try:
                    text_content = decrypted_data.decode('utf-8')
                    st.text_area("File Content", text_content, height=300)
                except UnicodeDecodeError:
                    st.error("Cannot display binary file as text")
            
            elif file_type in ['.pdf', '.docx', '.doc', '.pptx', '.xlsx']:
                # Document download
                st.warning("Preview available for this file type")
                
                # Provide download button
                st.download_button(
                    label="Download Decrypted File",
                    data=decrypted_data,
                    file_name=file_metadata["file_name"],
                    mime="application/octet-stream"
                )
            
            else:
                # Binary file download
                st.warning("Preview available for this file type")
                
                # Provide download button
                st.download_button(
                    label="Download Decrypted File",
                    data=decrypted_data,
                    file_name=file_metadata["file_name"],
                    mime="application/octet-stream"
                )

# Render encryption details
def render_encryption_details():
    st.subheader("Encryption Details")
    
    file_id = st.session_state.current_file
    file_metadata = get_file_info(file_id)
    
    if not file_metadata:
        return
    
    # Create tabs for different details
    details_tab, access_tab, integrity_tab = st.tabs(["Encryption", "Access Logs", "Integrity"])
    
    with details_tab:
        # Display encryption method details
        method = file_metadata.get("encryption_method", "Unknown")
        
        if method == "AES-256":
            st.markdown("""
            ### AES-256 Encryption
            
            **Algorithm:** Advanced Encryption Standard with 256-bit key
            
            **Features:**
            - Symmetric encryption (same key for encryption and decryption)
            - Fast and efficient for all file sizes
            - Widely used and trusted encryption standard
            
            **Security Level:** High
            """)
        
        elif method == "RSA-2048":
            st.markdown("""
            ### RSA-2048 Encryption
            
            **Algorithm:** Rivest-Shamir-Adleman with 2048-bit key
            
            **Features:**
            - Asymmetric encryption (public/private key pair)
            - Slower than symmetric encryption
            - Excellent for small, sensitive data
            
            **Security Level:** Very High
            """)
        
        elif method == "AES-256-GCM":
            st.markdown("""
            ### AES-256-GCM Encryption
            
            **Algorithm:** AES with Galois/Counter Mode
            
            **Features:**
            - Authenticated encryption with associated data (AEAD)
            - Provides both confidentiality and integrity
            - Ideal for media files where integrity is important
            
            **Security Level:** Very High
            """)
        
        elif method == "Hybrid (RSA+AES)":
            st.markdown("""
            ### Hybrid Encryption (RSA+AES)
            
            **Algorithm:** RSA-2048 + AES-256
            
            **Features:**
            - Combines strengths of both symmetric and asymmetric encryption
            - AES key is encrypted with RSA
            - Data is encrypted with AES
            - Excellent balance of security and performance
            
            **Security Level:** Extremely High
            """)
        
        elif method == "Quantum-Resistant":
            st.markdown("""
            ### Quantum-Resistant Encryption (Simulated)
            
            **Algorithm:** Simulated post-quantum cryptography
            
            **Features:**
            - Designed to resist attacks from quantum computers
            - Uses larger key sizes and different mathematical problems
            - Future-proof against quantum computing threats
            
            **Security Level:** Cutting-Edge
            """)
    
    with access_tab:
        # Display access logs
        access_logs = get_file_access_logs(file_id)
        
        if access_logs:
            # Create a DataFrame for display
            logs_df = pd.DataFrame([
                {
                    "Action": log.get("action", ""),
                    "User": log.get("user", ""),
                    "Timestamp": datetime.fromisoformat(log.get("timestamp", "")).strftime("%Y-%m-%d %H:%M"),
                    "Details": log.get("shared_with", "") if "shared_with" in log else ""
                }
                for log in access_logs
            ])
            
            st.dataframe(logs_df, use_container_width=True)
        else:
            st.info("No access logs available")
    
    with integrity_tab:
        # Display integrity information
        st.markdown("""
        ### File Integrity Protection
        
        This file is protected by a Merkle Tree hash verification system.
        
        **How it works:**
        1. The file is divided into small chunks
        2. Each chunk is hashed using SHA-256
        3. Hashes are paired and combined until a single root hash is created
        4. The root hash is stored with the file metadata
        5. When the file is decrypted, a new Merkle Tree is created and compared with the original
        
        This ensures that any tampering with the encrypted file will be detected.
        """)
        
        # Display Merkle root
        if "merkle_root" in file_metadata:
            st.code(file_metadata["merkle_root"], language="text")

# Render sharing options
def render_sharing_options():
    st.subheader("Share File")
    
    file_id = st.session_state.current_file
    file_metadata = get_file_info(file_id)
    
    if not file_metadata:
        return
    
    # Check if user is the owner
    if file_metadata["owner"] != st.session_state.username:
        st.warning("You can only share files that you own")
        return
    
    # Display current shares
    st.markdown("### Current Shares")
    
    shared_with = file_metadata.get("shared_with", [])
    if shared_with:
        for share in shared_with:
            col1, col2, col3 = st.columns([2, 1, 1])
            
            with col1:
                st.markdown(f"**{share['username']}**")
            
            with col2:
                st.caption(f"Permission: {share['permission']}")
            
            with col3:
                if st.button("Revoke", key=f"revoke_{file_id}_{share['username']}"):
                    # Remove share
                    file_metadata["shared_with"] = [
                        s for s in file_metadata["shared_with"] 
                        if s["username"] != share["username"]
                    ]
                    
                    # Save updated metadata
                    import os
                    metadata_path = os.path.join("data/files", f"{file_id}.json")
                    with open(metadata_path, 'w') as f:
                        import json
                        json.dump(file_metadata, f, indent=4)
                    
                    st.success(f"Access revoked for {share['username']}")
                    st.rerun()
    else:
        st.info("This file is not shared with anyone")
    
    # Share with new user
    st.markdown("### Share with User")
    
    # Method 1: Direct sharing
    col1, col2 = st.columns(2)
    
    with col1:
        target_username = st.text_input("Username", key=f"share_username_{file_id}")
    
    with col2:
        permission = st.selectbox(
            "Permission",
            ["read", "write", "admin"],
            key=f"share_permission_{file_id}"
        )
    
    if st.button("Share", key=f"share_button_{file_id}"):
        if target_username:
            success, message = share_file(
                file_id, st.session_state.username,
                target_username, permission
            )
            
            if success:
                st.success(message)
                # Update user score
                update_user_score(st.session_state.username, "share")
            else:
                st.error(message)
        else:
            st.warning("Please enter a username")
    
    # Method 2: Natural language command
    st.markdown("### Natural Language Sharing")
    st.caption("Example: 'Give John read access' or 'Allow Mary to edit this file'")
    
    nl_command = st.text_input("Enter sharing command", key=f"nl_command_{file_id}")
    
    if st.button("Process", key=f"nl_process_{file_id}"):
        if nl_command:
            success, message = parse_permission_command(
                nl_command, file_id, st.session_state.username
            )
            
            if success:
                st.success(message)
                # Update user score
                update_user_score(st.session_state.username, "share")
            else:
                st.error(message)
        else:
            st.warning("Please enter a command")
    
    # Method 3: Generate shareable link
    st.markdown("### Generate Shareable Link")
    
    if st.button("Generate Link", key=f"generate_link_{file_id}"):
        # Generate a simulated shareable link
        link = f"https://ciphercloud.example.com/share/{file_id}/{hashlib.sha256(file_id.encode()).hexdigest()[:16]}"
        
        st.code(link, language="text")
        
    
    # Method 4: Share via email
    st.markdown("### Share via Email")
    
    email = st.text_input("Email address", key=f"share_email_{file_id}")
    
    if st.button("Send Email", key=f"send_email_{file_id}"):
        if email:
            # Simulate sending email
            st.success(f"Sharing email sent to {email} (simulated)")
            
        else:
            st.warning("Please enter an email address")

# ... existing code ...

# Render user stats
def render_user_stats():
    st.subheader("User Statistics")
    
    # Get user data
    user_data = get_user_data(st.session_state.username)
    
    if not user_data:
        return
    
    # Access history analysis
    access_history = user_data.get("access_history", [])
    
    if access_history:
        # Count actions by type
        action_counts = {}
        for entry in access_history:
            action = entry.get("type", "unknown")
            action_counts[action] = action_counts.get(action, 0) + 1
        
        # Create bar chart
        fig = px.bar(
            x=list(action_counts.keys()),
            y=list(action_counts.values()),
            title="User Actions",
            labels={"x": "Action", "y": "Count"},
            color=list(action_counts.keys()),
            color_discrete_sequence=px.colors.qualitative.Pastel
        )
        st.plotly_chart(fig, use_container_width=True)
        
        # Activity timeline
        st.subheader("Activity Timeline")
        
        # Convert timestamps to datetime objects
        timeline_data = []
        for entry in access_history:
            if "timestamp" in entry:
                try:
                    timestamp = datetime.fromisoformat(entry["timestamp"])
                    timeline_data.append({
                        "date": timestamp.date(),
                        "action": entry.get("type", "unknown")
                    })
                except:
                    pass
        
        if timeline_data:
            # Create DataFrame
            timeline_df = pd.DataFrame(timeline_data)
            
            # Count actions by date
            timeline_counts = timeline_df.groupby(["date", "action"]).size().reset_index(name="count")
            
            # Create line chart
            fig = px.line(
                timeline_counts,
                x="date",
                y="count",
                color="action",
                title="Activity Over Time",
                labels={"date": "Date", "count": "Number of Actions"},
                markers=True
            )
            st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No activity data available")

# Render visualization dashboard
def render_visualization_dashboard():
    st.subheader("Analytics Dashboard")
    
    # Get user data
    user_data = get_user_data(st.session_state.username)
    
    if not user_data:
        return
    
    # Get all user files
    files = get_user_files(st.session_state.username)
    
    if not files:
        st.info("No files to analyze")
        return
    
    # Create tabs for different visualizations
    viz_tab1, viz_tab2, viz_tab3 = st.tabs(["Encryption Analysis", "File Activity", "Security Score"])
    
    with viz_tab1:
        # Count encryption methods
        encryption_counts = {}
        for file in files:
            method = file.get("encryption_method", "Unknown")
            encryption_counts[method] = encryption_counts.get(method, 0) + 1
        
        # Create donut chart
        fig = go.Figure(data=[go.Pie(
            labels=list(encryption_counts.keys()),
            values=list(encryption_counts.values()),
            hole=.4,
            marker_colors=px.colors.qualitative.Bold
        )])
        fig.update_layout(title_text="Encryption Methods Used")
        st.plotly_chart(fig, use_container_width=True)
        
        # Display encryption strength metrics
        st.markdown("### Encryption Strength Analysis")
        
        # Calculate average encryption strength (simulated)
        encryption_strength = {
            "AES-256": 85,
            "RSA-2048": 90,
            "AES-256-GCM": 88,
            "Hybrid (RSA+AES)": 95,
            "Quantum-Resistant": 99,
            "Unknown": 50
        }
        
        total_strength = sum(encryption_strength.get(file.get("encryption_method", "Unknown"), 0) for file in files)
        avg_strength = total_strength / len(files) if files else 0
        
        # Create gauge chart
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=avg_strength,
            title={"text": "Average Encryption Strength"},
            gauge={
                "axis": {"range": [0, 100]},
                "bar": {"color": "darkblue"},
                "steps": [
                    {"range": [0, 50], "color": "red"},
                    {"range": [50, 75], "color": "orange"},
                    {"range": [75, 90], "color": "yellow"},
                    {"range": [90, 100], "color": "green"}
                ],
                "threshold": {
                    "line": {"color": "black", "width": 4},
                    "thickness": 0.75,
                    "value": 90
                }
            }
        ))
        st.plotly_chart(fig, use_container_width=True)
    
    with viz_tab2:
        # File activity analysis
        st.markdown("### File Activity Analysis")
        
        # Prepare data
        file_data = []
        for file in files:
            file_id = file.get("file_id", "")
            if file_id:
                access_logs = get_file_access_logs(file_id)
                activity_count = len(access_logs)
                
                file_data.append({
                    "file_name": file.get("file_name", "Unknown"),
                    "activity_count": activity_count,
                    "last_accessed": file.get("last_accessed", "Never")
                })
        
        if file_data:
            # Sort by activity count
            file_data.sort(key=lambda x: x["activity_count"], reverse=True)
            
            # Create bar chart for most active files
            top_files = file_data[:5]  # Top 5 most active files
            
            fig = px.bar(
                top_files,
                x="file_name",
                y="activity_count",
                title="Most Active Files",
                labels={"file_name": "File", "activity_count": "Activity Count"},
                color="activity_count",
                color_continuous_scale=px.colors.sequential.Viridis
            )
            st.plotly_chart(fig, use_container_width=True)
            
            # Create table for recently accessed files
            st.markdown("### Recently Accessed Files")
            
            # Sort by last accessed time
            recent_files = sorted(
                [f for f in file_data if f["last_accessed"] != "Never"],
                key=lambda x: x["last_accessed"],
                reverse=True
            )[:5]  # Top 5 recently accessed
            
            if recent_files:
                recent_df = pd.DataFrame([
                    {
                        "File": file["file_name"],
                        "Last Accessed": datetime.fromisoformat(file["last_accessed"]).strftime("%Y-%m-%d %H:%M") 
                        if file["last_accessed"] != "Never" else "Never"
                    }
                    for file in recent_files
                ])
                
                st.dataframe(recent_df, use_container_width=True)
            else:
                st.info("No recent file access data")
        else:
            st.info("No file activity data available")
    
    with viz_tab3:
        # Security score analysis
        st.markdown("### Security Score Analysis")
        
        # Calculate security metrics (simulated)
        total_files = len(files)
        encrypted_files = sum(1 for file in files if file.get("encryption_method", "") != "")
        strong_encryption = sum(1 for file in files if file.get("encryption_method", "") in ["RSA-2048", "Hybrid (RSA+AES)", "Quantum-Resistant"])
        
        # Calculate percentages
        encryption_rate = (encrypted_files / total_files) * 100 if total_files > 0 else 0
        strong_rate = (strong_encryption / total_files) * 100 if total_files > 0 else 0
        
        # User score from user data
        user_score = user_data.get("score", 0)
        
        # Create metrics
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Encryption Coverage", f"{encryption_rate:.1f}%")
        
        with col2:
            st.metric("Strong Encryption Rate", f"{strong_rate:.1f}%")
        
        with col3:
            st.metric("User Security Score", user_score)
        
        # Create radar chart for security dimensions
        security_dimensions = {
            "Encryption Coverage": encryption_rate / 100,
            "Strong Encryption": strong_rate / 100,
            "User Score": min(user_score / 100, 1),  # Normalize to 0-1
            "File Protection": encrypted_files / max(total_files, 1),
            "Access Control": 0.8  # Simulated value
        }
        
        # Create radar chart
        categories = list(security_dimensions.keys())
        values = list(security_dimensions.values())
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatterpolar(
            r=values,
            theta=categories,
            fill='toself',
            name='Security Profile'
        ))
        
        fig.update_layout(
            polar=dict(
                radialaxis=dict(
                    visible=True,
                    range=[0, 1]
                )
            ),
            title="Security Profile"
        )
        
        st.plotly_chart(fig, use_container_width=True)