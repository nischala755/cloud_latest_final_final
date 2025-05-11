import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import random
import json
import os
import math

# User behavior profiles
USER_PROFILES = {
    "Regular User": {
        "login_frequency": 0.8,  # Probability of logging in on a given day
        "upload_rate": 0.4,      # Probability of uploading a file when logged in
        "download_rate": 0.6,    # Probability of downloading a file when logged in
        "share_rate": 0.2,       # Probability of sharing a file when logged in
        "preferred_encryption": ["AES-256", "RSA-2048"],
        "risk_score": 0.2        # Low risk score
    },
    "Power User": {
        "login_frequency": 0.95,
        "upload_rate": 0.7,
        "download_rate": 0.8,
        "share_rate": 0.5,
        "preferred_encryption": ["Hybrid (RSA+AES)", "AES-256-GCM"],
        "risk_score": 0.1        # Very low risk score
    },
    "Occasional User": {
        "login_frequency": 0.3,
        "upload_rate": 0.2,
        "download_rate": 0.4,
        "share_rate": 0.1,
        "preferred_encryption": ["AES-256"],
        "risk_score": 0.4        # Medium risk score
    },
    "Security Conscious": {
        "login_frequency": 0.7,
        "upload_rate": 0.5,
        "download_rate": 0.6,
        "share_rate": 0.3,
        "preferred_encryption": ["Quantum-Resistant", "Hybrid (RSA+AES)"],
        "risk_score": 0.05       # Extremely low risk score
    },
    "Suspicious User": {
        "login_frequency": 0.6,
        "upload_rate": 0.8,
        "download_rate": 0.9,
        "share_rate": 0.7,
        "preferred_encryption": ["AES-256"],
        "risk_score": 0.8        # High risk score
    }
}

# File types for simulation
FILE_TYPES = {
    "Document": [".docx", ".pdf", ".txt", ".xlsx"],
    "Image": [".jpg", ".png", ".gif"],
    "Code": [".py", ".js", ".html", ".css"],
    "Data": [".csv", ".json", ".xml"],
    "Archive": [".zip", ".rar", ".tar.gz"]
}

def generate_simulated_users(num_users=20):
    """Generate simulated users with different profiles"""
    users = []
    
    # Distribute users across profiles
    profile_distribution = {
        "Regular User": 0.4,
        "Power User": 0.2,
        "Occasional User": 0.25,
        "Security Conscious": 0.1,
        "Suspicious User": 0.05
    }
    
    for i in range(num_users):
        # Select profile based on distribution
        profile = random.choices(
            list(profile_distribution.keys()),
            weights=list(profile_distribution.values()),
            k=1
        )[0]
        
        # Generate username
        username = f"user_{i+1}"
        
        # Create user
        user = {
            "username": username,
            "profile": profile,
            "behavior": USER_PROFILES[profile],
            "created_at": (datetime.now() - timedelta(days=random.randint(1, 365))).isoformat(),
            "last_login": (datetime.now() - timedelta(days=random.randint(0, 30))).isoformat(),
            "login_count": random.randint(1, 100),
            "file_count": random.randint(0, 50),
            "share_count": random.randint(0, 20),
            "risk_score": USER_PROFILES[profile]["risk_score"] * (0.8 + 0.4 * random.random())  # Add some randomness
        }
        
        users.append(user)
    
    return users

def generate_activity_timeline(users, days=30):
    """Generate a simulated activity timeline for users"""
    activities = []
    
    end_date = datetime.now()
    start_date = end_date - timedelta(days=days)
    
    for user in users:
        profile = user["behavior"]
        current_date = start_date
        
        while current_date <= end_date:
            # Check if user logs in on this day
            if random.random() < profile["login_frequency"]:
                # Add login activity
                login_time = current_date.replace(
                    hour=random.randint(8, 18),
                    minute=random.randint(0, 59)
                )
                
                activities.append({
                    "username": user["username"],
                    "profile": user["profile"],
                    "action": "login",
                    "timestamp": login_time.isoformat(),
                    "details": "User logged in"
                })
                
                # Check for file upload
                if random.random() < profile["upload_rate"]:
                    # Generate random file details
                    file_type = random.choice(list(FILE_TYPES.keys()))
                    file_extension = random.choice(FILE_TYPES[file_type])
                    file_name = f"file_{random.randint(1000, 9999)}{file_extension}"
                    
                    # Select encryption method
                    encryption = random.choice(profile["preferred_encryption"])
                    
                    upload_time = login_time + timedelta(minutes=random.randint(5, 120))
                    
                    activities.append({
                        "username": user["username"],
                        "profile": user["profile"],
                        "action": "upload",
                        "timestamp": upload_time.isoformat(),
                        "details": f"Uploaded {file_name} using {encryption} encryption"
                    })
                
                # Check for file download
                if random.random() < profile["download_rate"]:
                    download_time = login_time + timedelta(minutes=random.randint(5, 180))
                    
                    activities.append({
                        "username": user["username"],
                        "profile": user["profile"],
                        "action": "download",
                        "timestamp": download_time.isoformat(),
                        "details": "Downloaded a file"
                    })
                
                # Check for file sharing
                if random.random() < profile["share_rate"]:
                    share_time = login_time + timedelta(minutes=random.randint(10, 200))
                    
                    # Select a random user to share with
                    target_user = random.choice([u["username"] for u in users if u["username"] != user["username"]])
                    
                    activities.append({
                        "username": user["username"],
                        "profile": user["profile"],
                        "action": "share",
                        "timestamp": share_time.isoformat(),
                        "details": f"Shared a file with {target_user}"
                    })
                
                # Add logout activity
                session_duration = random.randint(15, 240)  # 15 min to 4 hours
                logout_time = login_time + timedelta(minutes=session_duration)
                
                if logout_time.date() == current_date.date():  # Only add if logout is on the same day
                    activities.append({
                        "username": user["username"],
                        "profile": user["profile"],
                        "action": "logout",
                        "timestamp": logout_time.isoformat(),
                        "details": f"Session duration: {session_duration} minutes"
                    })
            
            current_date += timedelta(days=1)
    
    # Sort activities by timestamp
    activities.sort(key=lambda x: x["timestamp"])
    
    return activities

def detect_anomalies(activities, users):
    """Detect anomalous behavior in user activities"""
    anomalies = []
    
    # Group activities by user
    user_activities = {}
    for activity in activities:
        username = activity["username"]
        if username not in user_activities:
            user_activities[username] = []
        user_activities[username].append(activity)
    
    # Analyze each user's activities
    for username, user_acts in user_activities.items():
        # Get user profile
        user = next((u for u in users if u["username"] == username), None)
        if not user:
            continue
        
        # Sort activities by timestamp
        user_acts.sort(key=lambda x: x["timestamp"])
        
        # Check for unusual login times
        for i, activity in enumerate(user_acts):
            if activity["action"] == "login":
                login_time = datetime.fromisoformat(activity["timestamp"])
                
                # Check for late night logins (suspicious)
                if login_time.hour >= 23 or login_time.hour <= 5:
                    anomalies.append({
                        "username": username,
                        "timestamp": activity["timestamp"],
                        "type": "Unusual login time",
                        "severity": "Medium",
                        "details": f"Login at {login_time.strftime('%H:%M')}",
                        "risk_score": 0.6
                    })
            
            # Check for rapid succession of activities
            if i > 0:
                prev_time = datetime.fromisoformat(user_acts[i-1]["timestamp"])
                curr_time = datetime.fromisoformat(activity["timestamp"])
                time_diff = (curr_time - prev_time).total_seconds()
                
                # If activities are less than 5 seconds apart and from different actions
                if time_diff < 5 and activity["action"] != user_acts[i-1]["action"]:
                    anomalies.append({
                        "username": username,
                        "timestamp": activity["timestamp"],
                        "type": "Rapid activity succession",
                        "severity": "High",
                        "details": f"{user_acts[i-1]['action']} followed by {activity['action']} in {time_diff:.1f} seconds",
                        "risk_score": 0.8
                    })
        
        # Check for excessive file downloads
        download_count = sum(1 for act in user_acts if act["action"] == "download")
        expected_downloads = len(user_acts) * user["behavior"]["download_rate"]
        
        if download_count > expected_downloads * 1.5 and download_count > 5:
            anomalies.append({
                "username": username,
                "timestamp": datetime.now().isoformat(),
                "type": "Excessive downloads",
                "severity": "Medium",
                "details": f"{download_count} downloads (expected ~{expected_downloads:.1f})",
                "risk_score": 0.5
            })
        
        # Check for unusual sharing patterns
        share_count = sum(1 for act in user_acts if act["action"] == "share")
        expected_shares = len(user_acts) * user["behavior"]["share_rate"]
        
        if share_count > expected_shares * 2 and share_count > 3:
            anomalies.append({
                "username": username,
                "timestamp": datetime.now().isoformat(),
                "type": "Unusual sharing pattern",
                "severity": "High",
                "details": f"{share_count} shares (expected ~{expected_shares:.1f})",
                "risk_score": 0.7
            })
    
    # Sort anomalies by risk score (highest first)
    anomalies.sort(key=lambda x: x["risk_score"], reverse=True)
    
    return anomalies

def render_user_behavior_simulation():
    """Render the user behavior simulation dashboard"""
    st.subheader("User Behavior Simulation")
    
    # Initialize simulation data if not already in session state
    if "simulated_users" not in st.session_state:
        num_users = 20
        st.session_state.simulated_users = generate_simulated_users(num_users)
        st.session_state.simulated_activities = generate_activity_timeline(st.session_state.simulated_users)
        st.session_state.detected_anomalies = detect_anomalies(
            st.session_state.simulated_activities, 
            st.session_state.simulated_users
        )
    
    # Create tabs for different views
    sim_tab1, sim_tab2, sim_tab3 = st.tabs(["User Profiles", "Activity Timeline", "Anomaly Detection"])
    
    with sim_tab1:
        st.markdown("### Simulated User Profiles")
        
        # Create a DataFrame for user profiles
        user_df = pd.DataFrame([
            {
                "Username": user["username"],
                "Profile": user["profile"],
                "Created": datetime.fromisoformat(user["created_at"]).strftime("%Y-%m-%d"),
                "Last Login": datetime.fromisoformat(user["last_login"]).strftime("%Y-%m-%d"),
                "Files": user["file_count"],
                "Shares": user["share_count"],
                "Risk Score": user["risk_score"]
            }
            for user in st.session_state.simulated_users
        ])
        
        # Display user table
        st.dataframe(user_df, use_container_width=True)
        
        # Create profile distribution chart
        profile_counts = user_df["Profile"].value_counts().reset_index()
        profile_counts.columns = ["Profile", "Count"]
        
        fig = px.pie(
            profile_counts,
            values="Count",
            names="Profile",
            title="User Profile Distribution",
            color_discrete_sequence=px.colors.qualitative.Bold
        )
        st.plotly_chart(fig, use_container_width=True)
        
        # Risk score distribution
        fig = px.histogram(
            user_df,
            x="Risk Score",
            color="Profile",
            title="Risk Score Distribution",
            nbins=20,
            opacity=0.7
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with sim_tab2:
        st.markdown("### Activity Timeline")
        
        # Create a DataFrame for activities
        activity_df = pd.DataFrame([
            {
                "Username": act["username"],
                "Profile": act["profile"],
                "Action": act["action"].capitalize(),
                "Timestamp": datetime.fromisoformat(act["timestamp"]).strftime("%Y-%m-%d %H:%M"),
                "Details": act["details"],
                "Date": datetime.fromisoformat(act["timestamp"]).date()
            }
            for act in st.session_state.simulated_activities
        ])
        
        # Filter options
        col1, col2 = st.columns(2)
        
        with col1:
            selected_profiles = st.multiselect(
                "Filter by Profile",
                options=sorted(activity_df["Profile"].unique()),
                default=sorted(activity_df["Profile"].unique())
            )
        
        with col2:
            selected_actions = st.multiselect(
                "Filter by Action",
                options=sorted(activity_df["Action"].unique()),
                default=sorted(activity_df["Action"].unique())
            )
        
        # Apply filters
        filtered_df = activity_df[
            activity_df["Profile"].isin(selected_profiles) &
            activity_df["Action"].isin(selected_actions)
        ]
        
        # Display activity table
        st.dataframe(filtered_df, use_container_width=True)
        
        # Activity timeline chart
        activity_counts = filtered_df.groupby(["Date", "Action"]).size().reset_index(name="Count")
        
        fig = px.line(
            activity_counts,
            x="Date",
            y="Count",
            color="Action",
            title="Activity Timeline",
            markers=True
        )
        st.plotly_chart(fig, use_container_width=True)
        
        # Activity distribution by profile
        profile_activity = filtered_df.groupby(["Profile", "Action"]).size().reset_index(name="Count")
        
        fig = px.bar(
            profile_activity,
            x="Profile",
            y="Count",
            color="Action",
            title="Activity Distribution by User Profile",
            barmode="group"
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with sim_tab3:
        st.markdown("### Anomaly Detection")
        
        # Display anomaly count
        anomaly_count = len(st.session_state.detected_anomalies)
        st.metric("Detected Anomalies", anomaly_count)
        
        if anomaly_count > 0:
            # Create a DataFrame for anomalies
            anomaly_df = pd.DataFrame([
                {
                    "Username": anomaly["username"],
                    "Type": anomaly["type"],
                    "Severity": anomaly["severity"],
                    "Details": anomaly["details"],
                    "Risk Score": anomaly["risk_score"],
                    "Timestamp": datetime.fromisoformat(anomaly["timestamp"]).strftime("%Y-%m-%d %H:%M")
                }
                for anomaly in st.session_state.detected_anomalies
            ])
            
            # Display anomaly table
            st.dataframe(anomaly_df, use_container_width=True)
            
            # Anomaly distribution by type
            type_counts = anomaly_df["Type"].value_counts().reset_index()
            type_counts.columns = ["Type", "Count"]
            
            fig = px.bar(
                type_counts,
                x="Type",
                y="Count",
                title="Anomaly Types",
                color="Type"
            )
            st.plotly_chart(fig, use_container_width=True)
            
            # Risk score distribution
            fig = px.box(
                anomaly_df,
                x="Severity",
                y="Risk Score",
                title="Risk Score by Severity",
                color="Severity",
                points="all"
            )
            st.plotly_chart(fig, use_container_width=True)
            
            # User risk map
            user_risk = {}
            for anomaly in st.session_state.detected_anomalies:
                username = anomaly["username"]
                if username not in user_risk:
                    user_risk[username] = 0
                user_risk[username] += anomaly["risk_score"]
            
            user_risk_df = pd.DataFrame([
                {"Username": username, "Risk Score": score}
                for username, score in user_risk.items()
            ])
            
            fig = px.bar(
                user_risk_df.sort_values("Risk Score", ascending=False),
                x="Username",
                y="Risk Score",
                title="User Risk Map",
                color="Risk Score",
                color_continuous_scale="Reds"
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No anomalies detected in the simulated data")
    
    # Add option to regenerate simulation
    if st.button("Regenerate Simulation"):
        num_users = 20
        st.session_state.simulated_users = generate_simulated_users(num_users)
        st.session_state.simulated_activities = generate_activity_timeline(st.session_state.simulated_users)
        st.session_state.detected_anomalies = detect_anomalies(
            st.session_state.simulated_activities, 
            st.session_state.simulated_users
        )
        st.experimental_rerun()