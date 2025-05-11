import streamlit as st
import os
import random
import string
import time
from datetime import datetime
import json

# Import custom modules
from modules.ui_components import (
    render_login_page, render_sidebar, render_dashboard,
    render_file_upload, render_file_list, render_file_preview,
    render_encryption_details, render_sharing_options,
    render_user_stats, render_visualization_dashboard
)
from modules.quantum_simulation import render_quantum_key_visualization
from modules.user_behavior import render_user_behavior_simulation

# Set page config
st.set_page_config(
    page_title="Cipher Cloud",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Add custom CSS
st.markdown("""
<style>
    .login-container {
        display: flex;
        justify-content: center;
        align-items: center;
        height: 30vh;
    }
    .login-box {
        text-align: center;
        padding: 2rem;
        border-radius: 10px;
    }
    .stButton button {
        width: 100%;
    }
    .file-item {
        padding: 1rem;
        border-radius: 5px;
        margin-bottom: 0.5rem;
    }
    .file-item:hover {
        background-color: #f0f2f6;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if "username" not in st.session_state:
    st.session_state.username = None

if "current_file" not in st.session_state:
    st.session_state.current_file = None

if "entropy_pool" not in st.session_state:
    # Generate random entropy pool for encryption
    st.session_state.entropy_pool = ''.join(random.choices(
        string.ascii_letters + string.digits, k=64
    ))

# Create data directories if they don't exist
os.makedirs("data/users", exist_ok=True)
os.makedirs("data/files", exist_ok=True)

# Main app logic
def main():
    # Check if user is logged in
    if not st.session_state.logged_in:
        render_login_page()
    else:
        # Render sidebar
        render_sidebar()
        
        # Main content
        tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
            "Dashboard", "Files", "Upload", "File Details", 
            "Analytics", "Advanced Features"
        ])
        
        with tab1:
            render_dashboard()
        
        with tab2:
            render_file_list()
        
        with tab3:
            render_file_upload()
        
        with tab4:
            if st.session_state.current_file:
                file_tab1, file_tab2, file_tab3 = st.tabs([
                    "Preview", "Encryption Details", "Sharing"
                ])
                
                with file_tab1:
                    render_file_preview()
                
                with file_tab2:
                    render_encryption_details()
                
                with file_tab3:
                    render_sharing_options()
            else:
                st.info("Select a file to view details")
        
        with tab5:
            analytics_tab1, analytics_tab2, analytics_tab3, analytics_tab4 = st.tabs([
                "User Stats", "Visualizations", "Quantum Simulation", "User Behavior"
            ])
            
            with analytics_tab1:
                render_user_stats()
            
            with analytics_tab2:
                render_visualization_dashboard()
                
            with analytics_tab3:
                render_quantum_key_visualization()
                
            with analytics_tab4:
                render_user_behavior_simulation()
                
        with tab6:
            st.subheader("Advanced Security Features")
            
            advanced_tab1, advanced_tab2 = st.tabs([
                "Quantum Key Exchange", "Security Audit"
            ])
            
            with advanced_tab1:
                st.markdown("""
                ### Quantum Key Exchange Simulation
                
                This feature simulates a quantum key exchange protocol similar to BB84.
                
                **How it works:**
                1. Alice generates random qubits in random bases
                2. Bob measures these qubits in randomly chosen bases
                3. Alice and Bob publicly compare their basis choices
                4. They keep only the results where they used the same basis
                5. A subset of these bits is used to check for eavesdropping
                6. The remaining bits form the secure key
                """)
                
                if st.button("Simulate Quantum Key Exchange"):
                    with st.spinner("Performing quantum key exchange simulation..."):
                        # Simulate progress
                        progress_bar = st.progress(0)
                        for i in range(100):
                            time.sleep(0.02)
                            progress_bar.progress(i + 1)
                        
                        # Display simulated results
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.markdown("**Alice's Qubits:**")
                            alice_bits = ''.join(random.choices('01', k=16))
                            alice_bases = ''.join(random.choices('XZ', k=16))
                            
                            alice_data = []
                            for i in range(16):
                                alice_data.append({
                                    "Bit": i,
                                    "Value": alice_bits[i],
                                    "Basis": alice_bases[i]
                                })
                            
                            st.dataframe(alice_data)
                        
                        with col2:
                            st.markdown("**Bob's Measurements:**")
                            bob_bases = ''.join(random.choices('XZ', k=16))
                            
                            bob_data = []
                            for i in range(16):
                                # If bases match, Bob gets the same bit
                                # Otherwise, 50% chance of getting the right bit
                                if bob_bases[i] == alice_bases[i]:
                                    bob_bit = alice_bits[i]
                                else:
                                    bob_bit = alice_bits[i] if random.random() > 0.5 else ('0' if alice_bits[i] == '1' else '1')
                                
                                bob_data.append({
                                    "Bit": i,
                                    "Value": bob_bit,
                                    "Basis": bob_bases[i]
                                })
                            
                            st.dataframe(bob_data)
                        
                        # Show matching bases
                        st.markdown("**Matching Bases:**")
                        
                        matching_data = []
                        final_key = ""
                        
                        for i in range(16):
                            match = alice_bases[i] == bob_bases[i]
                            same_bit = alice_bits[i] == bob_data[i]["Value"]
                            
                            if match:
                                final_key += alice_bits[i]
                            
                            matching_data.append({
                                "Bit": i,
                                "Alice's Basis": alice_bases[i],
                                "Bob's Basis": bob_bases[i],
                                "Match": "Yes" if match else "No",
                                "Same Value": "Yes" if same_bit else "No"
                            })
                        
                        st.dataframe(matching_data)
                        
                        # Show final key
                        st.markdown("**Final Quantum Key:**")
                        st.code(final_key, language="text")
                        
                        # Check for eavesdropping
                        error_rate = sum(1 for i in range(16) 
                                        if alice_bases[i] == bob_bases[i] and alice_bits[i] != bob_data[i]["Value"]) / len(final_key)
                        
                        if error_rate > 0:
                            st.warning(f"Possible eavesdropping detected! Error rate: {error_rate:.2%}")
                        else:
                            st.success("No eavesdropping detected. Secure key established.")
            
            with advanced_tab2:
                st.markdown("""
                ### Security Audit
                
                Run a comprehensive security audit on your account and files.
                """)
                
                if st.button("Run Security Audit"):
                    with st.spinner("Running security audit..."):
                        # Simulate progress
                        progress_bar = st.progress(0)
                        for i in range(100):
                            time.sleep(0.03)
                            progress_bar.progress(i + 1)
                        
                        # Display simulated results
                        st.success("Security audit completed!")
                        
                        # Generate random audit results
                        audit_score = random.randint(70, 95)
                        
                        st.metric("Overall Security Score", f"{audit_score}/100")
                        
                        # Security recommendations
                        st.markdown("### Security Recommendations")
                        
                        recommendations = [
                            "Enable two-factor authentication for additional security",
                            "Update your password to a stronger one",
                            "Consider using quantum-resistant encryption for sensitive files",
                            "Review file sharing permissions regularly",
                            "Enable automatic file integrity checks"
                        ]
                        
                        # Randomly select 2-3 recommendations
                        selected_recommendations = random.sample(recommendations, k=random.randint(2, 3))
                        
                        for i, rec in enumerate(selected_recommendations):
                            st.markdown(f"{i+1}. {rec}")
                        
                        # Audit details
                        st.markdown("### Audit Details")
                        
                        audit_details = {
                            "Account Security": random.randint(70, 95),
                            "File Encryption": random.randint(75, 98),
                            "Access Controls": random.randint(65, 90),
                            "Sharing Practices": random.randint(60, 85),
                            "Data Integrity": random.randint(80, 95)
                        }
                        
                        # Create bar chart
                        st.bar_chart(audit_details)

# Run the app
if __name__ == "__main__":
    main()