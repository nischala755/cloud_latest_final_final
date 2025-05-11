import numpy as np
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import random
import math
import pandas as pd  # Add pandas import
from datetime import datetime

def bloch_sphere_coordinates(theta, phi):
    """Convert spherical coordinates to cartesian for Bloch sphere visualization"""
    x = math.sin(theta) * math.cos(phi)
    y = math.sin(theta) * math.sin(phi)
    z = math.cos(theta)
    return x, y, z

def simulate_qubit_state(num_qubits=4):
    """Simulate quantum states for visualization"""
    import cmath  # Import cmath module for complex number operations
    
    qubit_states = []
    for i in range(num_qubits):
        # Generate random angles for the Bloch sphere
        theta = random.uniform(0, math.pi)
        phi = random.uniform(0, 2 * math.pi)
        
        # Calculate the quantum state amplitudes
        alpha = math.cos(theta/2)
        # Use cmath.exp instead of math.exp for complex numbers
        beta = math.sin(theta/2) * cmath.exp(1j * phi)
        
        # Calculate Cartesian coordinates for Bloch sphere
        x, y, z = bloch_sphere_coordinates(theta, phi)
        
        # Calculate probabilities
        prob_0 = abs(alpha)**2
        prob_1 = abs(beta)**2
        
        qubit_states.append({
            'id': i,
            'theta': theta,
            'phi': phi,
            'alpha': alpha,
            'beta': beta,
            'x': x,
            'y': y,
            'z': z,
            'prob_0': prob_0,
            'prob_1': prob_1
        })
    
    return qubit_states

def generate_quantum_key(entropy_source, length=256):
    """Generate a simulated quantum key based on entropy source"""
    # Use entropy source to seed the random generator
    seed = hash(str(entropy_source)) % (2**32)
    np.random.seed(seed)
    
    # Generate random qubits (0 or 1)
    qubits = np.random.randint(0, 2, size=length)
    
    # Convert to binary string
    key = ''.join(str(bit) for bit in qubits)
    
    # Return the key and the qubit states
    return key, simulate_qubit_state(min(length, 8))  # Limit visualization to 8 qubits

def render_bloch_sphere(qubit_states):
    """Render a 3D Bloch sphere visualization of qubit states"""
    fig = go.Figure()
    
    # Add the Bloch sphere
    u = np.linspace(0, 2*np.pi, 100)
    v = np.linspace(0, np.pi, 100)
    x = np.outer(np.cos(u), np.sin(v))
    y = np.outer(np.sin(u), np.sin(v))
    z = np.outer(np.ones(np.size(u)), np.cos(v))
    
    fig.add_trace(go.Surface(x=x, y=y, z=z, opacity=0.3, colorscale='Blues', showscale=False))
    
    # Add the axes
    axis_length = 1.3
    axes = np.array([
        [0, 0, 0, axis_length, 0, 0],  # x-axis
        [0, 0, 0, 0, axis_length, 0],  # y-axis
        [0, 0, 0, 0, 0, axis_length]   # z-axis
    ])
    
    fig.add_trace(go.Scatter3d(x=axes[0, [0, 3]], y=axes[0, [1, 4]], z=axes[0, [2, 5]], 
                              mode='lines', line=dict(color='red', width=4), name='X'))
    fig.add_trace(go.Scatter3d(x=axes[1, [0, 3]], y=axes[1, [1, 4]], z=axes[1, [2, 5]], 
                              mode='lines', line=dict(color='green', width=4), name='Y'))
    fig.add_trace(go.Scatter3d(x=axes[2, [0, 3]], y=axes[2, [1, 4]], z=axes[2, [2, 5]], 
                              mode='lines', line=dict(color='blue', width=4), name='Z'))
    
    # Add the qubit states
    for qubit in qubit_states:
        fig.add_trace(go.Scatter3d(
            x=[0, qubit['x']], 
            y=[0, qubit['y']], 
            z=[0, qubit['z']],
            mode='lines+markers',
            line=dict(color=f'rgba({random.randint(100, 255)}, {random.randint(100, 255)}, {random.randint(100, 255)}, 0.8)', width=3),
            marker=dict(size=[0, 6]),
            name=f'Qubit {qubit["id"]}'
        ))
    
    # Update layout
    fig.update_layout(
        title="Qubit States on Bloch Sphere",
        scene=dict(
            xaxis_title="X",
            yaxis_title="Y",
            zaxis_title="Z",
            aspectmode='cube'
        ),
        margin=dict(l=0, r=0, b=0, t=30),
        legend=dict(x=0, y=1)
    )
    
    return fig

def render_quantum_key_visualization():
    """Render the quantum key visualization dashboard"""
    st.subheader("Quantum Key Simulation")
    
    st.markdown("""
    ### Quantum Key Generation
    
    This simulation demonstrates how quantum computing principles can be used for cryptographic key generation.
    The visualization shows:
    
    1. **Qubit States**: Represented on the Bloch sphere
    2. **Probability Distribution**: The likelihood of measuring each qubit as 0 or 1
    3. **Generated Key**: A simulated quantum-secure key
    """)
    
    # Generate a quantum key using session entropy
    key_length = st.slider("Key Length (bits)", min_value=64, max_value=512, value=256, step=64)
    
    if st.button("Generate New Quantum Key"):
        # Use current time and entropy pool as seed
        entropy = str(datetime.now()) + str(st.session_state.entropy_pool)
        
        # Generate key and qubit states
        key, qubit_states = generate_quantum_key(entropy, key_length)
        
        # Store in session state
        st.session_state.quantum_key = key
        st.session_state.qubit_states = qubit_states
    
    # Display visualization if key exists
    if hasattr(st.session_state, 'quantum_key') and hasattr(st.session_state, 'qubit_states'):
        col1, col2 = st.columns([2, 1])
        
        with col1:
            # Display Bloch sphere
            fig = render_bloch_sphere(st.session_state.qubit_states)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Display qubit probabilities
            prob_data = []
            for q in st.session_state.qubit_states:
                prob_data.append({'Qubit': f'Q{q["id"]}', 'State': '|0⟩', 'Probability': q['prob_0']})
                prob_data.append({'Qubit': f'Q{q["id"]}', 'State': '|1⟩', 'Probability': q['prob_1']})
            
            prob_df = pd.DataFrame(prob_data)
            fig = px.bar(
                prob_df, 
                x='Qubit', 
                y='Probability', 
                color='State',
                title='Qubit State Probabilities',
                color_discrete_map={'|0⟩': 'blue', '|1⟩': 'red'}
            )
            st.plotly_chart(fig, use_container_width=True)
        
        # Display the generated key
        st.subheader("Generated Quantum Key")
        key_display = st.session_state.quantum_key[:64] + "..." if len(st.session_state.quantum_key) > 64 else st.session_state.quantum_key
        st.code(key_display, language="text")
        
        # Key strength metrics
        entropy_estimate = sum(-p * math.log2(p) if p > 0 else 0 
                              for p in [st.session_state.qubit_states[i % len(st.session_state.qubit_states)]['prob_0'] 
                                       for i in range(key_length)])
        
        st.metric("Estimated Entropy", f"{entropy_estimate:.2f} bits")
        st.progress(min(entropy_estimate / key_length, 1.0))
        
        # Security level assessment
        security_level = "Low"
        if entropy_estimate / key_length > 0.9:
            security_level = "Very High"
        elif entropy_estimate / key_length > 0.8:
            security_level = "High"
        elif entropy_estimate / key_length > 0.6:
            security_level = "Medium"
            
        st.info(f"Security Level: {security_level}")