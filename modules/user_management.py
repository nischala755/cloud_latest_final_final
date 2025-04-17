import os
import json
import hashlib
import time
import uuid
from datetime import datetime

# User data directory
USER_DATA_DIR = 'data/users'

# Create a new user
def create_user(username, password, email):
    user_file = os.path.join(USER_DATA_DIR, f"{username}.json")
    
    # Check if user already exists
    if os.path.exists(user_file):
        return False, "Username already exists"
    
    # Hash the password
    salt = os.urandom(16).hex()
    password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    
    # Create user data
    user_data = {
        "username": username,
        "email": email,
        "password_hash": password_hash,
        "salt": salt,
        "created_at": datetime.now().isoformat(),
        "last_login": None,
        "score": 100,  # Initial score
        "files": [],
        "shared_files": [],
        "access_history": []
    }
    
    # Save user data
    with open(user_file, 'w') as f:
        json.dump(user_data, f, indent=4)
    
    return True, "User created successfully"

# Authenticate a user
def authenticate_user(username, password):
    user_file = os.path.join(USER_DATA_DIR, f"{username}.json")
    
    # Check if user exists
    if not os.path.exists(user_file):
        return False, "Invalid username or password"
    
    # Load user data
    with open(user_file, 'r') as f:
        user_data = json.load(f)
    
    # Verify password
    salt = user_data["salt"]
    password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    
    if password_hash != user_data["password_hash"]:
        return False, "Invalid username or password"
    
    # Update last login
    user_data["last_login"] = datetime.now().isoformat()
    
    # Add login to access history
    user_data["access_history"].append({
        "type": "login",
        "timestamp": datetime.now().isoformat(),
        "ip": "127.0.0.1"  # Simulated IP
    })
    
    # Save updated user data
    with open(user_file, 'w') as f:
        json.dump(user_data, f, indent=4)
    
    return True, "Login successful"

# Get user data
def get_user_data(username):
    user_file = os.path.join(USER_DATA_DIR, f"{username}.json")
    
    # Check if user exists
    if not os.path.exists(user_file):
        return None
    
    # Load user data
    with open(user_file, 'r') as f:
        user_data = json.load(f)
    
    return user_data

# Update user score
def update_user_score(username, action):
    user_data = get_user_data(username)
    
    if not user_data:
        return False
    
    # Update score based on action
    if action == "upload":
        user_data["score"] += 5
    elif action == "download":
        user_data["score"] += 2
    elif action == "share":
        user_data["score"] += 3
    elif action == "delete":
        user_data["score"] -= 1
    
    # Ensure score doesn't go below 0
    user_data["score"] = max(0, user_data["score"])
    
    # Save updated user data
    user_file = os.path.join(USER_DATA_DIR, f"{username}.json")
    with open(user_file, 'w') as f:
        json.dump(user_data, f, indent=4)
    
    return True

# Add file to user's files
def add_file_to_user(username, file_id, file_name, encryption_method):
    user_data = get_user_data(username)
    
    if not user_data:
        return False
    
    # Add file to user's files
    user_data["files"].append({
        "file_id": file_id,
        "file_name": file_name,
        "encryption_method": encryption_method,
        "uploaded_at": datetime.now().isoformat(),
        "last_accessed": datetime.now().isoformat()
    })
    
    # Add to access history
    user_data["access_history"].append({
        "type": "upload",
        "file_id": file_id,
        "file_name": file_name,
        "timestamp": datetime.now().isoformat()
    })
    
    # Update user score
    update_user_score(username, "upload")
    
    # Save updated user data
    user_file = os.path.join(USER_DATA_DIR, f"{username}.json")
    with open(user_file, 'w') as f:
        json.dump(user_data, f, indent=4)
    
    return True

# Add shared file to user
def add_shared_file_to_user(username, file_id, file_name, shared_by):
    user_data = get_user_data(username)
    
    if not user_data:
        return False
    
    # Add file to user's shared files
    user_data["shared_files"].append({
        "file_id": file_id,
        "file_name": file_name,
        "shared_by": shared_by,
        "shared_at": datetime.now().isoformat(),
        "last_accessed": None
    })
    
    # Add to access history
    user_data["access_history"].append({
        "type": "received_share",
        "file_id": file_id,
        "file_name": file_name,
        "shared_by": shared_by,
        "timestamp": datetime.now().isoformat()
    })
    
    # Save updated user data
    user_file = os.path.join(USER_DATA_DIR, f"{username}.json")
    with open(user_file, 'w') as f:
        json.dump(user_data, f, indent=4)
    
    return True

# Get all users
def get_all_users():
    users = []
    
    for filename in os.listdir(USER_DATA_DIR):
        if filename.endswith('.json'):
            username = filename[:-5]  # Remove .json extension
            user_data = get_user_data(username)
            
            if user_data:
                users.append({
                    "username": username,
                    "email": user_data.get("email", ""),
                    "score": user_data.get("score", 0),
                    "file_count": len(user_data.get("files", [])),
                    "last_login": user_data.get("last_login", "Never")
                })
    
    return users

# Record file access
def record_file_access(username, file_id, file_name, action):
    user_data = get_user_data(username)
    
    if not user_data:
        return False
    
    # Add to access history
    user_data["access_history"].append({
        "type": action,
        "file_id": file_id,
        "file_name": file_name,
        "timestamp": datetime.now().isoformat()
    })
    
    # Update last accessed for the file
    for file in user_data["files"]:
        if file["file_id"] == file_id:
            file["last_accessed"] = datetime.now().isoformat()
            break
    
    # For shared files
    for file in user_data["shared_files"]:
        if file["file_id"] == file_id:
            file["last_accessed"] = datetime.now().isoformat()
            break
    
    # Update user score based on action
    update_user_score(username, action)
    
    # Save updated user data
    user_file = os.path.join(USER_DATA_DIR, f"{username}.json")
    with open(user_file, 'w') as f:
        json.dump(user_data, f, indent=4)
    
    return True