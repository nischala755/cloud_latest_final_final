import os
import json
import hashlib
import base64
import uuid
import re
from datetime import datetime
import shutil

# File data directory
FILE_DATA_DIR = 'data/files'
KEYS_DIR = 'data/keys'
ACCESS_LOGS_DIR = 'data/access_logs'

# Save uploaded file
def save_file(file_data, file_name, username, encryption_method, encryption_key):
    # Generate a unique file ID
    file_id = str(uuid.uuid4())
    
    # Create file metadata
    file_metadata = {
        "file_id": file_id,
        "file_name": file_name,
        "original_name": file_name,
        "owner": username,
        "uploaded_at": datetime.now().isoformat(),
        "last_accessed": datetime.now().isoformat(),
        "encryption_method": encryption_method,
        "size": len(file_data),
        "shared_with": [],
        "merkle_root": create_merkle_tree(file_data)
    }
    
    # Save encrypted file
    file_path = os.path.join(FILE_DATA_DIR, f"{file_id}.bin")
    with open(file_path, 'wb') as f:
        f.write(file_data)
    
    # Save file metadata
    metadata_path = os.path.join(FILE_DATA_DIR, f"{file_id}.json")
    with open(metadata_path, 'w') as f:
        json.dump(file_metadata, f, indent=4)
    
    # Save encryption key
    key_path = os.path.join(KEYS_DIR, f"{file_id}.key")
    with open(key_path, 'wb') as f:
        if isinstance(encryption_key, bytes):
            f.write(encryption_key)
        else:
            f.write(encryption_key.encode())
    
    # Create access log
    access_log = {
        "file_id": file_id,
        "file_name": file_name,
        "logs": [
            {
                "action": "upload",
                "user": username,
                "timestamp": datetime.now().isoformat(),
                "ip": "127.0.0.1"  # Simulated IP
            }
        ]
    }
    
    # Save access log
    log_path = os.path.join(ACCESS_LOGS_DIR, f"{file_id}.json")
    with open(log_path, 'w') as f:
        json.dump(access_log, f, indent=4)
    
    return file_id, file_metadata

# Get file information
def get_file_info(file_id):
    metadata_path = os.path.join(FILE_DATA_DIR, f"{file_id}.json")
    
    if not os.path.exists(metadata_path):
        return None
    
    with open(metadata_path, 'r') as f:
        file_metadata = json.load(f)
    
    return file_metadata

# Get file data
def get_file_data(file_id):
    file_path = os.path.join(FILE_DATA_DIR, f"{file_id}.bin")
    
    if not os.path.exists(file_path):
        return None
    
    with open(file_path, 'rb') as f:
        file_data = f.read()
    
    return file_data

# Get encryption key
def get_encryption_key(file_id):
    key_path = os.path.join(KEYS_DIR, f"{file_id}.key")
    
    if not os.path.exists(key_path):
        return None
    
    with open(key_path, 'rb') as f:
        key_data = f.read()
    
    return key_data

# Get user files
def get_user_files(username):
    files = []
    
    for filename in os.listdir(FILE_DATA_DIR):
        if filename.endswith('.json'):
            with open(os.path.join(FILE_DATA_DIR, filename), 'r') as f:
                file_metadata = json.load(f)
            
            if file_metadata["owner"] == username:
                files.append(file_metadata)
            elif username in [share["username"] for share in file_metadata.get("shared_with", [])]:
                files.append(file_metadata)
    
    return files

# Share file with another user
def share_file(file_id, owner_username, target_username, permission="read"):
    file_metadata = get_file_info(file_id)
    
    if not file_metadata:
        return False, "File not found"
    
    if file_metadata["owner"] != owner_username:
        return False, "You don't have permission to share this file"
    
    # Check if already shared
    for share in file_metadata.get("shared_with", []):
        if share["username"] == target_username:
            return False, "File already shared with this user"
    
    # Add share information
    if "shared_with" not in file_metadata:
        file_metadata["shared_with"] = []
    
    file_metadata["shared_with"].append({
        "username": target_username,
        "permission": permission,
        "shared_at": datetime.now().isoformat()
    })
    
    # Save updated metadata
    metadata_path = os.path.join(FILE_DATA_DIR, f"{file_id}.json")
    with open(metadata_path, 'w') as f:
        json.dump(file_metadata, f, indent=4)
    
    # Update access log
    log_path = os.path.join(ACCESS_LOGS_DIR, f"{file_id}.json")
    
    if os.path.exists(log_path):
        with open(log_path, 'r') as f:
            access_log = json.load(f)
        
        access_log["logs"].append({
            "action": "share",
            "user": owner_username,
            "shared_with": target_username,
            "permission": permission,
            "timestamp": datetime.now().isoformat()
        })
        
        with open(log_path, 'w') as f:
            json.dump(access_log, f, indent=4)
    
    return True, "File shared successfully"

# Update file access
def update_file_access(file_id, username, action):
    file_metadata = get_file_info(file_id)
    
    if not file_metadata:
        return False
    
    # Update last accessed
    file_metadata["last_accessed"] = datetime.now().isoformat()
    
    # Save updated metadata
    metadata_path = os.path.join(FILE_DATA_DIR, f"{file_id}.json")
    with open(metadata_path, 'w') as f:
        json.dump(file_metadata, f, indent=4)
    
    # Update access log
    log_path = os.path.join(ACCESS_LOGS_DIR, f"{file_id}.json")
    
    if os.path.exists(log_path):
        with open(log_path, 'r') as f:
            access_log = json.load(f)
        
        access_log["logs"].append({
            "action": action,
            "user": username,
            "timestamp": datetime.now().isoformat(),
            "ip": "127.0.0.1"  # Simulated IP
        })
        
        with open(log_path, 'w') as f:
            json.dump(access_log, f, indent=4)
    
    return True

# Create Merkle Tree for file integrity
# ... existing code ...

# Create Merkle Tree for file integrity
def create_merkle_tree(data):
    # Split data into chunks
    chunk_size = 1024  # 1KB chunks
    chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
    
    # Calculate hash for each chunk
    hashes = [hashlib.sha256(chunk).hexdigest() for chunk in chunks]
    
    # Build the Merkle tree
    while len(hashes) > 1:
        if len(hashes) % 2 != 0:
            hashes.append(hashes[-1])  # Duplicate the last hash if odd number
        
        new_hashes = []
        for i in range(0, len(hashes), 2):
            combined = hashes[i] + hashes[i+1]
            new_hash = hashlib.sha256(combined.encode()).hexdigest()
            new_hashes.append(new_hash)
        
        hashes = new_hashes
    
    # Return the Merkle root
    return hashes[0] if hashes else hashlib.sha256(b'').hexdigest()

# Verify file integrity using Merkle Tree
def verify_file_integrity(file_id, file_data):
    file_metadata = get_file_info(file_id)
    
    if not file_metadata or "merkle_root" not in file_metadata:
        return False
    
    # Calculate Merkle root for the current data
    current_root = create_merkle_tree(file_data)
    
    # Compare with stored root
    return current_root == file_metadata["merkle_root"]

# Parse natural language permission command
def parse_permission_command(command, file_id, username):
    # Simple rule-based parsing for permission commands
    command = command.lower()
    
    # Extract target username
    user_match = re.search(r'(give|grant|allow|share with) (\w+)', command)
    if user_match:
        target_username = user_match.group(2)
    else:
        return False, "Could not identify user in command"
    
    # Determine permission level
    permission = "read"  # Default
    if "edit" in command or "write" in command or "modify" in command:
        permission = "write"
    elif "admin" in command or "full" in command:
        permission = "admin"
    
    # Share the file
    return share_file(file_id, username, target_username, permission)

# Delete file
def delete_file(file_id, username):
    file_metadata = get_file_info(file_id)
    
    if not file_metadata:
        return False, "File not found"
    
    if file_metadata["owner"] != username:
        return False, "You don't have permission to delete this file"
    
    # Delete file data
    file_path = os.path.join(FILE_DATA_DIR, f"{file_id}.bin")
    if os.path.exists(file_path):
        os.remove(file_path)
    
    # Delete metadata
    metadata_path = os.path.join(FILE_DATA_DIR, f"{file_id}.json")
    if os.path.exists(metadata_path):
        os.remove(metadata_path)
    
    # Delete key
    key_path = os.path.join(KEYS_DIR, f"{file_id}.key")
    if os.path.exists(key_path):
        os.remove(key_path)
    
    # Update access log
    log_path = os.path.join(ACCESS_LOGS_DIR, f"{file_id}.json")
    if os.path.exists(log_path):
        with open(log_path, 'r') as f:
            access_log = json.load(f)
        
        access_log["logs"].append({
            "action": "delete",
            "user": username,
            "timestamp": datetime.now().isoformat()
        })
        
        with open(log_path, 'w') as f:
            json.dump(access_log, f, indent=4)
    
    return True, "File deleted successfully"

# Get file access logs
def get_file_access_logs(file_id):
    log_path = os.path.join(ACCESS_LOGS_DIR, f"{file_id}.json")
    
    if not os.path.exists(log_path):
        return []
    
    with open(log_path, 'r') as f:
        access_log = json.load(f)
    
    return access_log.get("logs", [])

# Get files by extension
def get_files_by_extension(username, extension):
    all_files = get_user_files(username)
    
    # Filter files by extension
    filtered_files = [
        file for file in all_files 
        if file["file_name"].lower().endswith(extension.lower())
    ]
    
    return filtered_files