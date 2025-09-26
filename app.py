import streamlit as st
import hashlib
import json
import time
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # Fixed typo
import base64

# Configuration
PERSISTENCE_FILE = "encrypted_data.json"
MAX_ATTEMPTS = 3
LOCKOUT_TIME = 300  # 5 minutes in seconds

# Initialize session state correctly
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}  # Fixed: using {} instead of ()
if 'failed_attempts' not in st.session_state:  # Fixed variable name
    st.session_state.failed_attempts = 0  # Fixed: proper initialization
if 'lockout_until' not in st.session_state:
    st.session_state.lockout_until = 0
if 'master_password' not in st.session_state:
    st.session_state.master_password = "admin123"

# Generate or load encryption key
def get_encryption_key():
    if 'encryption_key' not in st.session_state:
        key = Fernet.generate_key()
        st.session_state.encryption_key = key
    return st.session_state.encryption_key

cipher = Fernet(get_encryption_key())

# Enhanced password hashing with PBKDF2
def hash_passkey(passkey, salt=None):
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(  # Fixed class name
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(passkey.encode()))
    return key, salt

# Verify passkey
def verify_passkey(passkey, stored_hash, salt):
    new_hash, _ = hash_passkey(passkey, salt)
    return new_hash == stored_hash

# Data persistence functions
def load_data():
    try:
        if os.path.exists(PERSISTENCE_FILE):
            with open(PERSISTENCE_FILE, 'r') as f:
                return json.load(f)
    except Exception as e:
        st.error(f"Error loading data: {e}")
    return {}

def save_data():
    try:
        with open(PERSISTENCE_FILE, 'w') as f:
            json.dump(st.session_state.stored_data, f)
    except Exception as e:
        st.error(f"Error saving data: {e}")

# Load data on startup
if not st.session_state.stored_data:
    st.session_state.stored_data = load_data()

# Encryption function
def encrypt_data(text, passkey):
    try:
        encrypted_text = cipher.encrypt(text.encode()).decode()
        hashed_passkey, salt = hash_passkey(passkey)
        
        return {
            "encrypted_text": encrypted_text,
            "passkey_hash": hashed_passkey.decode(),
            "salt": base64.b64encode(salt).decode()
        }
    except Exception as e:
        st.error(f"Encryption error: {e}")
        return None

# Decryption function
def decrypt_data(data_id, passkey):
    if st.session_state.lockout_until > time.time():
        remaining_time = int(st.session_state.lockout_until - time.time())
        st.error(f"Account locked. Please try again in {remaining_time} seconds.")
        return None
    
    if data_id not in st.session_state.stored_data:
        st.error("Data not found!")
        return None
    
    data = st.session_state.stored_data[data_id]
    
    try:
        salt = base64.b64decode(data["salt"])
        if verify_passkey(passkey, data["passkey_hash"].encode(), salt):
            decrypted_text = cipher.decrypt(data["encrypted_text"].encode()).decode()
            st.session_state.failed_attempts = 0  # Reset attempts on success
            return decrypted_text
        else:
            st.session_state.failed_attempts += 1
            attempts_left = MAX_ATTEMPTS - st.session_state.failed_attempts
            
            if attempts_left > 0:
                st.error(f"❌ Incorrect passkey! Attempts remaining: {attempts_left}")
            else:
                st.session_state.lockout_until = time.time() + LOCKOUT_TIME
                st.error(f"🔒 Too many failed attempts! Account locked for {LOCKOUT_TIME//60} minutes.")
            
            return None
    except Exception as e:
        st.error(f"Decryption error: {e}")
        return None

# Generate unique data ID
def generate_data_id():
    return f"data_{int(time.time())}_{hashlib.sha256(os.urandom(16)).hexdigest()[:8]}"

# Login page
def login_page():
    st.subheader("🔑 Reauthorization Required")
    
    if st.session_state.lockout_until > time.time():
        remaining_time = int(st.session_state.lockout_until - time.time())
        st.warning(f"🔒 Account locked. Please try again in {remaining_time} seconds.")
        return
    
    login_pass = st.text_input("Enter Master Password:", type="password", key="login_pass")
    
    if st.button("Login"):
        if login_pass == st.session_state.master_password:
            st.session_state.failed_attempts = 0
            st.session_state.lockout_until = 0
            st.success("✅ Reauthorized successfully!")
            time.sleep(1)
            st.rerun()
        else:
            st.error("❌ Incorrect master password!")

# Settings page for admin
def settings_page():
    st.subheader("⚙️ System Settings")
    
    st.write("### Master Password Configuration")
    new_master = st.text_input("New Master Password:", type="password", key="new_master")
    confirm_master = st.text_input("Confirm Master Password:", type="password", key="confirm_master")
    
    if st.button("Update Master Password"):
        if new_master and new_master == confirm_master:
            st.session_state.master_password = new_master
            st.success("✅ Master password updated successfully!")
        else:
            st.error("❌ Passwords don't match or are empty!")
    
    st.write("### Data Management")
    if st.button("Clear All Data"):
        if st.checkbox("I understand this will delete all stored data permanently"):
            st.session_state.stored_data = {}
            save_data()
            st.success("✅ All data cleared!")
    
    st.write("### System Information")
    st.write(f"Total stored entries: {len(st.session_state.stored_data)}")
    st.write(f"Failed attempts: {st.session_state.failed_attempts}")

# Fixed navigation - using selectbox instead of switch_page
def main():
    st.set_page_config(
        page_title="Secure Data Encryption System",
        page_icon="🔒",
        layout="wide"
    )
    
    st.title("🔒 Secure Data Encryption System")
    st.markdown("---")
    
    # Navigation - Fixed: using selectbox navigation instead of switch_page
    menu_options = ["Home", "Store Data", "Retrieve Data", "Login", "Settings"]
    
    if st.session_state.failed_attempts >= MAX_ATTEMPTS:
        st.warning("🔒 Account locked due to multiple failed attempts. Please login.")
        choice = "Login"
    else:
        choice = st.sidebar.selectbox("Navigation", menu_options)
    
    st.sidebar.markdown("---")
    st.sidebar.info("### System Status")
    st.sidebar.write(f"Failed attempts: {st.session_state.failed_attempts}/{MAX_ATTEMPTS}")
    
    if st.session_state.lockout_until > time.time():
        remaining = int(st.session_state.lockout_until - time.time())
        st.sidebar.error(f"🔒 Locked: {remaining}s")
    
    # Fixed: Simple if-else navigation instead of switch_page
    if choice == "Home":
        home_page()
    elif choice == "Store Data":
        store_data_page()
    elif choice == "Retrieve Data":
        retrieve_data_page()
    elif choice == "Login":
        login_page()
    elif choice == "Settings":
        settings_page()

def home_page():
    st.subheader("🏠 Welcome to the Secure Data System")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("### 📊 System Overview")
        st.write(f"**Total encrypted entries:** {len(st.session_state.stored_data)}")
        st.write(f"**Failed decryption attempts:** {st.session_state.failed_attempts}")
        st.write(f"**Account status:** {'🔒 Locked' if st.session_state.lockout_until > time.time() else '✅ Active'}")
        
        if st.session_state.stored_data:
            st.write("### 📋 Recent Entries")
            recent_entries = list(st.session_state.stored_data.keys())[-5:]
            for entry in recent_entries:
                st.write(f"• {entry}")
    
    with col2:
        st.write("### 🔐 Security Features")
        st.write("✅ **Military-grade encryption** using Fernet (AES-128)")
        st.write("✅ **PBKDF2 key derivation** with 100,000 iterations")
        st.write("✅ **Automatic account lockout** after 3 failed attempts")
        st.write("✅ **Time-based lockout** (5 minutes)")
        st.write("✅ **Persistent encrypted storage**")
        
        st.write("### 🚀 Quick Actions")
        if st.button("Store New Data", key="home_store"):
            st.session_state.navigation = "Store Data"
            st.rerun()
        if st.button("Retrieve Data", key="home_retrieve"):
            st.session_state.navigation = "Retrieve Data"
            st.rerun()

def store_data_page():
    st.subheader("📂 Store Data Securely")
    
    with st.form("store_data_form"):
        user_data = st.text_area("Enter Sensitive Data:", height=150, 
                               placeholder="Enter the text you want to encrypt and store securely...")
        passkey = st.text_input("Enter Encryption Passkey:", type="password",
                              help="Remember this passkey! You'll need it to decrypt the data later.")
        data_id = st.text_input("Optional Data Identifier:", 
                              placeholder="Leave empty for auto-generated ID")
        
        submitted = st.form_submit_button("🔒 Encrypt & Save Data")
        
        if submitted:
            if not user_data or not passkey:
                st.error("⚠️ Both data and passkey are required!")
                return
            
            if not data_id:
                data_id = generate_data_id()
            
            if data_id in st.session_state.stored_data:
                st.error("❌ Data ID already exists! Please choose a different one.")
                return
            
            encrypted_data = encrypt_data(user_data, passkey)
            
            if encrypted_data:
                st.session_state.stored_data[data_id] = encrypted_data
                save_data()
                
                st.success("✅ Data encrypted and stored securely!")
                
                col1, col2 = st.columns(2)
                with col1:
                    st.info(f"**Data ID:** `{data_id}`")
                with col2:
                    st.info("**Save this ID for retrieval**")
                
                if st.button("Store Another Entry"):
                    st.rerun()

def retrieve_data_page():
    st.subheader("🔍 Retrieve Your Data")
    
    if st.session_state.lockout_until > time.time():
        remaining_time = int(st.session_state.lockout_until - time.time())
        st.error(f"🔒 Account locked. Please try again in {remaining_time} seconds.")
        st.info("Visit the Login page to reauthorize.")
        return
    
    with st.form("retrieve_data_form"):
        data_id = st.text_input("Enter Data ID:", 
                              placeholder="The unique identifier for your data")
        passkey = st.text_input("Enter Decryption Passkey:", type="password")
        
        submitted = st.form_submit_button("🔓 Decrypt Data")
        
        if submitted:
            if not data_id or not passkey:
                st.error("⚠️ Both Data ID and passkey are required!")
                return
            
            decrypted_text = decrypt_data(data_id, passkey)
            
            if decrypted_text:
                st.success("✅ Data decrypted successfully!")
                
                st.text_area("Decrypted Data:", value=decrypted_text, height=200, 
                           key="decrypted_output")
                
                st.info("**Security Tip:** Copy the data and close this page when done.")

# Run the app
if __name__ == "__main__":
    main()