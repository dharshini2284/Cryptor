import os
import threading
import time
import zipfile
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from getpass import getpass
import base64
import tkinter as tk
from tkinter import filedialog, messagebox
import random

# Constants
CHUNK_SIZE = 4096  # Size of each chunk to process
MAX_THREADS = 4  # Number of threads to use

# Semaphore for thread synchronization
semaphore = threading.Semaphore(1)

def generate_key(password: str):
    """Generate a Fernet key based on a password."""
    salt = b'\x00' * 16  # Use a fixed salt for demonstration; use a random salt in production
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_chunk(key: bytes, chunk: bytes) -> bytes:
    """Encrypt a chunk of data using Fernet."""
    cipher = Fernet(key)
    return cipher.encrypt(chunk)

def decrypt_chunk(key: bytes, chunk: bytes):
    """Decrypt a chunk of data using Fernet."""
    cipher = Fernet(key)
    try:
        decrypted = cipher.decrypt(chunk)
        return decrypted
    except Exception as e:
        print(f"Decryption error: {e}")  # Log the specific error
        raise  # Re-raise to allow further handling in process_chunk

def process_file(file_path: str, action: str, key: bytes, output_file_name: str):
    """Process the entire file in chunks for encryption or decryption."""
    threads = []  # List to keep track of threads

    with open(file_path, 'rb') as input_file:
        output_file = open(output_file_name, 'wb')
        try:
            if action == 'encrypt':
                while True:
                    chunk = input_file.read(CHUNK_SIZE)
                    if not chunk:
                        break

                    thread = threading.Thread(target=process_chunk, args=(action, key, chunk, output_file))
                    thread.start()
                    threads.append(thread)

            elif action == 'decrypt':
                encrypted_data = input_file.read()  # Read all encrypted data
                decrypted_data = decrypt_chunk(key, encrypted_data)  # Decrypt the entire data
                output_file.write(decrypted_data)  # Write the decrypted data to output

        finally:
            for thread in threads:
                thread.join()  # Wait for all threads to complete
            output_file.close()



def process_chunk(action: str, key: bytes, chunk: bytes, output_file, file_path=None):
    """Process a chunk of data (encrypt or decrypt)."""
    # Introduce a random sleep time to simulate varying execution order
    time.sleep(random.uniform(0.1, 1))  # Sleep for a random duration between 0.1 and 1 second
    
    with semaphore:
        thread_name = threading.current_thread().name
        print(f"{thread_name} is entering critical section.")
        try:
            if action == 'encrypt':
                encrypted_chunk = encrypt_chunk(key, chunk)
                output_file.write(encrypted_chunk)
                print(f"{thread_name} has written encrypted chunk to output.")
        except Exception as e:
            print(f"Error processing chunk in {thread_name}: {e} (Action: {action})")
        finally:
            print(f"{thread_name} is exiting critical section.")

def backup_file(original_file_path: str):
    """Create a backup of the original file as a mirror (RAID 1 concept)."""
    backup_file_path = f"{original_file_path}.bak"
    mirror_file_path = f"{original_file_path}.mirror"  # Second copy for mirroring
    try:
        with open(original_file_path, 'rb') as original_file:
            with open(backup_file_path, 'wb') as backup_file:
                backup_file.write(original_file.read())
                
            with open(mirror_file_path, 'wb') as mirror_file:
                mirror_file.write(original_file.read())  # Create a second backup

        print(f"Backup created at: {backup_file_path}")
        print(f"Mirror backup created at: {mirror_file_path}")
        return backup_file_path, mirror_file_path
    except Exception as e:
        messagebox.showerror("Error", f"Failed to create backup: {e}")
        return None


def select_file():
    """Open a file dialog to select a file."""
    file_path = filedialog.askopenfilename()
    if file_path:
        input_file_entry.delete(0, tk.END)  # Clear previous entry
        input_file_entry.insert(0, file_path)

def encrypt_file():
    """Handle the file encryption process with backup."""
    file_path = input_file_entry.get()
    output_file_name = output_file_entry.get()
    password = password_entry.get()
    key = generate_key(password)

    if not output_file_name:
        messagebox.showerror("Error", "Please enter an output file name.")
        return

    # Create a backup of the original file
    backup_path = backup_file(file_path)
    if backup_path:
        messagebox.showinfo("Backup", "Backup created successfully!")

    if compress_var.get():
        file_path = compress_file(file_path)

    try:
        process_file(file_path, 'encrypt', key, output_file_name)
        messagebox.showinfo("Success", "File encrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {e}")

def decrypt_file():
    """Handle the file decryption process."""
    file_path = input_file_entry.get()
    output_file_name = output_file_entry.get()
    password = password_entry.get()
    key = generate_key(password)

    if not output_file_name:
        messagebox.showerror("Error", "Please enter an output file name.")
        return

    try:
        process_file(file_path, 'decrypt', key, output_file_name)
        messagebox.showinfo("Success", "File decrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")

# Create the main window
root = tk.Tk()
root.title("File Encryption/Decryption Tool")

# Create and place widgets
tk.Label(root, text="Input File:").grid(row=0, column=0, padx=10, pady=10)
input_file_entry = tk.Entry(root, width=50)
input_file_entry.grid(row=0, column=1, padx=10, pady=10)

tk.Button(root, text="Browse", command=select_file).grid(row=0, column=2, padx=10, pady=10)

tk.Label(root, text="Output File Name:").grid(row=1, column=0, padx=10, pady=10)
output_file_entry = tk.Entry(root, width=50)
output_file_entry.grid(row=1, column=1, padx=10, pady=10)

tk.Label(root, text="Password:").grid(row=2, column=0, padx=10, pady=10)
password_entry = tk.Entry(root, show='*')
password_entry.grid(row=2, column=1, padx=10, pady=10)

compress_var = tk.BooleanVar()
tk.Checkbutton(root, text="Compress file before encryption", variable=compress_var).grid(row=3, columnspan=2, padx=10, pady=10)

tk.Button(root, text="Encrypt", command=encrypt_file).grid(row=4, column=0, padx=10, pady=10)
tk.Button(root, text="Decrypt", command=decrypt_file).grid(row=4, column=1, padx=10, pady=10)

# Start the GUI event loop
root.mainloop()