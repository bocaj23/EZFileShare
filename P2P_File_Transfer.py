import os
import socket
import ssl
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import queue
import zlib
import zipfile
import shutil
import time

# Constants
DEFAULT_HOST = '127.0.0.1' # Default Host for File Transfer
DEFAULT_PORT = 65432 # Default Port for File Transfer
USER_DATA_SERVER_HOST = '127.0.0.1'  # Host for the user data server
USER_DATA_SERVER_PORT = 5000         # Port for the user data server
BUFFER_SIZE = 4096
CLIENT_CERTFILE = "client.crt" # Client Cert Signed with CA Key and Cert
CLIENT_KEYFILE = "client.key" # Client Key
SERVER_CERTFILE = "server.crt" # Server Cert Signed with CA Key and Cert
SERVER_KEYFILE = "server.key" # Server Key
CA_CRT = "ca.crt" # Certificate Authority Cert

# Shared state
server_log_widget = None
client_log_widget = None
friends_list_widget = None
download_dir = os.getcwd()
command_queue = queue.Queue()
friends_list = {}
persistent_secure_socket = None
server_ssl_context = None
client_ssl_context = None
username = None
CLIENT_PORT = DEFAULT_PORT 

def initialize_server_ssl_context():
    """Initializes the Server SSL context."""
    global server_ssl_context
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    server_ssl_context = ssl_context 
    ssl_context.load_cert_chain(certfile=SERVER_CERTFILE, keyfile=SERVER_KEYFILE)
    ssl_context.load_verify_locations(CA_CRT)
    return ssl_context

def initialize_client_ssl_context():
    """Initializes the Client SSL context."""
    global client_ssl_context
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    client_ssl_context = ssl_context 
    ssl_context.load_cert_chain(certfile=CLIENT_CERTFILE, keyfile=CLIENT_KEYFILE)
    ssl_context.load_verify_locations(CA_CRT)
    return ssl_context

def log_message(widget, message):
    """Logs a message to a specific Text widget."""
    widget.config(state="normal")
    widget.insert(tk.END, message + "\n")
    widget.config(state="disabled")
    widget.see(tk.END)

def server_log_callback(message):
    """Callback to log server messages."""
    if server_log_widget:
        log_message(server_log_widget, message)

def client_log_callback(message):
    """Callback to log client messages."""
    if client_log_widget:
        log_message(client_log_widget, message)

def server(host, port):
    """Runs the P2P server"""
    global download_dir
    context = initialize_server_ssl_context()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen(5)
        server_log_callback(f"Server listening on {host}:{port}")
        with context.wrap_socket(server_socket, server_side=True) as secure_socket:
            while True:
                # Process commands from the queue
                try:
                    while not command_queue.empty():
                        command, value = command_queue.get_nowait()
                        if command == "set_download_dir":
                            download_dir = value
                            server_log_callback(f"Download directory changed to: {value}")
                except queue.Empty:
                    pass

                # Accept client connections
                try:
                    conn, addr = secure_socket.accept()
                    server_log_callback(f"Connection established with {addr}")
                    threading.Thread(
                        target=handle_client,
                        args=(conn,),
                        daemon=True
                    ).start()
                except ssl.SSLError as e:
                    server_log_callback(f"SSL error: {e}")

def handle_client(conn):
    """Handles an incoming client connection with file integrity check."""
    global download_dir
    try:
        # Receive the filename and checksum
        metadata = conn.recv(BUFFER_SIZE).decode()
        if not metadata:
            return
        filename, expected_checksum = metadata.split("|")
        expected_checksum = int(expected_checksum)

        server_log_callback(f"Receiving file: {filename}")
        file_path = os.path.join(download_dir, filename)

        # Receive the file data
        with open(file_path, "wb") as f:
            while True:
                data = conn.recv(BUFFER_SIZE)
                if not data:
                    break
                f.write(data)

        # Calculate the checksum of the received file
        with open(file_path, "rb") as f:
            file_data = f.read()
            actual_checksum = zlib.crc32(file_data)

        # Verify the checksum
        if actual_checksum == expected_checksum:
            server_log_callback(f"File {filename} received successfully to {file_path} (Checksum Verified).")
        else:
            server_log_callback(f"File {filename} received to {file_path}, but checksum mismatch! Expected: {expected_checksum}, Got: {actual_checksum}")
    except Exception as e:
        server_log_callback(f"Error: {e}")
    finally:
        conn.close()

def client(host, port, filename):
    """Runs the P2P client to send a file with integrity verification."""
    global client_ssl_context
    initialize_client_ssl_context()
    context = client_ssl_context

    try:
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure_socket:
                client_log_callback(f"Connected to {host}:{port}")

                # Calculate the file's CRC checksum
                with open(filename, "rb") as f:
                    file_data = f.read()
                    checksum = zlib.crc32(file_data)

                # Send the filename and checksum
                secure_socket.sendall(f"{os.path.basename(filename)}|{checksum}".encode())

                # Send the file content
                with open(filename, "rb") as f:
                    while chunk := f.read(BUFFER_SIZE):
                        secure_socket.sendall(chunk)

                client_log_callback(f"File {filename} sent.")
    except Exception as e:
        client_log_callback(f"Error: {e}")

def zip_directory(directory_path):
    zip_file_path = f"{directory_path}.zip"
    with zipfile.ZipFile(zip_file_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, start=directory_path)
                zipf.write(file_path, arcname)
    return zip_file_path

def add_friend():
    """Adds a new friend (host and port) to the friends list."""
    name = simpledialog.askstring("Add Friend", "Enter friend's name:")
    if name:
        host, port = get_host_and_port()
        if host and port:
            friends_list[name] = (host, port)
            update_friends_list()

def remove_friend():
    """Removes the selected friend from the friends list."""
    try:
        # Get the currently selected item
        selected_index = friends_list_widget.curselection()
        if not selected_index:
            messagebox.showerror("Error", "No friend selected.")
            return

        # Extract the friend's name from the selected item
        selected_item = friends_list_widget.get(selected_index)
        friend_name = selected_item.split(" (")[0]

        # Remove the friend from the dictionary
        if friend_name in friends_list:
            del friends_list[friend_name]
            update_friends_list()
            messagebox.showinfo("Success", f"Friend '{friend_name}' removed.")
        else:
            messagebox.showerror("Error", "Friend not found in the list.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to remove friend: {e}")

def update_friends_list():
    """Updates the friends list widget."""
    friends_list_widget.delete(0, tk.END)  # Clear the current list
    for name, (host, port) in friends_list.items():
        friends_list_widget.insert(tk.END, f"{name} ({host}:{port})")  # Add friends to the list

def start_server():
    """Starts the server in a separate thread."""
    host, port = get_host_and_port()
    if host and port:
        threading.Thread(target=server, args=(host, port), daemon=True).start()
        server_log_callback(f"Server started on {host}:{port}. Files will be saved to {download_dir}.")

def select_download_dir():
    """Opens a directory selection dialog to choose the download directory."""
    selected_dir = filedialog.askdirectory(title="Select Download Directory")
    if selected_dir:
        global download_dir
        download_dir = selected_dir
        command_queue.put(("set_download_dir", selected_dir))
        server_log_callback(f"Download directory set to: {download_dir}")

def select_and_send_file():
    """Opens a file dialog and sends the selected file."""
    file_path = filedialog.askopenfilename(title="Select a File")
    if file_path:
        client_log_callback(f"Selected file: {file_path}")
        host, port = get_host_and_port()
        if host and port:
            threading.Thread(target=client, args=(host, port, file_path), daemon=True).start()

def select_and_send_directory():
    """Opens a directory dialog, copies the folder to the current working directory, zips it, and sends the zip file."""
    directory_path = filedialog.askdirectory(title="Select a Directory")
    if directory_path:
        # Copy the directory to the local directory
        local_directory = os.getcwd()  # Get the current working directory
        folder_name = os.path.basename(directory_path)  # Extract the folder name
        local_copy_path = os.path.join(local_directory, folder_name)

        if os.path.exists(local_copy_path):
            client_log_callback(f"Directory {folder_name} already exists in the current directory.")
        else:
            shutil.copytree(directory_path, local_copy_path)  # Copy the directory
            client_log_callback(f"Copied directory to: {local_copy_path}")

        # Zip the copied directory
        zip_path = zip_directory(local_copy_path)
        client_log_callback(f"Zipped directory: {zip_path}")

        # Send the zip file
        host, port = get_host_and_port()
        if host and port:
            threading.Thread(target=client, args=(host, port, zip_path), daemon=True).start()

def get_host_and_port():
    """Gets the host and port from the GUI input fields."""
    host = host_entry.get()
    try:
        port = int(port_entry.get())
        if port < 1 or port > 65535:
            raise ValueError("Port out of range.")
    except ValueError:
        messagebox.showerror("Invalid Input", "Port must be an integer between 1 and 65535.")
        return None, None
    return host, port

def connect_persistent(host, port):
    """Establishes a persistent connection with user server if not already connected."""
    global persistent_secure_socket, client_ssl_context, server_ssl_context
    try:
        # Check if already connected
        if persistent_secure_socket:
            return persistent_secure_socket
        
        # Create raw socket connection
        raw_socket = socket.create_connection((host, port))
        
        # Wrap with SSL/TLS
        persistent_secure_socket = client_ssl_context.wrap_socket(raw_socket, server_hostname=host)
        return persistent_secure_socket
    except socket.error as e:
        print(f"Socket error: {e}")
    except ssl.SSLError as e:
        print(f"SSL error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
    return None  # Return None if connection fails

def disconnect_persistent():
    """Closes the persistent connection with user server if it exists."""
    global persistent_secure_socket
    if persistent_secure_socket:
        persistent_secure_socket.close()
        persistent_secure_socket = None
        
def send_message(message):
    """Sends a message to user server using the persistent connection."""
    if persistent_secure_socket is None:
        raise ConnectionError("No active connection.")
    persistent_secure_socket.sendall(message.encode())

def receive_message(buffer_size=1024):
    """Receives a message from user server using the persistent connection."""
    if persistent_secure_socket is None:
        raise ConnectionError("No active connection.")
    return persistent_secure_socket.recv(buffer_size).decode()

def show_login():
    """Displays the login screen and queries the server for validation."""
    login_success = False

    def attempt_login():
        nonlocal login_success
        global username
        user = username_entry.get()
        password = password_entry.get()

        try:
           
            # Send login request
            send_message("LOGIN")
            send_message(f"{user}|{password}")

            # Receive response
            response = receive_message()
            if response == "LOGIN_SUCCESS":
                login_success = True
                username = user
                messagebox.showinfo("Login Successful", "Welcome!")
                login_window.destroy()
            elif response == "LOGIN_FAIL":
                messagebox.showerror("Login Failed", "Invalid username or password.")
            else:
                messagebox.showerror("Error", "An error occurred during login.")
        except Exception as e:
            messagebox.showerror("Error", f"Connection failed: {e}")

    login_window = tk.Tk()
    login_window.title("Login")

    tk.Label(login_window, text="Username:").grid(row=0, column=0, padx=10, pady=5)
    username_entry = tk.Entry(login_window)
    username_entry.grid(row=0, column=1, padx=10, pady=5)

    tk.Label(login_window, text="Password:").grid(row=1, column=0, padx=10, pady=5)
    password_entry = tk.Entry(login_window, show="*")
    password_entry.grid(row=1, column=1, padx=10, pady=5)
    
    tk.Button(login_window, text="Login", command=attempt_login).grid(row=2, column=0, columnspan=2, pady=10)
    username = username_entry
    login_window.mainloop()
    return login_success

# User Data Client Integration
def register_with_user_data_server(): # In Progress
    """Registers the client with the user data server."""
    try:
        # Establish persistent connection if not already connected
        connect_persistent(USER_DATA_SERVER_HOST, USER_DATA_SERVER_PORT)

        # Send registration request
        ip = socket.gethostbyname(socket.gethostname())
        message = f"register|{username}|{"PASSWORD"}|{ip}|{CLIENT_PORT}" # Placeholder Password
        send_message(message)

        # Receive response
        response = receive_message()
        client_log_callback(f"User Data Server Response: {response}")
    except Exception as e:
        client_log_callback(f"Error registering with User Data Server: {e}")

def send_periodic_updates():
    """Sends periodic updates to the user data server."""
    def update():
        while True:
            try:
                # Establish persistent connection if not already connected
                connect_persistent(USER_DATA_SERVER_HOST, USER_DATA_SERVER_PORT)

                # Send update request
                ip = socket.gethostbyname(socket.gethostname())
                message = f"update|{username}|{ip}|{CLIENT_PORT}"
                send_message(message)

                # Receive response
                response = receive_message()
                client_log_callback(f"Periodic Update Response: {response}")
            except Exception as e:
                client_log_callback(f"Error in periodic update: {e}")
            time.sleep(60)  # Send updates every 60 seconds

    threading.Thread(target=update, daemon=True).start()

# Starting updates after login
def start_user_data_updates():
    """Initializes registration and periodic updates."""
    send_periodic_updates()

# GUI Initialization
def main():
    global server_log_widget, client_log_widget, friends_list_widget, host_entry, port_entry
    initialize_client_ssl_context()
    connect_persistent(USER_DATA_SERVER_HOST, USER_DATA_SERVER_PORT)
    if not show_login():
        return  # Exit if login fails or the window is closed without logging in.
    
    root = tk.Tk()
    root.title("EZFileShare")

    # Start User Data Updates
    threading.Thread(target=start_user_data_updates, daemon=True).start()

    # Server Section
    tk.Label(root, text="Receive").grid(row=1, column=0, padx=10, pady=5, sticky="w")
    server_log_widget = tk.Text(root, height=10, width=50, state="disabled")
    server_log_widget.grid(row=2, column=0, padx=10, pady=5)
    tk.Button(root, text="Start", command=start_server).grid(row=3, column=0, padx=10, pady=5)
    tk.Button(root, text="Select Download Directory", command=select_download_dir).grid(row=4, column=0, padx=10, pady=5)

    # Client Section
    tk.Label(root, text="Send").grid(row=1, column=1, padx=10, pady=5, sticky="w")
    client_log_widget = tk.Text(root, height=10, width=50, state="disabled")
    client_log_widget.grid(row=2, column=1, padx=10, pady=5)
    tk.Button(root, text="Select File & Send", command=select_and_send_file).grid(row=3, column=1, padx=10, pady=5)
    tk.Button(root, text="Select Directory & Send", command=select_and_send_directory).grid(row=4, column=1, padx=10, pady=5)
    #tk.Button(root, text="Disconnect From User Server", command=disconnect_persistent).grid(row=5, column=1, padx=10, pady=5)

    # Friends List Section
    tk.Label(root, text="Friends List").grid(row=5, column=0, padx=10, pady=5, sticky="w")
    friends_list_widget = tk.Listbox(root, height=10, width=50)
    friends_list_widget.grid(row=6, column=0, padx=10, pady=5)
    tk.Button(root, text="Add Friend", command=add_friend).grid(row=7, column=0, padx=10, pady=5)
    tk.Button(root, text="Remove Friend", command=remove_friend).grid(row=8, column=0, padx=10, pady=5)

    # Host and Port Configuration
    tk.Label(root, text="Host:").grid(row=6, column=0, padx=10, pady=5, sticky="e")
    host_entry = tk.Entry(root)
    host_entry.insert(0, DEFAULT_HOST)
    host_entry.grid(row=6, column=1, padx=10, pady=5, sticky="w")

    tk.Label(root, text="Port:").grid(row=7, column=0, padx=10, pady=5, sticky="e")
    port_entry = tk.Entry(root)
    port_entry.insert(0, str(DEFAULT_PORT))
    port_entry.grid(row=7, column=1, padx=10, pady=5, sticky="w")

    #root.protocol("WM_DELETE_WINDOW", disconnect_persistent())
    root.mainloop()

if __name__ == "__main__":
    main()