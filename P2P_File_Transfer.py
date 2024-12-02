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
import json

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
FRIENDS_FILE = "friends.json"

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

def listen_for_server_messages():
    """Listens for messages from the server in a separate thread."""
    global username
    try:
        while True:
            try:
                # Receive messages from the server
                message = receive_message()
                if not message:
                    break

                # Log the incoming message
                client_log_callback(f"Received message: {message}")

                # Handle FRIEND_REQUEST_ACCEPTED messages
                if message.startswith("FRIEND_REQUEST_ACCEPTED"):
                    _, sender, recipient, ip, port = message.split("|")
                    handle_friend_request_accepted(recipient, ip, port)
                    client_log_callback(f"Friend request from {sender} to {recipient} was accepted.")

                # Handle FRIEND_REQUEST_DECLINED messages
                elif message.startswith("FRIEND_REQUEST_DECLINED"):
                    _, sender, recipient = message.split("|")
                    client_log_callback(f"Friend request from {sender} to {recipient} was declined.")

                # Handle FRIEND_REQUEST messages
                elif message.startswith("FRIEND_REQUEST"):
                    _, sender, recipient = message.split("|")
                    client_log_callback(f"Friend request received from {sender}.")
                    handle_friend_request(sender, recipient)

                # Handle UPDATE_SUCCESS messages
                elif message.startswith("UPDATE_SUCCESS"):
                    client_log_callback("User Update Successful.")

                else:
                    # Handle other server messages if necessary
                    client_log_callback(f"Unhandled server message: {message}")

            except Exception as e:
                client_log_callback(f"Error receiving or processing message: {e}")
                break

    except Exception as e:
        client_log_callback(f"Listener thread encountered an error: {e}")

def handle_friend_request(sender, recipient):
    """Opens a Tkinter dialog box to ask the user to accept or reject a friend request."""
    def on_accept():
        # User accepts the friend request
        send_message(f"FRIEND_REQUEST_ACCEPT|{sender}|{recipient}")
        client_log_callback(f"Friend request from {sender} accepted.")
        root.destroy()  # Close the dialog box

    def on_decline():
        # User declines the friend request
        send_message(f"FRIEND_REQUEST_DECLINE|{sender}|{recipient}")
        client_log_callback(f"Friend request from {sender} declined.")
        root.destroy()  # Close the dialog box

    # Create a simple dialog box
    root = tk.Tk()
    root.title("Friend Request")
    root.geometry("300x150")
    tk.Label(root, text=f"Friend request from {sender}", font=("Arial", 14)).pack(pady=20)

    # Buttons for Accept and Decline
    button_frame = tk.Frame(root)
    button_frame.pack(pady=10)

    accept_button = tk.Button(button_frame, text="Accept", command=on_accept, width=10, bg="green", fg="white")
    accept_button.pack(side=tk.LEFT, padx=10)

    decline_button = tk.Button(button_frame, text="Decline", command=on_decline, width=10, bg="red", fg="white")
    decline_button.pack(side=tk.RIGHT, padx=10)

    # Run the dialog box
    root.mainloop()

def handle_friend_request_accepted(recipient, ip, port):
    """Handles the entire friend request accepted message."""
    try:
        # Ensure required fields are present
        if not recipient or not ip or not port:
            server_log_callback(f"Missing data in FRIEND_REQUEST_ACCEPTED message")
            return

        # Read existing friends from FRIENDS_FILE
        try:
            with open("friends.json", "r") as friends_file:
                friends_data = json.load(friends_file)
        except FileNotFoundError:
            friends_data = {}

        # Add new friend data
        friends_data[recipient] = {"ip": ip, "port": port}

        # Write back to FRIENDS_FILE
        with open("friends.json", "w") as friends_file:
            json.dump(friends_data, friends_file, indent=4)

        update_friends_list(friends_list_widget)
        server_log_callback(f"Added {recipient} to friends list with IP {ip} and Port {port}.")
    except Exception as e:
        server_log_callback(f"Error processing FRIEND_REQUEST_ACCEPTED message: {e}")

def load_friends():
    """Loads the friends list from the JSON file."""
    try:
        with open(FRIENDS_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        # If the file doesn't exist, return an empty dictionary
        return {}
    except json.JSONDecodeError:
        # If the JSON file is corrupted, return an empty dictionary
        return {}

def save_friends(friends):
    """Saves the friends list to the JSON file."""
    try:
        with open(FRIENDS_FILE, "w") as f:
            json.dump(friends, f, indent=4)
    except Exception as e:
        client_log_callback(f"Error saving friends list: {e}")

def send_friend_request():
    """ Sends a friend request to the server and handles the response. """
    global username
    try:
        # Ensure the persistent connection is established
        if persistent_secure_socket is None:
            raise ConnectionError("No active connection to the server.")
        
        sender = username
        # Send friend request
        recipient = simpledialog.askstring("Add Friend", "Enter friend's name:")
        if recipient is None:
            return
        request_message = f"ADD_FRIEND|{sender}|{recipient}"
        send_message(request_message)
        client_log_callback(f"Friend Request Sent to {recipient}.")

    except ConnectionError as e:
        return f"Connection error: {e}"
    except Exception as e:
        return f"An error occurred while processing the friend request: {e}"

def remove_friend():
    try:
        # Get the selected friend from the Listbox
        selected_friend = friends_list_widget.get(tk.ACTIVE)
        if not selected_friend:
            messagebox.showerror("Error", "No friend selected!")
            return

        # Load the current friends data from the file
        try:
            with open("friends.json", "r") as file:
                friends_data = json.load(file)
        except FileNotFoundError:
            messagebox.showerror("Error", "Friends file not found.")
            return

        # Check if the selected friend exists in the file
        if selected_friend in friends_data:
            # Remove the selected friend
            del friends_data[selected_friend]

            # Save the updated data back to the file
            with open("friends.json", "w") as file:
                json.dump(friends_data, file, indent=4)

            update_friends_list(friends_list_widget)
            
            messagebox.showinfo("Success", f"{selected_friend} has been removed from your friends list.")
        else:
            messagebox.showerror("Error", f"{selected_friend} is not in your friends list.")

    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

def update_friends_list(friends_list_widget):
    """
    Updates the friends list UI widget by reading the FRIENDS_FILE.
    """
    try:
        # Load friends from the JSON file
        with open(FRIENDS_FILE, "r") as f:
            friends_data = json.load(f)
    except FileNotFoundError:
        friends_data = {}  # No friends file exists yet
    except json.JSONDecodeError:
        friends_data = {}  # Corrupted file, treat as empty

    # Clear the existing list in the widget
    friends_list_widget.delete(0, tk.END)

    # Add friends to the widget
    for friend, details in friends_data.items():
        ip = details.get("ip", "Unknown IP")
        port = details.get("port", "Unknown Port")
        friends_list_widget.insert(tk.END, f"{friend}")
        # friends_list_widget.insert(tk.END, f"{friend} (IP: {ip}, Port: {port})")

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
        client_log_callback(f"Socket error: {e}")
    except ssl.SSLError as e:
        client_log_callback(f"SSL error: {e}")
    except Exception as e:
        client_log_callback(f"Unexpected error: {e}")
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
                message = f"UPDATE|{username}|{ip}|{CLIENT_PORT}"
                send_message(message)

                # Receive response
                #response = receive_message()
                #client_log_callback(f"Periodic Update Response: {response}")
            except Exception as e:
                client_log_callback(f"Error in periodic update: {e}")
            time.sleep(60)  # Send updates every 60 seconds

    threading.Thread(target=update, daemon=True).start()


def get_active_users():
    """Gets the list of active users from the server."""
    try:
        # Send the request to get active users
        send_message("GET_ACTIVE_USERS")
        
        # Receive and decode the response
        response = receive_message()
        
        # Parse the JSON response
        active_users = json.loads(response)
        client_log_callback(f"Active Users: {active_users}")
        return active_users
    except json.JSONDecodeError:
        raise ValueError("Failed to parse the server's response. Invalid JSON format.")
    except ConnectionError as e:
        raise ConnectionError(f"Connection error while getting active users: {e}")
    except Exception as e:
        raise Exception(f"An error occurred while getting active users: {e}")

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

    # Start Listener for User Server Messages
    threading.Thread(target=listen_for_server_messages, daemon=True).start()
    
    # Start User Data Updates
    #threading.Thread(target=start_user_data_updates, daemon=True).start()

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
    tk.Button(root, text="Get Active Users", command=get_active_users).grid(row=5, column=1, padx=10, pady=5)
    #tk.Button(root, text="Disconnect From User Server", command=disconnect_persistent).grid(row=5, column=1, padx=10, pady=5)

    # Friends List Section
    tk.Label(root, text="Friends List").grid(row=5, column=0, padx=10, pady=5, sticky="w")
    friends_list_widget = tk.Listbox(root, height=10, width=50)
    friends_list_widget.grid(row=6, column=0, padx=10, pady=5)
    tk.Button(root, text="Add Friend", command=send_friend_request).grid(row=7, column=0, padx=10, pady=5)
    tk.Button(root, text="Remove Friend", command=remove_friend).grid(row=8, column=0, padx=10, pady=5)

    update_friends_list(friends_list_widget)

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