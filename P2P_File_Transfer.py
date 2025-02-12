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
import sys
import requests

# Constants
DEFAULT_PORT = 65432 # Default Port for File Transfer
USER_DATA_SERVER_HOST = '127.0.0.1' # Host for the user data server
USER_DATA_SERVER_PORT = 5000         # Port for the user data server
BUFFER_SIZE = 4096
SERVER_CERTFILE = "server.crt" # Server Cert Signed with CA Key and Cert
SERVER_KEYFILE = "server.key" # Server Key
CA_CRT = "ca.crt" # Certificate Authority Cert

# Shared state
server_log_widget = None
client_log_widget = None
friends_list_widget = None
download_dir = os.getcwd()
selected_filepath = None
command_queue = queue.Queue()
stop_file_server = False
friends_list = []
friend_requests = []
selected_friend = None
selected_friend_label = None
persistent_secure_socket = None
server_ssl_context = None
client_ssl_context = None
file_client_ssl_context = None
username = None

def get_ip():
    try:
        response = requests.get("http://api.ipify.org", timeout=5)
        response.raise_for_status()
        #print(response.text.strip())
        return response.text.strip()
    except requests.RequestException as e:
        return f"Unable to fetch public ip: {e}"
    
#default_host = get_ip()
default_host = '127.0.0.1'

def initialize_server_ssl_context():
    """Initializes the Server SSL context."""
    global server_ssl_context
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
    ssl_context.load_cert_chain(certfile=SERVER_CERTFILE, keyfile=SERVER_KEYFILE)
    ssl_context.load_verify_locations(CA_CRT)
    server_ssl_context = ssl_context 
    return ssl_context

def initialize_client_ssl_context():
    """Initializes the Client SSL context."""
    global client_ssl_context
    ssl_context = ssl.create_default_context()
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
    ssl_context.check_hostname = False
    ssl_context.load_verify_locations(CA_CRT)
    client_ssl_context = ssl_context 
    return ssl_context

def initialize_file_client_ssl_context():
    """Initializes the Client SSL context."""
    global file_client_ssl_context
    ssl_context = ssl.create_default_context()
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
    ssl_context.check_hostname = False
    ssl_context.load_verify_locations(CA_CRT)
    file_client_ssl_context = ssl_context 
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
    """Runs the P2P server with command handling and friends list validation."""
    global stop_file_server, download_dir
    context = initialize_server_ssl_context()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow port reuse
        server_socket.bind((host, port))
        server_socket.listen(5)
        server_socket.settimeout(1)  # Set a timeout of 1 second
        server_log_callback(f"Server listening on {host}:{port}")
        with context.wrap_socket(server_socket, server_side=True) as secure_socket:
            try:
                while not stop_file_server:
                    try:
                        conn, addr = secure_socket.accept()
                        server_log_callback(f"Connection established with {addr}")
                        threading.Thread(
                            target=handle_client,
                            args=(conn,),
                            daemon=True
                        ).start()
                    except socket.timeout:
                        # Timeout occurs every second, allowing the loop to check stop_file_server
                        continue
                    except ssl.SSLError as e:
                        server_log_callback(f"SSL error: {e}")
                    except OSError:  # Handle socket closure during shutdown
                        break
                    except Exception as e:  # Catch-all for any other exception
                        server_log_callback(f"Unexpected error: {e}")
            finally:
                secure_socket.close()
                server_socket.close()
                server_log_callback("Server stopped.")

def handle_client(conn):
    """Handles an incoming client connection with file integrity check using length-prefixed protocol."""
    global download_dir
    try:
        # Receive metadata length (4 bytes)
        metadata_length = int.from_bytes(conn.recv(4), 'big')

        # Receive and parse metadata
        metadata = conn.recv(metadata_length).decode()
        filename, expected_checksum, file_size = metadata.split("|")
        expected_checksum = int(expected_checksum)
        file_size = int(file_size)

        server_log_callback(f"Receiving file: {filename} ({file_size} bytes)")

        # Prepare to receive the file
        file_path = os.path.join(download_dir, filename)
        os.makedirs(download_dir, exist_ok=True)
        with open(file_path, "wb") as f:
            received_bytes = 0
            while received_bytes < file_size:
                chunk = conn.recv(BUFFER_SIZE)
                if not chunk:  # Connection closed unexpectedly
                    raise ConnectionError("Connection closed before file transfer completed.")
                f.write(chunk)
                received_bytes += len(chunk)

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
        stop_server()


def client(host, port, filename):
    """Runs the P2P client to send a file with integrity verification."""
    global file_client_ssl_context
    initialize_file_client_ssl_context()
    context = file_client_ssl_context

    try:
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure_socket:
                client_log_callback(f"Connected to {host}:{port}")

                # Calculate the file's CRC checksum and file size
                with open(filename, "rb") as f:
                    file_data = f.read()
                    checksum = zlib.crc32(file_data)
                    file_size = len(file_data)

                # Prepare and send length-prefixed metadata
                metadata = f"{os.path.basename(filename)}|{checksum}|{file_size}".encode()
                metadata_length = len(metadata)
                secure_socket.sendall(metadata_length.to_bytes(4, 'big'))  # Send metadata length (4 bytes)
                secure_socket.sendall(metadata)  # Send metadata

                # Send the file content
                with open(filename, "rb") as f:
                    while chunk := f.read(BUFFER_SIZE):
                        secure_socket.sendall(chunk)

                client_log_callback(f"File {filename} sent successfully.")
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
    try:
        while True:
            try:
                # Receive messages from the server
                message = receive_message()
                if not message:
                    break

                # Handle UPDATE_FRIENDS messages
                if message.startswith("UPDATE_FRIENDS|"):
                    try:
                        _, username, friends_data = message.split("|", 2)  # Allow the friends list to contain commas
                        update_friends_list(friends_list_widget, friends_data)
                        server_log_callback(f"Friends List Updated")
                    except ValueError:
                        server_log_callback("Error: Malformed UPDATE_FRIENDS message received.")

                # Handle FRIEND_REQUEST_DECLINED messages
                elif message.startswith("FRIEND_REQUEST_DECLINED"):
                    _, sender, recipient = message.split("|")
                    server_log_callback(f"Friend request from {sender} to {recipient} was declined.")

                elif message.startswith("FRIEND_REQUEST_SAVED"):
                    _, recipient = message.split("|")
                    server_log_callback(f"Friend Request Received: {recipient}")

                elif message.startswith("FRIEND_REQUEST_FAIL"):
                    _, error = message.split("|")
                    server_log_callback(f"{error}")

                # Handle FRIEND_REQUEST messages
                elif message.startswith("FRIEND_REQUEST"):
                    _, sender, recipient = message.split("|")
                    server_log_callback(f"Friend request received from {sender}.")
                    handle_friend_request(sender, recipient)

                elif message.startswith("REQUEST_FILE_TRANSFER"):
                    #format for message REQUEST_FILE_TRANSFER|{sender}|{recipient}|{filename}
                    handle_request_to_send(message)

                elif message.startswith("FILE_TRANSFER_ACCEPT"):
                    handle_request_to_send_accepted(message)
                
                elif message.startswith("FILE_TRANSFER_DECLINE"):
                    _, sender, recipient = message.split("|")
                    server_log_callback(f"File transfer request to {recipient} declined.")

                elif message.startswith("FILE_TRANSFER_FAIL"):
                    _, error = message.split("|")
                    client_log_callback(f"{error}")

                # Handle UPDATE_SUCCESS messages
                elif message.startswith("UPDATE_SUCCESS"):
                    server_log_callback("User Update Successful.")

                else:
                    # Log other incoming messages
                    server_log_callback(f"Received message: {message}")

            except Exception as e:
                server_log_callback(f"Error receiving or processing message: {e}")
                break

    except Exception as e:
        server_log_callback(f"Listener thread encountered an error: {e}")


def send_request_to_send():
    """Selects a file and sends a request to transfer it to a selected friend."""
    global selected_friend

    if selected_friend is None:
        messagebox.showwarning("Error", "No friend selected!")
        return

    file_path = select_file()
    if not file_path:
        messagebox.showwarning("Error", "No file selected!")
        return

    sender = username  # Replace with the actual sender username
    recipient = selected_friend
    filename = file_path.split("/")[-1]  # Extracts the file name from the file path

    formatted_message = f"REQUEST_FILE_TRANSFER|{sender}|{recipient}|{filename}"

    try:
        send_message(formatted_message)
        client_log_callback("Request to send has been sent")
    except ConnectionError as e:
        messagebox.showerror("Connection Error", f"Failed to send request: {e}")
    except Exception as e:
        messagebox.showerror("Error", f"An unexpected error occurred: {e}")
    

def handle_request_to_send(message):
    """Opens a Tkinter dialog box to ask the user to accept or reject a file transfer request."""
    _, sender, recipient, filename = message.split("|")

    def on_rts_accept():
        # User accepts the file transfer request
        start_server()
        send_message(f"FILE_TRANSFER_ACCEPT|{sender}|{recipient}|{default_host}|{DEFAULT_PORT}")
        client_log_callback(f"File Transfer Request from {sender} accepted.")
        root.destroy()  # Close the dialog box

    def on_rts_decline():
        # User declines the file transfer request
        send_message(f"FILE_TRANSFER_DECLINE|{sender}|{recipient}")
        client_log_callback(f"File Transfer Request from {sender} declined.")
        root.destroy()  # Close the dialog box

    # Create a simple dialog box
    root = tk.Tk()
    root.title("File Transfer Request")
    root.geometry("300x150")
    tk.Label(root, text=f"File Transfer Request from {sender}\nFilename: {filename}", font=("Arial", 14)).pack(pady=20)

    # Buttons for Accept and Decline
    button_frame = tk.Frame(root)
    button_frame.pack(pady=10)

    accept_button = tk.Button(button_frame, text="Accept", command=on_rts_accept, width=10, bg="green", fg="white")
    accept_button.pack(side=tk.LEFT, padx=10)

    decline_button = tk.Button(button_frame, text="Decline", command=on_rts_decline, width=10, bg="red", fg="white")
    decline_button.pack(side=tk.RIGHT, padx=10)

    # Run the dialog box
    root.mainloop()

def handle_request_to_send_accepted(message):
    """
    Handles a file transfer acceptance with the format:
    FILE_TRANSFER_ACCEPT|{sender}|{recipient}|{recipient_ip}|{recipient_port}
    and starts the P2P client to send the selected file to the recipient.
    """
    global selected_filepath

    try:
        # Parse the incoming message
        parts = message.split("|")
        if len(parts) != 5:
            client_log_callback(f"Invalid message format: {message}")
            return

        action, sender, recipient, recipient_ip, recipient_port = parts

        # Ensure the action is valid
        if action != "FILE_TRANSFER_ACCEPT":
            client_log_callback(f"Invalid action in message: {action}")
            return

        # Ensure a file was previously selected
        if not selected_filepath:
            client_log_callback("No file selected to send.")
            return

        # Convert port to integer
        recipient_port = int(recipient_port)

        # Start the P2P client to send the file
        client_log_callback(
            f"Starting file transfer to {recipient} at {recipient_ip}:{recipient_port} with file {selected_filepath}"
        )
        #client(recipient_ip, recipient_port, selected_filepath)
        client(default_host, DEFAULT_PORT, selected_filepath)

    except ValueError as ve:
        client_log_callback(f"Invalid port in message: {ve}")
    except Exception as e:
        client_log_callback(f"Error handling file transfer acceptance: {e}")


def process_friend_requests():
    """Processes each friend request one by one and removes it from the list after handling."""
    global friend_requests

    if not friend_requests:
        return  # No friend requests to process

    # Get the first request from the list
    next_request = friend_requests.pop(0)

    # Assume the request is from 'next_request' to the current user
    handle_friend_request(next_request, username)

    # After handling the request, continue to the next one
    process_friend_requests()


def handle_friend_request(sender, recipient):
    """Opens a Tkinter dialog box to ask the user to accept or reject a friend request."""
    def on_accept():
        # User accepts the friend request
        send_message(f"FRIEND_REQUEST_ACCEPT|{sender}|{recipient}")
        server_log_callback(f"Friend request from {sender} accepted.")
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


def send_friend_request():
    """ Sends a friend request to the server and handles the response. """
    global friends_list
    try:
        # Ensure the persistent connection is established
        if persistent_secure_socket is None:
            raise ConnectionError("No active connection to the server.")
        
        sender = username
        # Send friend request
        recipient = simpledialog.askstring("Add Friend", "Enter friend's name:")
        if recipient is None:
            return
        elif recipient in friends_list:
            server_log_callback(f"{recipient} already in friends list.")
            return
        
        request_message = f"ADD_FRIEND|{sender}|{recipient}"
        send_message(request_message)
        client_log_callback(f"Friend Request Sent to {recipient}.")

    except ConnectionError as e:
        return f"Connection error: {e}"
    except Exception as e:
        return f"An error occurred while processing the friend request: {e}"

def remove_friend():
    global friends_list  # Reference the global friends list
    sender = username

    try:
        # Get the selected friend from the Listbox
        selected_friend = friends_list_widget.get(tk.ACTIVE)
        if not selected_friend:
            messagebox.showerror("Error", "No friend selected!")
            return

        # Check if the selected friend exists in friends_list
        if selected_friend in friends_list:
            # Send the message to the server
            try:
                message = f"REMOVE_FRIEND|{sender}|{selected_friend}"
                send_message(message)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to notify the server: {e}")
                return

            # Remove the selected friend from friends_list
            #friends_list.remove(selected_friend)

            # Update the friends list UI
            #update_friends_list(friends_list_widget, ",".join(friends_list))

            messagebox.showinfo("Success", f"{selected_friend} has been removed from your friends list.")
        else:
            messagebox.showerror("Error", f"{selected_friend} is not in your friends list.")

    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

def update_friends_list(friends_list_widget, received_friends):
    """
    Updates the friends list UI widget with the received friends list and stores it in the global friends_list.
    
    :param friends_list_widget: The Tkinter widget displaying the friends list.
    :param received_friends: Comma-separated string or a list of friends received from the server.
    """
    global friends_list  # Reference the global variable

    # Ensure received_friends is a list
    if isinstance(received_friends, str):
        # Clear the existing friends list
        friends_list.clear()
        friends_list.extend(received_friends.split(","))  # Convert from string
    elif isinstance(received_friends, list):
        friends_list = received_friends  # Use list directly
    else:
        raise TypeError("received_friends must be a string or a list")
    
    # Clear the existing list in the widget
    friends_list_widget.delete(0, tk.END)

    # Populate the widget with updated friends list
    for friend in friends_list:
        friends_list_widget.insert(tk.END, friend)

def start_server():
    """Starts the server in a separate thread."""
    global stop_file_server
    stop_file_server = False
    #host, port = get_host_and_port()
    host, port = '0.0.0.0', DEFAULT_PORT
    if host and port:
        threading.Thread(target=server, args=(host, port), daemon=True).start()
        server_log_callback(f"Server listening on {host}:{port}. Files will be saved to {download_dir}.")

def stop_server():
    """Stops the server gracefully."""
    global stop_file_server
    stop_file_server = True
    #server_log_callback("Server stop requested.")

def select_download_dir():
    """Opens a directory selection dialog to choose the download directory."""
    selected_dir = filedialog.askdirectory(title="Select Download Directory")
    if selected_dir:
        global download_dir
        download_dir = selected_dir
        command_queue.put(("set_download_dir", selected_dir))
        server_log_callback(f"Download directory set to: {download_dir}")

def select_file():
    """Opens a file dialog to select file."""
    global selected_filepath
    file_path = filedialog.askopenfilename(title="Select a File")
    selected_filepath = file_path
    if file_path:
        client_log_callback(f"Selected file: {file_path}")
        return file_path


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
        
        initialize_client_ssl_context()

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
        global username, friends_list, friend_requests

        user = username_entry.get()
        password = password_entry.get()

        if not user or not password:
            messagebox.showwarning("Input Error", "Please enter both username and password.")
            return

        try:
            # Send login request
            send_message(f"LOGIN|{user}|{password}")

            # Receive response
            response = receive_message()

            # Expected response format: "LOGIN_SUCCESS|username|friend1,friend2|request1,request2"
            if response.startswith(f"LOGIN_SUCCESS|{user}|"):
                try:
                    _, username, friends_data, requests_data = response.split("|", 3)
    
                    # Parse friends list (if empty, set to an empty list)
                    friends_list = friends_data.split(",") if friends_data else []

                    # Parse friend requests (if empty, set to an empty list)
                    friend_requests = requests_data.split(",") if requests_data else []

                    login_success = True
                    messagebox.showinfo("Login Successful", "Welcome!")
                    login_window.destroy()
                except ValueError:
                    messagebox.showerror("Error", "Invalid login response format.")
            elif response == f"LOGIN_FAIL|{user}":
                messagebox.showerror("Login Failed", "Invalid username or password.")
            else:
                messagebox.showerror("Error", "An error occurred during login.")
        except Exception as e:
            messagebox.showerror("Error", f"Connection failed: {e}")

    def attempt_register():
        user = username_entry.get()
        password = password_entry.get()

        if not user or not password:
            messagebox.showwarning("Input Error", "Please enter both username and password.")
            return

        #ip = socket.gethostbyname(socket.gethostname())  # Replace with actual client IP or retrieve dynamically
        port = DEFAULT_PORT  # Replace with actual client port

        try:
            register_message = f"REGISTER|{user}|{password}|{default_host}|{port}"
            send_message(register_message)

            # Receive response
            response = receive_message()
            if response == f"REGISTER_SUCCESS|{user}":
                messagebox.showinfo("Registration Successful", "You can now log in.")
            elif response.startswith(f"REGISTER_FAIL|{user}"):
                messagebox.showerror("Registration Failed", "User already exists or another issue occurred.")
            else:
                messagebox.showerror("Error", f"An error occurred during registration. {response}")
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
    tk.Button(login_window, text="Register", command=attempt_register).grid(row=3, column=0, columnspan=2, pady=10)
    
    login_window.mainloop()
    return login_success


def send_periodic_updates():
    """Sends periodic updates to the user data server."""
    def update():
        while True:
            try:
                # Establish persistent connection if not already connected
                connect_persistent(USER_DATA_SERVER_HOST, USER_DATA_SERVER_PORT)

                # Send update request
                ip = socket.gethostbyname(socket.gethostname())
                message = f"UPDATE|{username}|{ip}|{DEFAULT_PORT}"
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
        server_log_callback(f"Active Users: {active_users}")
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


def select_friend():
    global selected_friend
    try:
        # Get the currently selected friend from the ListBox
        selected_friend = friends_list_widget.get(friends_list_widget.curselection())
        # Update the persistent label to notify the user
        selected_friend_label.config(text=f"Selected Friend: {selected_friend}")
    except tk.TclError:
        # Handle the case where no friend is selected
        messagebox.showwarning("Selection Error", "No friend selected!")

# GUI Initialization
def main():
    global server_log_widget, client_log_widget, friends_list_widget, host_entry, port_entry, selected_friend, selected_friend_label
    #initialize_client_ssl_context()

    if not connect_persistent(USER_DATA_SERVER_HOST, USER_DATA_SERVER_PORT):
        messagebox.showerror("Error","Failed to Connect to User Server")
        sys.exit(1)
            
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
    tk.Button(root, text="Select Download Directory", command=select_download_dir).grid(row=3, column=0, padx=10, pady=5)
    #tk.Button(root, text="Start", command=start_server).grid(row=4, column=0, padx=10, pady=5)
    #tk.Button(root, text="Stop", command=stop_server).grid(row=5, column=0, padx=10, pady=5)
    
    # Client Section
    tk.Label(root, text="Send").grid(row=1, column=1, padx=10, pady=5, sticky="w")
    client_log_widget = tk.Text(root, height=10, width=50, state="disabled")
    client_log_widget.grid(row=2, column=1, padx=10, pady=5)
    tk.Button(root, text="Select File & Send", command=send_request_to_send).grid(row=3, column=1, padx=10, pady=5)
    tk.Button(root, text="Select Directory & Send", command=select_and_send_directory).grid(row=4, column=1, padx=10, pady=5)
    tk.Button(root, text="Get Active Users", command=get_active_users).grid(row=5, column=1, padx=10, pady=5)
    #tk.Button(root, text="Disconnect From User Server", command=disconnect_persistent).grid(row=5, column=1, padx=10, pady=5)

    # Friends List Section
    tk.Label(root, text="Friends List").grid(row=5, column=0, padx=10, pady=5, sticky="w")
    friends_list_widget = tk.Listbox(root, height=10, width=50)
    friends_list_widget.grid(row=6, column=0, padx=10, pady=5)
    tk.Button(root, text="Add Friend", command=send_friend_request).grid(row=7, column=0, padx=10, pady=5)
    tk.Button(root, text="Remove Friend", command=remove_friend).grid(row=8, column=0, padx=10, pady=5)
    tk.Button(root, text="Select Friend", command=select_friend).grid(row=9, column=0, padx=10, pady=5)
    selected_friend_label = tk.Label(root, text="Selected Friend: None", fg="blue")
    selected_friend_label.grid(row=10, column=0, padx=10, pady=5, sticky="w")

    # Update UI with friends
    root.after(100, process_friend_requests)
    update_friends_list(friends_list_widget, friends_list)

    # Host and Port Configuration
    tk.Label(root, text="Host:").grid(row=6, column=0, padx=10, pady=5, sticky="e")
    host_entry = tk.Entry(root)
    host_entry.insert(0, default_host)
    host_entry.grid(row=6, column=1, padx=10, pady=5, sticky="w")

    tk.Label(root, text="Port:").grid(row=7, column=0, padx=10, pady=5, sticky="e")
    port_entry = tk.Entry(root)
    port_entry.insert(0, str(DEFAULT_PORT))
    port_entry.grid(row=7, column=1, padx=10, pady=5, sticky="w")

    #root.protocol("WM_DELETE_WINDOW", disconnect_persistent())
    root.mainloop()

if __name__ == "__main__":
    main()