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

# Constants
DEFAULT_HOST = '127.0.0.1' # Default Host for File Transfer
DEFAULT_PORT = 65432 # Default Port for File Transfer
USER_DATA_SERVER_HOST = '127.0.0.1' # Host for the user data server
#USER_DATA_SERVER_HOST = '192.168.56.1'
USER_DATA_SERVER_PORT = 5000         # Port for the user data server
BUFFER_SIZE = 4096
CLIENT_CERTFILE = "client.crt" # Client Cert Signed with CA Key and Cert
CLIENT_KEYFILE = "client.key" # Client Key
SERVER_CERTFILE = "server.crt" # Server Cert Signed with CA Key and Cert
SERVER_KEYFILE = "server.key" # Server Key
CA_CRT = "ca.crt" # Certificate Authority Cert
friendfile = "friends.json"

# Shared state
server_log_widget = None
client_log_widget = None
friends_list_widget = None
download_dir = os.getcwd()
selected_filepath = None
command_queue = queue.Queue()
stop_file_server = False
friends_list = {}
selected_friend = None
selected_friend_label = None
persistent_secure_socket = None
server_ssl_context = None
client_ssl_context = None
file_client_ssl_context = None
username = None

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
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
    ssl_context.load_cert_chain(certfile=CLIENT_CERTFILE, keyfile=CLIENT_KEYFILE)
    ssl_context.load_verify_locations(CA_CRT)
    client_ssl_context = ssl_context 
    return ssl_context

def initialize_file_client_ssl_context():
    """Initializes the Client SSL context."""
    global file_client_ssl_context
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
    ssl_context.load_cert_chain(certfile=CLIENT_CERTFILE, keyfile=CLIENT_KEYFILE)
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

                # Handle FRIEND_REQUEST_ACCEPTED messages
                if message.startswith("FRIEND_REQUEST_ACCEPTED"):
                    _, sender, recipient, ip, port = message.split("|")
                    handle_friend_request_accepted(sender, recipient, ip, port)
                    client_log_callback(f"Friend request from {sender} to {recipient} was accepted.")

                # Handle FRIEND_REQUEST_DECLINED messages
                elif message.startswith("FRIEND_REQUEST_DECLINED"):
                    _, sender, recipient = message.split("|")
                    client_log_callback(f"Friend request from {sender} to {recipient} was declined.")
                
                elif message.startswith("FRIEND_REQUEST_FAIL"):
                    _, error = message.split("|")
                    client_log_callback(f"{error}")

                # Handle FRIEND_REQUEST messages
                elif message.startswith("FRIEND_REQUEST"):
                    _, sender, recipient = message.split("|")
                    client_log_callback(f"Friend request received from {sender}.")
                    handle_friend_request(sender, recipient)

                elif message.startswith("REMOVE_FRIEND"):
                    _, sender, recipient = message.split("|")
                    handle_remove_friend(sender)

                elif message.startswith("REQUEST_FILE_TRANSFER"):
                    #format for message REQUEST_FILE_TRANSFER|{sender}|{recipient}|{filename}
                    handle_request_to_send(message)

                elif message.startswith("FILE_TRANSFER_ACCEPT"):
                    handle_request_to_send_accepted(message)
                
                elif message.startswith("FILE_TRANSFER_DECLINE"):
                    _, sender, recipient = message.split("|")
                    client_log_callback(f"File transfer request to {recipient} declined.")

                elif message.startswith("FILE_TRANSFER_FAIL"):
                    _, error = message.split("|")
                    client_log_callback(f"{error}")

                # Handle UPDATE_SUCCESS messages
                elif message.startswith("UPDATE_SUCCESS"):
                    client_log_callback("User Update Successful.")

                else:
                    # Log other incoming messages
                    client_log_callback(f"Received message: {message}")

            except Exception as e:
                client_log_callback(f"Error receiving or processing message: {e}")
                break

    except Exception as e:
        client_log_callback(f"Listener thread encountered an error: {e}")


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

    # Load friend list from friends.json
    try:
        with open(friendfile, "r") as file:
            friends = json.load(file)
    except FileNotFoundError:
        client_log_callback("Friends file not found.")
        send_message(f"FILE_TRANSFER_DECLINE|{sender}|{recipient}")
        return
    except json.JSONDecodeError:
        client_log_callback("Invalid friends file format.")
        send_message(f"FILE_TRANSFER_DECLINE|{sender}|{recipient}")
        return

    # Check if the sender is in the friend list
    if sender not in friends:
        client_log_callback(f"File Transfer Request from {sender} automatically declined (not in friend list).")
        send_message(f"FILE_TRANSFER_DECLINE|{sender}|{recipient}")
        return

    def on_rts_accept():
        # User accepts the file transfer request
        start_server()
        send_message(f"FILE_TRANSFER_ACCEPT|{sender}|{recipient}|{DEFAULT_HOST}|{DEFAULT_PORT}")
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
        client(DEFAULT_HOST, DEFAULT_PORT, selected_filepath)

    except ValueError as ve:
        client_log_callback(f"Invalid port in message: {ve}")
    except Exception as e:
        client_log_callback(f"Error handling file transfer acceptance: {e}")


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


def handle_friend_request_accepted(sender, recipient, ip, port):
    """Handles the entire friend request accepted message."""
    try:
        if recipient == username:
            # Ensure required fields are present
            if not sender or not ip or not port:
                server_log_callback(f"Missing data in FRIEND_REQUEST_ACCEPTED message")
                return

            # Read existing friends from FRIENDS_FILE
            try:
                with open(friendfile, "r") as friends_file:
                    friends_data = json.load(friends_file)
            except FileNotFoundError:
                friends_data = {}

            # Add new friend data
            friends_data[sender] = {"ip": ip, "port": port}

            # Write back to FRIENDS_FILE
            with open(friendfile, "w") as friends_file:
                json.dump(friends_data, friends_file, indent=4)

            update_friends_list(friends_list_widget)
            server_log_callback(f"Added {sender} to friends list with IP {ip} and Port {port}.")

        else:
            # Ensure required fields are present
            if not recipient or not ip or not port:
                server_log_callback(f"Missing data in FRIEND_REQUEST_ACCEPTED message")
                return

            # Read existing friends from FRIENDS_FILE
            try:
                with open(friendfile, "r") as friends_file:
                    friends_data = json.load(friends_file)
            except FileNotFoundError:
                friends_data = {}

            # Add new friend data
            friends_data[recipient] = {"ip": ip, "port": port}

            # Write back to FRIENDS_FILE
            with open(friendfile, "w") as friends_file:
                json.dump(friends_data, friends_file, indent=4)

            update_friends_list(friends_list_widget)
            server_log_callback(f"Added {recipient} to friends list with IP {ip} and Port {port}.")

    except Exception as e:
        server_log_callback(f"Error processing FRIEND_REQUEST_ACCEPTED message: {e}")

def handle_remove_friend(sender):
    """
    Handles removing a sender from the friends list in the friends.json file.

    :param sender: The sender to remove from the friends file.
    :param server_log_callback: Function to log server events.
    """
    try:
        # Load the current friends data
        friends_data = {}
        try:
            with open(friendfile, "r") as file:
                friends_data = json.load(file)
        except FileNotFoundError:
            server_log_callback(f"Friends file not found. Cannot remove {sender}.")
            return

        # Check if the sender exists in the friends file
        if sender not in friends_data:
            server_log_callback(f"Sender {sender} not found in friends list.")
            return

        # Remove the sender
        del friends_data[sender]

        # Save the updated friends data
        with open(friendfile, "w") as file:
            json.dump(friends_data, file, indent=4)
        
        update_friends_list(friends_list_widget)

        server_log_callback(f"{sender} has unfriended you.")

    except Exception as e:
        server_log_callback(f"Error removing friend {sender}: {e}")

def load_friends():
    """Loads the friends list from the JSON file."""
    try:
        with open(friendfile, "r") as f:
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
        with open(friendfile, "w") as f:
            json.dump(friends, f, indent=4)
    except Exception as e:
        client_log_callback(f"Error saving friends list: {e}")

def send_friend_request():
    """ Sends a friend request to the server and handles the response. """
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
    sender = username
    try:
        # Get the selected friend from the Listbox
        selected_friend = friends_list_widget.get(tk.ACTIVE)
        if not selected_friend:
            messagebox.showerror("Error", "No friend selected!")
            return

        # Load the current friends data from the file
        try:
            with open(friendfile, "r") as file:
                friends_data = json.load(file)
        except FileNotFoundError:
            messagebox.showerror("Error", "Friends file not found.")
            return

        # Check if the selected friend exists in the file
        if selected_friend in friends_data:
            # Send the message to the server
            try:
                message = f"REMOVE_FRIEND|{sender}|{selected_friend}"
                send_message(message)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to notify the server: {e}")
                return

            # Remove the selected friend from the local file
            del friends_data[selected_friend]

            # Save the updated data back to the file
            with open(friendfile, "w") as file:
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
        with open(friendfile, "r") as f:
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
    global stop_file_server
    stop_file_server = False
    #host, port = get_host_and_port()
    host, port = DEFAULT_HOST, DEFAULT_PORT
    if host and port:
        threading.Thread(target=server, args=(host, port), daemon=True).start()
        server_log_callback(f"Server started on {host}:{port}. Files will be saved to {download_dir}.")

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
        global username
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
            if response == f"LOGIN_SUCCESS|{user}":
                login_success = True
                username = user
                messagebox.showinfo("Login Successful", "Welcome!")
                login_window.destroy()
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

        ip = socket.gethostbyname(socket.gethostname())  # Replace with actual client IP or retrieve dynamically
        port = DEFAULT_PORT  # Replace with actual client port

        try:
            register_message = f"REGISTER|{user}|{password}|{ip}|{port}"
            send_message(register_message)

            # Receive response
            response = receive_message()
            if response == f"REGISTER_SUCCESS|{user}":
                messagebox.showinfo("Registration Successful", "You can now log in.")
            elif response == f"REGISTER_FAIL|{user}|User '{user}' already exists.":
                messagebox.showerror("Registration Failed", f"User {user} already exists")
            elif response.startswith(f"REGISTER_FAIL|{user}"):
                messagebox.showerror("Registration Failed")
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