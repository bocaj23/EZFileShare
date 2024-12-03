import socket
import threading
import json
import ssl
import tkinter as tk
from threading import Lock
import bcrypt

# Constants
PORT = 5000
USER_DATA_FILE = "data.json" # Stored User Data
BUFFER_SIZE = 1024
CERTFILE = "server.crt"
KEYFILE = "server.key"
CA_CRT = "ca.crt"

host = None
server_socket = None
server_running = False
active_users = {}
active_users_lock = Lock()
user_database = None

def get_machine_ip():
    """Returns the IP address of the machine."""
    try:
        # Create a socket connection to determine the IP address
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.gaierror as e:
        print(f"Error getting the machine's IP address: {e}")
        return None

#host = get_machine_ip()
host = '127.0.0.1'

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

def load_user_data():
    """Loads user data from a JSON file."""
    global user_database
    try:
        with open(USER_DATA_FILE, "r") as f:
            user_database = json.load(f)
    except FileNotFoundError:
        server_log_callback(f"User data file {USER_DATA_FILE} not found. Creating a default one.")
        default_data = {
            "admin": {
                "password": "password",
                "ip": "127.0.0.1",
                "port": 5001
            }
        }
        with open(USER_DATA_FILE, "w") as f:
            json.dump(default_data, f, indent=4)
        
    except json.JSONDecodeError:
        server_log_callback(f"Error decoding {USER_DATA_FILE}. Ensure it is valid JSON.")
        user_database = {}


def handle_register_request(conn, register_message):
    """Handles a REGISTER request and stores user data in a JSON file."""
    global user_database
    try:
        # Parse the register message
        parts = register_message.split("|")
        if len(parts) != 5 or parts[0] != "REGISTER":
            raise ValueError("Invalid registration message format.")
        
        _, user, password, ip, port = parts

        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        # Prepare user data
        user_data = {
            "password": hashed_password,
            "ip": ip,
            "port": int(port)
        }

        # Load existing data
        try:
            with open(USER_DATA_FILE, "r") as file:
                data = json.load(file)
        except FileNotFoundError:
            data = {}

        # Check if the user already exists
        if user in data:
            conn.sendall(f"REGISTER_FAIL|{user}|User '{user}' already exists.".encode())

        # Update data with new user
        data[user] = user_data

        # Write updated data back to the file
        with open(USER_DATA_FILE, "w") as file:
            json.dump(data, file, indent=4)
        
        user_database = load_user_data()

        conn.sendall(f"REGISTER_SUCCESS|{user}".encode())

    except Exception as e:
        conn.sendall(f"REGISTER_FAIL|{user}|{str(e)}".encode())


def handle_login_request(conn, request, addr):
    """Handles login requests from the client."""
    global user_database
    try:

        load_user_data()

        request_type, username, password = request.split("|")

        # Retrieve user data
        user_data = user_database.get(username)

        # Verify the password using bcrypt
        if user_data and bcrypt.checkpw(password.encode(), user_data["password"].encode()):
            with active_users_lock:
                active_users[username] = {"ip": addr[0], "port": addr[1], "conn": conn}
            server_log_callback(f"User {username} logged in from {addr}")
            response = f"LOGIN_SUCCESS|{username}"
        else:
            response = f"LOGIN_FAIL|{username}"

        # Send the response
        conn.sendall(response.encode())

    except Exception as e:
        conn.sendall(b"LOGIN_ERROR")
        server_log_callback(f"Error during login request handling: {e}")

def handle_update_request(conn, message):
    """Handles update requests to modify user data."""
    global user_database
    try:
        # Parse the update message (format: update|<username>|<ip>|<port>)
        parts = message.split("|")
        if len(parts) != 4 or parts[0] != "update":
            conn.sendall(b"INVALID_UPDATE_REQUEST")
            return

        _, username, ip, port = parts

        if username in user_database:
            # Update user data
            user_database[username]["ip"] = ip
            user_database[username]["port"] = int(port)

            # Save the updated user data to file
            with open(USER_DATA_FILE, "w") as f:
                json.dump(user_database, f, indent=4)

            server_log_callback(f"User {username}'s data updated: IP={ip}, PORT={port}")
            conn.sendall(b"UPDATE_SUCCESS")
        else:
            conn.sendall(b"USER_NOT_FOUND")
    except Exception as e:
        server_log_callback(f"Error handling update request: {e}")
        conn.sendall(b"UPDATE_ERROR")

def handle_add_friend_request(sender, recipient):
    """Handles an add friend request."""
    try:
        # Load user data from the file
        try:
            with open(USER_DATA_FILE, "r") as file:
                user_data = json.load(file)
        except FileNotFoundError:
            server_log_callback("User data file not found.")
            return

        # Check if recipient exists in user data
        if recipient not in user_data:
            with active_users_lock:
                sender_conn = active_users[sender]["conn"]
            sender_conn.sendall(f"FRIEND_REQUEST_FAIL|User {recipient} does not exist.".encode())
            server_log_callback(f"Friend request from {sender} failed: User {recipient} does not exist.")
            return

        # Check if recipient is online
        with active_users_lock:
            if recipient in active_users:
                recipient_conn = active_users[recipient]["conn"]
                # Forward the friend request
                friend_request_message = f"FRIEND_REQUEST|{sender}|{recipient}"
                recipient_conn.sendall(friend_request_message.encode())
                server_log_callback(f"Friend request from {sender} forwarded to {recipient}.")
            else:
                sender_conn = active_users[sender]["conn"]
                sender_conn.sendall(b"FRIEND_REQUEST_FAIL|Recipient not online.")
                server_log_callback(f"Failed to send friend request from {sender} to {recipient}: Recipient not online.")
    except ValueError:
        server_log_callback(f"Invalid message format for friend request from {sender} to {recipient}.")
    except KeyError:
        with active_users_lock:
            sender_conn = active_users[sender]["conn"]
        sender_conn.sendall(f"Error: User {recipient} is not active.".encode())
    except Exception as e:
        server_log_callback(f"Error handling friend request from {sender} to {recipient}: {e}")

def handle_remove_friend(message):
    """
    Handles forwarding a message from sender to recipient.
    
    :param message: The incoming message in the format "ACTION|SENDER|RECIPIENT|..."
    :param active_users: Dictionary of active users with connection details.
    :param active_users_lock: Lock to ensure thread-safe access to active_users.
    :param server_log_callback: Function to log server events.
    """
    try:
        # Parse the incoming message
        parts = message.split("|")
        if len(parts) < 3:
            server_log_callback(f"Invalid message format: {message}")
            return

        action, sender, recipient = parts[:3]

        # Ensure the action is valid
        if action not in ("FRIEND_REQUEST_ACCEPT", "FRIEND_REQUEST_DECLINE", "REMOVE_FRIEND"):
            server_log_callback(f"Invalid action in message: {action}")
            return

        sender_conn = None
        recipient_conn = None

        # Access active users safely
        with active_users_lock:
            sender_conn = active_users.get(sender, {}).get("conn")
            recipient_conn = active_users.get(recipient, {}).get("conn")

        if not sender_conn:
            server_log_callback(f"Sender {sender} is not online. Cannot forward response.")
            return

        if not recipient_conn:
            server_log_callback(f"Recipient {recipient} is not online. Cannot forward response.")
            return

        # Forward the message to the recipient
        recipient_conn.sendall(message.encode())
        server_log_callback(f"Message forwarded from {sender} to {recipient}: {message}")

    except Exception as e:
        server_log_callback(f"Error handling forward message: {e}")

def handle_friend_response(message):
    """Handles a friend request response with the format FRIEND_REQUEST_ACCEPT|{sender}|{recipient} 
    or FRIEND_REQUEST_DECLINE|{sender}|{recipient}."""
    try:
        # Parse the incoming message
        parts = message.split("|")
        if len(parts) < 3:
            server_log_callback(f"Invalid message format: {message}")
            return

        action, sender, recipient = parts[:3]

        # Ensure the action is valid
        if action not in ("FRIEND_REQUEST_ACCEPT", "FRIEND_REQUEST_DECLINE"):
            server_log_callback(f"Invalid action in message: {action}")
            return

        sender_conn = None
        recipient_conn = None

        # Access active users safely
        with active_users_lock:
            if sender in active_users:
                sender_conn = active_users[sender]["conn"]
            else:
                server_log_callback(f"Sender {sender} is not online. Cannot forward response.")
                return

            if recipient in active_users:
                recipient_conn = active_users[recipient]["conn"]
            else:
                server_log_callback(f"Recipient {recipient} is not online. Cannot forward response.")
                return

        # Handle ACCEPT or DECLINE responses
        if action == "FRIEND_REQUEST_ACCEPT":
            try:
                # Fetch sender's and recipient's information from data.json
                with open("data.json", "r") as user_file:
                    user_data = json.load(user_file)
                    sender_data = user_data.get(sender)
                    recipient_data = user_data.get(recipient)

                if sender_data and recipient_data:
                    sender_ip = sender_data["ip"]
                    sender_port = sender_data["port"]
                    recipient_ip = recipient_data["ip"]
                    recipient_port = recipient_data["port"]

                    # Notify the sender with recipient's information
                    sender_response = f"FRIEND_REQUEST_ACCEPTED|{sender}|{recipient}|{recipient_ip}|{recipient_port}"
                    sender_conn.sendall(sender_response.encode())
                    server_log_callback(f"Friend request accepted by {recipient}. Info sent to {sender}.")

                    # Notify the recipient with sender's information
                    recipient_response = f"FRIEND_REQUEST_ACCEPTED|{sender}|{recipient}|{sender_ip}|{sender_port}"
                    recipient_conn.sendall(recipient_response.encode())
                    server_log_callback(f"Sender {sender}'s info sent to {recipient}.")
                else:
                    error_message = f"FRIEND_REQUEST_FAIL|{sender}|Recipient or sender data not found"
                    sender_conn.sendall(error_message.encode())
            except Exception as e:
                server_log_callback(f"Error reading user data or sending response: {e}")

        elif action == "FRIEND_REQUEST_DECLINE":
            try:
                # Notify the sender of the declined request
                response_message = f"FRIEND_REQUEST_DECLINED|{sender}|{recipient}"
                sender_conn.sendall(response_message.encode())
                server_log_callback(f"Friend request declined by {recipient}. Notification sent to {sender}.")
            except Exception as e:
                server_log_callback(f"Error sending decline notification: {e}")

    except Exception as e:
        server_log_callback(f"Error handling friend request response: {e}")

def handle_client(conn, addr):
    """Handles an incoming client connection with support for persistent connections."""
    global user_database
    username = None
    try:
        server_log_callback(f"Connection established with {addr}")

        while True:
            try:
                request = conn.recv(BUFFER_SIZE).decode()
                if not request:
                    break

                if request.startswith("LOGIN"):
                    handle_login_request(conn, request, addr)
                    username = request.split('|')[1]
                elif request.startswith("REGISTER|"):  # Handle periodic updates
                    server_log_callback(f"Register request received: {request}")
                    handle_register_request(conn, request)

                elif request.startswith("UPDATE|"):  # Handle periodic updates
                    server_log_callback(f"Periodic update received: {request}")
                    handle_update_request(conn, request)

                elif request.startswith("ADD_FRIEND|"):  # Handle add friend requests
                    _, sender, recipient = request.split("|")
                    handle_add_friend_request(sender, recipient)
                
                elif request.startswith("REMOVE_FRIEND|"):
                    handle_remove_friend(request)

                elif request.startswith("FRIEND_REQUEST_ACCEPT|"):  # Handle friend request responses
                    #conn.sendall(b"Friend Request Received")
                    #f"FRIEND_REQUEST_ACCEPT|{sender}|{recipient}"
                    handle_friend_response(request)
                    
                elif request.startswith("FRIEND_REQUEST_DECLINE|"):
                    #f"FRIEND_REQUEST_DECLINE|{sender}|{recipient}"
                    handle_friend_response(request)

                elif request == "DISCONNECT":  # Handle client-initiated disconnect
                    server_log_callback(f"Client {addr} requested disconnection.")
                    break

                elif request == "GET_ACTIVE_USERS":  # Respond with a list of active users
                    with active_users_lock:
                        active_users_list = json.dumps(active_users)
                    conn.sendall(active_users_list.encode())

                else:
                    server_log_callback(f"Unknown request type: {request}")
                    conn.sendall(b"UNKNOWN_REQUEST")

            except Exception as e:
                server_log_callback(f"Error processing request from {addr}: {e}")
                break

    except Exception as e:
        server_log_callback(f"Connection error with {addr}: {e}")
    finally:
        if username:
            # Remove user from active users list on disconnect
            with active_users_lock:
                if username in active_users:
                    del active_users[username]
            server_log_callback(f"User {username} disconnected")
        conn.close()
        server_log_callback(f"Connection closed with {addr}")

def start_server_thread():
    """Starts the server in a separate thread."""
    global server_running, server_socket
    server_running = True

    def run_server():
        global server_socket
        try:
            # SSL context setup
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_verify_locations(CA_CRT)
            context.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)

            # Create and bind socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.bind((host, PORT))
            server_socket.listen(5)
            server_log_callback(f"Server started on {host}:{PORT}")

            while server_running:
                try:
                    server_socket.settimeout(1)  # Timeout to periodically check server_running
                    conn, addr = server_socket.accept()
                    secure_conn = context.wrap_socket(conn, server_side=True)
                    threading.Thread(target=handle_client, args=(secure_conn, addr), daemon=True).start()
                except socket.timeout:
                    continue  # Check server_running again
                except OSError as e:
                    if server_running:  # Log only if the server wasn't already stopped
                        server_log_callback(f"Server socket error: {e}")
                        break
        except Exception as e:
            server_log_callback(f"Server error: {e}")
        finally:
            if server_socket:
                server_socket.close()
                server_socket = None
            server_log_callback("Server stopped.")

    threading.Thread(target=run_server, daemon=True).start()

def stop_server():
    """Stops the server cleanly."""
    global server_running, server_socket
    if server_running:
        server_running = False  # Signal the server thread to stop
        if server_socket:
            try:
                server_socket.close()  # Close the server socket
            except Exception as e:
                server_log_callback(f"Error while closing server socket: {e}")
            finally:
                server_socket = None
        server_log_callback("Server stopping...")

def start_server_button_callback():
    """Callback for the Start Server button."""
    start_button.config(state="disabled")
    stop_button.config(state="normal")
    start_server_thread()

def stop_server_button_callback():
    """Callback for the Stop Server button."""
    stop_server()
    start_button.config(state="normal")
    stop_button.config(state="disabled")

def on_close():
    """Handle window close event."""
    stop_server()  # Ensure the server is stopped
    root.destroy()  # Destroy the GUI window

# Tkinter UI
root = tk.Tk()
root.title("EZFileShare User Server")

# Server Control Section
control_frame = tk.Frame(root)
control_frame.pack(pady=10)

start_button = tk.Button(control_frame, text="Start Server", command=start_server_button_callback)
start_button.pack(side=tk.LEFT, padx=5)

stop_button = tk.Button(control_frame, text="Stop Server", command=stop_server_button_callback, state="disabled")
stop_button.pack(side=tk.LEFT, padx=5)

# Server Log Section
tk.Label(root, text="Server Log:").pack(anchor="w", padx=10)
server_log_widget = tk.Text(root, height=15, width=60, state="disabled")
server_log_widget.pack(padx=10, pady=5)

# Run the Tkinter main loop
root.protocol("WM_DELETE_WINDOW", on_close)  # Stop server on window close
root.mainloop()