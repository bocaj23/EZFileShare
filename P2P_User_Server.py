import socket
import threading
import json
import ssl
import tkinter as tk

# Constants
HOST = '127.0.0.1'
PORT = 5000
USER_DATA_FILE = "data.json" # Stored User Data
BUFFER_SIZE = 1024
CERTFILE = "server.crt"
KEYFILE = "server.key"
CA_CRT = "ca.crt"

server_socket = None
server_running = False

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
    try:
        with open(USER_DATA_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        server_log_callback(f"User data file {USER_DATA_FILE} not found. Creating a default one.")
        default_data = {"admin": "password"}
        with open(USER_DATA_FILE, "w") as f:
            json.dump(default_data, f)
        return default_data
    except json.JSONDecodeError:
        server_log_callback(f"Error decoding {USER_DATA_FILE}. Ensure it is valid JSON.")
        return {}

USER_DATABASE = load_user_data()

def handle_login_request(conn, data):
    """Handles login requests from the client."""
    try:
        username, password = data.split("|")
        if username in USER_DATABASE and USER_DATABASE[username] == password:
            conn.sendall(b"LOGIN_SUCCESS")
        else:
            conn.sendall(b"LOGIN_FAIL")
    except Exception as e:
        conn.sendall(b"LOGIN_ERROR")
        server_log_callback(f"Error during login request handling: {e}")

def handle_client(conn, addr):
    """Handles an incoming client connection with support for persistent connections."""
    try:
        server_log_callback(f"Connection established with {addr}")

        while True:  # Keep the connection alive for multiple requests
            try:
                request = conn.recv(BUFFER_SIZE).decode()
                if not request:  # Client disconnected
                    break

                if request == "LOGIN":
                    login_data = conn.recv(BUFFER_SIZE).decode()
                    handle_login_request(conn, login_data)

                elif request.startswith("update|"):  # Handle periodic updates
                    server_log_callback(f"Periodic update received: {request}")
                    conn.sendall(b"UPDATE_SUCCESS")

                elif request == "DISCONNECT":  # Handle client-initiated disconnect
                    server_log_callback(f"Client {addr} requested disconnection.")
                    break

                else:
                    server_log_callback(f"Unknown request type: {request}")
                    conn.sendall(b"UNKNOWN_REQUEST")
            
            except Exception as e:
                server_log_callback(f"Error processing request from {addr}: {e}")
                break

    except Exception as e:
        server_log_callback(f"Connection error with {addr}: {e}")
    finally:
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
            context.load_verify_locations(CA_CRT)
            context.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)

            # Create and bind socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.bind((HOST, PORT))
            server_socket.listen(5)
            server_log_callback(f"Server started on {HOST}:{PORT}")

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