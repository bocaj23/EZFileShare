import os
import socket
import ssl
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
import queue
import zlib
import secrets
import string
import stat
from dataclasses import dataclass
import requests

# Constants
DEFAULT_PORT = 65432
BUFFER_SIZE = 4096
CERTFILE = "cert.pem"
KEYFILE = "key.pem"
AUTHCERTFILE = "authcert.pem"

def get_ip():
    try:
        response = requests.get("http://api.ipify.org", timeout=5)
        response.raise_for_status()
        return response.text.strip()
    except requests.RequestException as e:
        return f"Unable to fetch public ip: {e}"

def send_to_server(endpoint, username, password, identifier, ip, port):
    """Sends data to the remote server securely using an SSL socket."""
    server_host = "50.19.225.62"
    server_port = 6223
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    auth_cert_file = os.path.join(script_dir, "authcert.pem")

    if endpoint.upper() == "GET":
        payload = f"GET {username}\n"
    else:
        payload = f"{endpoint.upper()} {username} {password} {identifier} {ip} {port}\n"

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations(auth_cert_file)

    #client only sends one message and server sends one message back
    try:
        with socket.create_connection((server_host, server_port)) as sock:
            with context.wrap_socket(sock, server_hostname=server_host) as secure_sock:
                print("Connection established with the server.")
                
                secure_sock.sendall(payload.encode('utf-8'))
                print("Payload sent to server.")

                response = secure_sock.recv(BUFFER_SIZE).decode('utf-8', errors='ignore')
                print("Response received from server:", response)

                secure_sock.shutdown(socket.SHUT_RDWR)
                secure_sock.close()

                return response

    except ssl.SSLError as e:
        print(f"SSL error: {e}")
        return f"SSL Error: {e}"
    except Exception as e:
        print(f"Client error: {e}")
        return f"Error: {e}"




def create_tls_context():
    """Creates a TLS context."""
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)
    return context


def server(host, port, command_queue, server_log_callback):
    """Runs the P2P server with a command queue for dynamic behavior."""
    context = create_tls_context()
    current_dir = {"download_dir": os.getcwd()}  # Shared state

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
                            current_dir["download_dir"] = value
                            server_log_callback(f"Download directory changed to: {value}")
                except queue.Empty:
                    pass

                # Accept client connections
                try:
                    conn, addr = secure_socket.accept()
                    server_log_callback(f"Connection established with {addr}")
                    threading.Thread(
                        target=handle_client, 
                        args=(conn, current_dir, server_log_callback)
                    ).start()
                except ssl.SSLError as e:
                    server_log_callback(f"SSL error: {e}")


def handle_client(conn, current_dir, log_callback):
    """Handles an incoming client connection with file integrity check."""
    try:
        # Receive the filename and checksum
        metadata = conn.recv(BUFFER_SIZE).decode()
        if not metadata:
            return
        filename, expected_checksum = metadata.split("|")
        expected_checksum = int(expected_checksum)

        log_callback(f"Receiving file: {filename}")
        download_dir = current_dir["download_dir"]
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
            log_callback(f"File {filename} received successfully to {file_path} (Checksum Verified).")
        else:
            log_callback(f"File {filename} received to {file_path}, but checksum mismatch! Expected: {expected_checksum}, Got: {actual_checksum}")
    except Exception as e:
        log_callback(f"Error: {e}")
    finally:
        conn.close()

def client(host, port, filename, client_log_callback, recipiant_username):
    """Runs the P2P client to send a file with integrity verification."""
    try:
        # Send a request to the server and get the response
        response = send_to_server("GET", recipiant_username, None, None, None, None)  
        print(f"Server response: {response}")

        # Parse the response
        parts = response.split()
        if len(parts) != 5 or parts[0] != "GET-RESPONSE" or parts[1] != "VALID":
            raise ValueError("Invalid response format from server.")
        
        recipient_ip = parts[3]
        recipient_port = int(parts[4])
        client_log_callback(f"Recipient IP: {recipient_ip}, Port: {recipient_port}")
    except Exception as e:
        client_log_callback(f"Error processing server response: {e}")
        return

    # Prepare the SSL context
    script_dir = os.path.dirname(os.path.abspath(__file__))
    cert_file = os.path.join(script_dir, CERTFILE)

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations(cert_file)

    try:
        # Connect to the recipient using the extracted IP and port
        with socket.create_connection((recipient_ip, recipient_port)) as sock:
            with context.wrap_socket(sock, server_hostname=recipient_ip) as secure_socket:
                client_log_callback(f"Connected to {recipient_ip}:{recipient_port}")

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

                client_log_callback(f"File {filename} sent successfully.")
    except Exception as e:
        client_log_callback(f"Error during file transfer: {e}")


class P2PApp:
    @dataclass
    class login_state:
        username: str
        ip: str
        port: int
        logged_in: bool

    def __init__(self, root):
        self.root = root
        self.root.title("EZFileShare")
        self.login_state.logged_in = 0;

        # Command queue for server
        self.command_queue = queue.Queue()

        # Server Section
        tk.Label(root, text="Receive").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.server_log = tk.Text(root, height=10, width=50, state="disabled")
        self.server_log.grid(row=1, column=0, padx=10, pady=5)
        tk.Button(root, text="Start", command=self.start_server).grid(row=2, column=0, padx=10, pady=5)
        tk.Button(root, text="Select Download Directory", command=self.select_download_dir).grid(row=3, column=0, padx=10, pady=5)

        #Friends Section
        tk.Label(root, text="Friends").grid(row=4, column=0, padx=10, pady=5, sticky="w")

        # Username Section
        tk.Label(root, text="Username:").grid(row=4, column=0, padx=10, pady=5, sticky="e")
        self.username_entry = tk.Entry(root)
        self.username_entry.grid(row=4, column=1, padx=10, pady=5, sticky="w")

        # Login Section
        self.login_button = tk.Button(root, text="Login", command=self.login)
        self.login_button.grid(row=4, column=2, padx=10, pady=5, sticky="w")

        # Logout Section
        self.logout_button = tk.Button(root, text="Logout", command=self.logout)
        self.logout_button.grid(row=4, column=3, padx=10, pady=5, sticky="w")

        # Password Section
        tk.Label(root, text="Password:").grid(row=5, column=0, padx=10, pady=5, sticky="e")
        self.password_entry = tk.Entry(root, show="*")  # Mask password input
        self.password_entry.grid(row=5, column=1, padx=10, pady=5, sticky="w")

        # Register Section
        self.register_button = tk.Button(root, text="Register", command=self.register)
        self.register_button.grid(row=5, column=2, padx=10, pady=5, sticky="w")

        # Client Section
        tk.Label(root, text="Send").grid(row=0, column=2, padx=10, pady=5, sticky="w")
        self.client_log = tk.Text(root, height=10, width=50, state="disabled")
        self.client_log.grid(row=1, column=2, padx=10, pady=5)
        tk.Button(root, text="Select File & Send", command=self.select_and_send_file).grid(row=2, column=2, padx=10, pady=5)
        tk.Label(root, text="To:").grid(row=2, column=1, padx=10, pady=5, sticky="e")
        self.to_entry = tk.Entry(root)
        self.to_entry.grid(row=2, column=2, padx=10, pady=5, sticky="w")

        # Host and Port Configuration
        tk.Label(root, text="Host:").grid(row=6, column=0, padx=10, pady=5, sticky="e")
        self.host_entry = tk.Entry(root)
        self.host_entry.insert(0, get_ip())
        self.host_entry.grid(row=6, column=1, padx=10, pady=5, sticky="w")

        tk.Label(root, text="Port:").grid(row=7, column=0, padx=10, pady=5, sticky="e")
        self.port_entry = tk.Entry(root)
        self.port_entry.insert(0, str(DEFAULT_PORT))
        self.port_entry.grid(row=7, column=1, padx=10, pady=5, sticky="w")

        # Default download directory
        self.download_dir = os.getcwd()

    def log_message(self, widget, message):
        """Logs a message to a specific Text widget."""
        widget.config(state="normal")
        widget.insert(tk.END, message + "\n")
        widget.config(state="disabled")
        widget.see(tk.END)

    def server_log_callback(self, message):
        """Callback to log server messages."""
        self.log_message(self.server_log, message)

    def client_log_callback(self, message):
        """Callback to log client messages."""
        self.log_message(self.client_log, message)

    def get_host_and_port(self):
        """Gets the host and port from the GUI input fields."""
        host = self.host_entry.get()
        try:
            port = int(self.port_entry.get())
            if port < 1 or port > 65535:
                raise ValueError("Port out of range.")
        except ValueError:
            messagebox.showerror("Invalid Input", "Port must be an integer between 1 and 65535.")
            return None, None
        return host, port

    def start_server(self):
        """Starts the server in a separate thread."""
        host, port = self.get_host_and_port()
        if host and port:
            threading.Thread(target=server, args=(host, port, self.command_queue, self.server_log_callback), daemon=True).start()
            self.server_log_callback(f"Server started on {host}:{port}. Files will be saved to {self.download_dir}.")

    def select_download_dir(self):
        """Opens a directory selection dialog to choose the download directory."""
        selected_dir = filedialog.askdirectory(title="Select Download Directory")
        if selected_dir:
            self.download_dir = selected_dir
            self.command_queue.put(("set_download_dir", selected_dir))
            self.server_log_callback(f"Download directory set to: {self.download_dir}")

    def select_and_send_file(self):
        """Opens a file dialog and sends the selected file."""
        recipiant_username = self.to_entry.get()
        file_path = filedialog.askopenfilename(title="Select a File")
        if file_path:
            self.client_log_callback(f"Selected file: {file_path}")
            host, port = self.get_host_and_port()
            if host and port:
                threading.Thread(target=client, args=(host, port, file_path, self.client_log_callback, recipiant_username), daemon=True).start()

    def login(self):
        """Handles the login button click."""
        username = self.username_entry.get()

        if len(username) > 16:
            raise ValueError("Username cannot be longer than 16 characters")

        password = self.password_entry.get()
        ip = self.host_entry.get()
        port = self.port_entry.get()

        script_dir = os.path.dirname(os.path.abspath(__file__))
        identifier_file = os.path.join(script_dir, "identifier.pem")

        try:
            if not os.path.exists(identifier_file):
                raise FileNotFoundError("The identifier.pem file is missing. Please register first.")

            with open(identifier_file, "r") as f:
                key_string = f.read().strip()

            if not key_string:
                raise ValueError("The identifier.pem file is empty or corrupted.")

            response = send_to_server("LOGIN", username, password, key_string, ip, port)

            messagebox.showinfo("Login Response", response)

            if "Login successful" in response:
                self.password_entry.grid_remove() 
                self.login_button.grid_remove()    
                self.register_button.grid_remove()
                self.login_state.username = username;
                self.login_state.ip = ip;
                self.login_state.port = port
                self.login_state.logged_in = 1;
            

        except FileNotFoundError as e:
            messagebox.showerror("Error", f"File Error: {e}")
        except ValueError as e:
            messagebox.showerror("Error", f"Value Error: {e}")
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")



    def register(self):
        """Handles the register button click with secure key generation."""
        username = self.username_entry.get()

        if len(username) > 16:
            raise ValueError("Username cannot be longer than 16 characters")

        password = self.password_entry.get()
        ip = self.host_entry.get()
        port = self.port_entry.get()

        script_dir = os.path.dirname(os.path.abspath(__file__))
        identifier_file = os.path.join(script_dir, "identifier.pem")

        try:
            if os.path.exists(identifier_file):
                raise FileExistsError("The identifier.pem file already exists. Registration cannot overwrite the file.")

            chars = string.ascii_letters + string.digits
            random_string = ''.join(secrets.choice(chars) for _ in range(64))

            with open(identifier_file, "w") as f:
                f.write(random_string)

            os.chmod(identifier_file, stat.S_IRUSR | stat.S_IWUSR)

            messagebox.showinfo("Key File Generated", "A new identifier.pem file has been created.")

            response = send_to_server("REGISTER", username, password, random_string, ip, port)

            messagebox.showinfo("Register Response", response)

            if "Register successful" in response:
                self.register_button.grid_remove() 

        except PermissionError as e:
            messagebox.showerror("Error", f"Permission Error: {e}")

        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")

    def logout(self):
        return

if __name__ == "__main__":
    root = tk.Tk()
    app = P2PApp(root)
    root.mainloop()