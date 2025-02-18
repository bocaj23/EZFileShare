import os
import socket
import ssl
import threading
import customtkinter as ctk
from tkinter import filedialog, messagebox
import queue
import zlib
import secrets
import string
import stat
from dataclasses import dataclass
import requests
import upnpy


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

#create tls context
#wait for incoming connection
#send cert
#accept incoming connection
def server(host, port, command_queue, server_log_callback):
    """Runs the P2P server with a command queue for dynamic behavior."""
    context = create_tls_context()
    current_dir = {"download_dir": os.getcwd()}  

    host = "0.0.0.0"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen(5)
        server_log_callback(f"Server listening on {host}:{port}")
        with context.wrap_socket(server_socket, server_side=True) as secure_socket:
            while True:
                try:
                    while not command_queue.empty():
                        command, value = command_queue.get_nowait()
                        if command == "set_download_dir":
                            current_dir["download_dir"] = value
                            server_log_callback(f"Download directory changed to: {value}")
                except queue.Empty:
                    pass

                try:
                    conn, addr = secure_socket.accept()
                    client_ip = addr[0]
                    if client_ip == "50.19.225.62":
                        server_log_callback(f"[SERVER] Connection established with {addr}")
                        threading.Thread(
                            target=handle_client_cert_exchange, 
                            args=(conn, addr, current_dir, server_log_callback)
                        ).start()
                    else:
                        server_log_callback(f"[SERVER] Connection established with {addr}")
                        threading.Thread(
                            target=handle_file_transfer, 
                            args=(conn, addr, current_dir, server_log_callback)
                        ).start()
                except ssl.SSLError as e:
                    server_log_callback(f"SSL error: {e}")

def handle_file_transfer(conn, addr, current_dir, log_callback):
    """Handles the file transfer process."""
    try:
        log_callback(f"[SERVER][RECIPIANT] Connection established with {addr}.")

        # Wait for "CLIENT-READY" signal
        client_ready_signal = conn.recv(BUFFER_SIZE).decode("utf-8")
        

        if client_ready_signal != "CLIENT-READY":
            log_callback(f"Unexpected signal from client: {client_ready_signal}")
            return

        log_callback(f"[SERVER][RECIPIANT] Client Ready...")


        # Send readiness signal to client
        payload = "SERVER-READY"
        conn.sendall(payload.encode("utf-8"))

        # Receive metadata
        metadata = conn.recv(BUFFER_SIZE).decode("utf-8")
        if not metadata or "|" not in metadata:
            log_callback("Invalid or empty metadata received. Closing connection.")
            return

        filename, expected_checksum = metadata.split("|")
        expected_checksum = int(expected_checksum)

        log_callback(f"Receiving file: {filename}")
        download_dir = current_dir["download_dir"]
        file_path = os.path.join(download_dir, filename)

        # Receive file data
        with open(file_path, "wb") as f:
            while True:
                data = conn.recv(BUFFER_SIZE)
                if not data or data == b"EOF":
                    break
                f.write(data)

        # Verify checksum
        with open(file_path, "rb") as f:
            file_data = f.read()
            actual_checksum = zlib.crc32(file_data)

        if actual_checksum == expected_checksum:
            log_callback(f"File {filename} received successfully at {file_path} (Checksum verified).")
        else:
            log_callback(f"Checksum mismatch for {filename}! Expected: {expected_checksum}, Got: {actual_checksum}")
    except Exception as e:
        log_callback(f"Error during file transfer: {e}")

def handle_client_cert_exchange(conn, addr, current_dir, log_callback):
    """Handles an incoming client connection."""
    try:
        ###################################### FIRST SEND CERT AS PAYLOAD
        with open('cert.pem', 'r') as file:
            payload = file.read()

        
        conn.sendall(payload.encode('utf-8'))
        log_callback(f"[SERVER] Certificate sent to {addr}. Closing connection to auth server")
        #####################################
    except Exception as e:
        log_callback(f"Unexpected error with {addr}: {e}")
    finally:
        try:
            conn.close()
            log_callback(f"Connection with {addr} closed.")
        except Exception as e:
            log_callback(f"Error closing connection: {e}")

def client(username, filename, client_log_callback, recipient_username):
    """Runs the P2P client to send a file with integrity verification."""
    try:
        # Fetch recipient information
        client_log_callback("[CLIENT][AUTH_SERVER][GET PACKET 1] Seeing if recipiant exists")
        response = send_to_server("GET", recipient_username, None, None, None, None)
        client_log_callback(f"Server response: {response}")

        parts = response.split()
        if len(parts) != 5:
            client_log_callback("Invalid response format from server")
            return
        client_log_callback("[CLIENT][AUTH_SERVER][GET PACKET 1] Packet format correct")

        if parts[0] != "GET-RESPONSE" or parts[1] != "VALID":
            client_log_callback("Recipient not found or not online")
            return
        client_log_callback("[CLIENT][GET PACKET 1]Packet content correct")

        recipient_ip = parts[3]
        recipient_port = int(parts[4])

        client_log_callback("[CLIENT][AUTH_SERVER][INITIATE] Sending initiate packet")
        response = send_to_server("INITIATE", username, None, None, recipient_ip, recipient_port)
        client_log_callback(f"[CLIENT][AUTH_SERVER][INITATE] Response received")

        with open('client_cert.pem', 'w') as file:
            file.write(response)


        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.load_verify_locations(cafile="client_cert.pem")
        context.check_hostname = False

        with socket.create_connection((recipient_ip, recipient_port)) as sock:
            with context.wrap_socket(sock, server_hostname=recipient_ip) as secure_sock:
                client_log_callback(f"[SERVER][RECIPIANT] Connected to recipient at {recipient_ip}:{recipient_port}")
                client_log_callback(f"[SERVER][RECIPIANT] Sending ready message...")
                ready_signal = "CLIENT-READY"
                secure_sock.sendall(ready_signal.encode('utf-8'))

                client_log_callback(f"[SERVER][RECIPIANT] Ready message sent, waiting for server...")
                ready_signal = secure_sock.recv(BUFFER_SIZE).decode("utf-8")
                if ready_signal != "SERVER-READY":
                    client_log_callback(f"Unexpected signal from server: {ready_signal}")
                    return

                client_log_callback("[CLIENT][RECIPIANT] Server is ready. Preparing to send metadata and file...")

                # Send metadata
                with open(filename, "rb") as f:
                    file_data = f.read()
                    checksum = zlib.crc32(file_data)
                    metadata = f"{os.path.basename(filename)}|{checksum}"
                    secure_sock.sendall(metadata.encode("utf-8"))
                    client_log_callback(f"Sent metadata: {metadata}")

                    # Reset the file pointer and send the file
                    f.seek(0)
                    while chunk := f.read(BUFFER_SIZE):
                        secure_sock.sendall(chunk)

                      # Send EOF marker explicitly
                    secure_sock.sendall(b"EOF")
                    client_log_callback(f"File {filename} sent successfully.")

    except socket.timeout:
        client_log_callback("Connection timed out. The recipient might be offline or unreachable.")
    except ConnectionRefusedError:
        client_log_callback("Connection refused. The recipient's file sharing service might not be running.")
    except ssl.SSLError as e:
        client_log_callback(f"SSL Error: {e}")
    except Exception as e:
        client_log_callback(f"Error during file transfer: {str(e)}")

def get_default_gateway_windows():
    import subprocess

    result = subprocess.run(['ipconfig'], capture_output=True, text=True)
    lines = result.stdout.splitlines()

    for i, line in enumerate(lines):
        if "Default Gateway" in line:
            parts = line.split()
            if parts[-1] != ":":
                return parts[-1]

    return None

def setup_port_forwarding(default_gateway, port, description="P2P Program"):
    try:
        # Initialize UPnP
        upnp = upnpy.UPnP()
        
        # Discover UPnP devices
        devices = upnp.discover()
        if not devices:
            return "No UPnP devices found. Ensure UPnP is enabled on your router."

        # Find the device associated with the default gateway
        gateway_device = None
        for device in devices:
            if default_gateway in device['location']:
                gateway_device = device
                break

        if not gateway_device:
            return f"No UPnP-enabled device found matching the default gateway ({default_gateway})."

        # Select the Internet Gateway Device (IGD)
        igd = gateway_device['IGD']

        # Get the internal IP address of the host
        hostname = socket.gethostname()
        internal_ip = socket.gethostbyname(hostname)

        # Set up port forwarding
        protocol = 'TCP'
        igd.AddPortMapping(
            NewRemoteHost='',  # Empty for all external hosts
            NewExternalPort=port,
            NewProtocol=protocol,
            NewInternalPort=port,
            NewInternalClient=internal_ip,
            NewEnabled=1,
            NewPortMappingDescription=description,
            NewLeaseDuration=0  # 0 for permanent
        )
        return f"Port {port} forwarded successfully to {internal_ip} through {default_gateway}."
    except Exception as e:
        return f"Failed to forward port {port}: {e}"

@dataclass
class login_state:
    username: str = ""
    ip: str = ""
    port: int = DEFAULT_PORT
    logged_in: bool = False

class P2PApp:
    def __init__(self, root):
        self.root = root
        self.root.title("EZFileShare")
        self.user_state = login_state()

        # Set appearance mode and color theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Command queue for server
        self.command_queue = queue.Queue()

        self.tabview = ctk.CTkTabview(self.root)
        self.tabview.pack(fill="both", expand=True)

        self.file_sharing_tab = self.tabview.add("File Sharing")
        self.settings_tab = self.tabview.add("Settings")

<<<<<<< Updated upstream
        self.draw_file_sharing_tab()
=======
        self.draw_login_tab()

    def draw_login_tab(self):
        for widget in self.login_tab.winfo_children():
            widget.destroy()

        # Username Section
        ctk.CTkLabel(self.login_tab, text="Username:").grid(row=4, column=0, padx=10, pady=5, sticky="e")
        self.username_entry = ctk.CTkEntry(self.login_tab)
        self.username_entry.grid(row=4, column=1, padx=10, pady=5, sticky="w")

        # Login Section
        self.login_button = ctk.CTkButton(self.login_tab, text="Login", command=self.login)
        self.login_button.grid(row=4, column=2, padx=10, pady=5, sticky="w")
        
        # Logout Section
        self.logout_button = ctk.CTkButton(self.login_tab, text="Logout", command=self.logout)
        self.logout_button.grid(row=6, column=2, padx=10, pady=5, sticky="w")

        # Password Section
        ctk.CTkLabel(self.login_tab, text="Password:").grid(row=5, column=0, padx=10, pady=5, sticky="e")
        self.password_entry = ctk.CTkEntry(self.login_tab, show="*")  # Mask password input
        self.password_entry.grid(row=5, column=1, padx=10, pady=5, sticky="w")

        # Register Section
        if self.user_state.logged_in == False:
            self.register_button = ctk.CTkButton(self.login_tab, text="Register", command=self.register)
            self.register_button.grid(row=5, column=2, padx=10, pady=5, sticky="w")

        # Port Configuration
        ctk.CTkLabel(self.login_tab, text="Port:").grid(row=6, column=0, padx=10, pady=5, sticky="e")
        self.port_entry = ctk.CTkEntry(self.login_tab)
        
        self.port_entry.insert(0, str(DEFAULT_PORT))
        self.port_entry.grid(row=6, column=1, padx=10, pady=5, sticky="w")
<<<<<<< Updated upstream
<<<<<<< Updated upstream
>>>>>>> Stashed changes
=======
>>>>>>> Stashed changes
=======
>>>>>>> Stashed changes

    def draw_file_sharing_tab(self):
        for widget in self.file_sharing_tab.winfo_children():
            widget.destroy()

        # Server Section
        ctk.CTkLabel(self.file_sharing_tab, text="Receive").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.server_log = ctk.CTkTextbox(self.file_sharing_tab, height=200, width=400)
        self.server_log.grid(row=1, column=0, padx=10, pady=5)
        
        if self.user_state.logged_in == True:
            ctk.CTkButton(self.file_sharing_tab, text="Start", command=self.start_server).grid(row=2, column=0, padx=10, pady=5)
            ctk.CTkButton(self.file_sharing_tab, text="Select Download Directory", command=self.select_download_dir).grid(row=3, column=0, padx=10, pady=5)
<<<<<<< Updated upstream
<<<<<<< Updated upstream

<<<<<<< Updated upstream
        #Friends Section
        ctk.CTkLabel(self.file_sharing_tab, text="Friends").grid(row=4, column=0, padx=10, pady=5, sticky="w")

        # Username Section
        ctk.CTkLabel(self.file_sharing_tab, text="Username:").grid(row=4, column=0, padx=10, pady=5, sticky="e")
        self.username_entry = ctk.CTkEntry(self.file_sharing_tab)
        self.username_entry.grid(row=4, column=1, padx=10, pady=5, sticky="w")

        # Login Section
        self.login_button = ctk.CTkButton(self.file_sharing_tab, text="Login", command=self.login)
        self.login_button.grid(row=4, column=2, padx=10, pady=5, sticky="w")

        # Logout Section
        self.logout_button = ctk.CTkButton(self.file_sharing_tab, text="Logout", command=self.logout)
        self.logout_button.grid(row=4, column=3, padx=10, pady=5, sticky="w")
=======
=======
=======

            # Show friends list when logged in
            friends_frame = ctk.CTkFrame(self.file_sharing_tab, fg_color="gray10")
            friends_frame.grid(row=8, column=0, columnspan=4, padx=10, pady=5, sticky="nsew")
            
            # Create header label
            header = ctk.CTkLabel(friends_frame, text="Friends List", font=("Arial", 16, "bold"))
            header.pack(padx=10, pady=(10,5))

            # Add search bar
            search_frame = ctk.CTkFrame(friends_frame)
            search_frame.pack(fill="x", padx=10, pady=5)
            
            search_entry = ctk.CTkEntry(search_frame, placeholder_text="Search friends...", width=200)
            search_entry.pack(side="left", padx=5, pady=5)

            add_friend_button = ctk.CTkButton(search_frame, text="Add Friend")
            add_friend_button.pack(side="right", padx=5, pady=5)
            
            add_friend_entry = ctk.CTkEntry(search_frame, placeholder_text="Enter friend's username...", width=200)
            add_friend_entry.pack(side="right", padx=5, pady=5)

            # Add example friends
            friends = [
                "Alice123",
                "BobSmith",
                "Charlie99", 
                "Diana2024",
                "EvanP"
            ]

            # Create a frame to hold friend entries
            friends_list_frame = ctk.CTkFrame(friends_frame)
            friends_list_frame.pack(fill="x", padx=10, pady=2)

            def update_friends_list(*args):
                # Clear existing friends
                for widget in friends_list_frame.winfo_children():
                    widget.destroy()
                
                search_text = search_entry.get().lower()
                # Show only matching friends
                for friend in friends:
                    if search_text in friend.lower():
                        friend_frame = ctk.CTkFrame(friends_list_frame)
                        friend_frame.pack(fill="x", padx=10, pady=2)
                        
                        friend_label = ctk.CTkLabel(friend_frame, text=friend)
                        friend_label.pack(side="left", padx=10, pady=5)
                        
                        select_button = ctk.CTkButton(friend_frame, text="Select", command=lambda f=friend: self.select_friend(f))
                        select_button.pack(side="right", padx=10, pady=5)
                        
                        status_label = ctk.CTkLabel(friend_frame, text="Online", text_color="green")
                        status_label.pack(side="right", padx=10, pady=5)

            # Bind search entry to update function
            search_entry.bind('<KeyRelease>', update_friends_list)
            
            # Initial population of friends list
            update_friends_list()
>>>>>>> Stashed changes

>>>>>>> Stashed changes
            # Show friends list when logged in
            friends_frame = ctk.CTkFrame(self.file_sharing_tab, fg_color="gray10")
            friends_frame.grid(row=8, column=0, columnspan=4, padx=10, pady=5, sticky="nsew")
            
            # Create header label
            header = ctk.CTkLabel(friends_frame, text="Friends List", font=("Arial", 16, "bold"))
            header.pack(padx=10, pady=(10,5))
<<<<<<< Updated upstream
=======

            # Add search bar
            search_frame = ctk.CTkFrame(friends_frame)
            search_frame.pack(fill="x", padx=10, pady=5)
            
            search_entry = ctk.CTkEntry(search_frame, placeholder_text="Search friends...", width=200)
            search_entry.pack(side="left", padx=5, pady=5)

            add_friend_button = ctk.CTkButton(search_frame, text="Add Friend")
            add_friend_button.pack(side="right", padx=5, pady=5)
            
            add_friend_entry = ctk.CTkEntry(search_frame, placeholder_text="Enter friend's username...", width=200)
            add_friend_entry.pack(side="right", padx=5, pady=5)

            # Add example friends
            friends = [
                "Alice123",
                "BobSmith",
                "Charlie99", 
                "Diana2024",
                "EvanP"
            ]

            # Create a frame to hold friend entries
            friends_list_frame = ctk.CTkFrame(friends_frame)
            friends_list_frame.pack(fill="x", padx=10, pady=2)

            def update_friends_list(*args):
                # Clear existing friends
                for widget in friends_list_frame.winfo_children():
                    widget.destroy()
                
                search_text = search_entry.get().lower()
                # Show only matching friends
                for friend in friends:
                    if search_text in friend.lower():
                        friend_frame = ctk.CTkFrame(friends_list_frame)
                        friend_frame.pack(fill="x", padx=10, pady=2)
                        
                        friend_label = ctk.CTkLabel(friend_frame, text=friend)
                        friend_label.pack(side="left", padx=10, pady=5)
                        
                        select_button = ctk.CTkButton(friend_frame, text="Select", command=lambda f=friend: self.select_friend(f))
                        select_button.pack(side="right", padx=10, pady=5)
                        
                        status_label = ctk.CTkLabel(friend_frame, text="Online", text_color="green")
                        status_label.pack(side="right", padx=10, pady=5)

            # Bind search entry to update function
            search_entry.bind('<KeyRelease>', update_friends_list)
            
            # Initial population of friends list
            update_friends_list()
>>>>>>> Stashed changes

            # Add search bar
            search_frame = ctk.CTkFrame(friends_frame)
            search_frame.pack(fill="x", padx=10, pady=5)
            
            search_entry = ctk.CTkEntry(search_frame, placeholder_text="Search friends...", width=200)
            search_entry.pack(side="left", padx=5, pady=5)

            add_friend_button = ctk.CTkButton(search_frame, text="Add Friend")
            add_friend_button.pack(side="right", padx=5, pady=5)
            
            add_friend_entry = ctk.CTkEntry(search_frame, placeholder_text="Enter friend's username...", width=200)
            add_friend_entry.pack(side="right", padx=5, pady=5)

            # Add example friends
            friends = [
                "Alice123",
                "BobSmith",
                "Charlie99", 
                "Diana2024",
                "EvanP"
            ]

            # Create a frame to hold friend entries
            friends_list_frame = ctk.CTkFrame(friends_frame)
            friends_list_frame.pack(fill="x", padx=10, pady=2)

            def update_friends_list(*args):
                # Clear existing friends
                for widget in friends_list_frame.winfo_children():
                    widget.destroy()
                
                search_text = search_entry.get().lower()
                # Show only matching friends
                for friend in friends:
                    if search_text in friend.lower():
                        friend_frame = ctk.CTkFrame(friends_list_frame)
                        friend_frame.pack(fill="x", padx=10, pady=2)
                        
                        friend_label = ctk.CTkLabel(friend_frame, text=friend)
                        friend_label.pack(side="left", padx=10, pady=5)
                        
                        select_button = ctk.CTkButton(friend_frame, text="Select", command=lambda f=friend: self.select_friend(f))
                        select_button.pack(side="right", padx=10, pady=5)
                        
                        status_label = ctk.CTkLabel(friend_frame, text="Online", text_color="green")
                        status_label.pack(side="right", padx=10, pady=5)

            # Bind search entry to update function
            search_entry.bind('<KeyRelease>', update_friends_list)
            
            # Initial population of friends list
            update_friends_list()
>>>>>>> Stashed changes

        # Password Section
        ctk.CTkLabel(self.file_sharing_tab, text="Password:").grid(row=5, column=0, padx=10, pady=5, sticky="e")
        self.password_entry = ctk.CTkEntry(self.file_sharing_tab, show="*")  # Mask password input
        self.password_entry.grid(row=5, column=1, padx=10, pady=5, sticky="w")

        # Register Section
        if self.user_state.logged_in == False:
            self.register_button = ctk.CTkButton(self.file_sharing_tab, text="Register", command=self.register)
            self.register_button.grid(row=5, column=2, padx=10, pady=5, sticky="w")

        # Client Section
        ctk.CTkLabel(self.file_sharing_tab, text="Send").grid(row=0, column=2, padx=10, pady=5, sticky="w")
        self.client_log = ctk.CTkTextbox(self.file_sharing_tab, height=200, width=400)
        self.client_log.grid(row=1, column=2, padx=10, pady=5)
        if self.user_state.logged_in == True:
            ctk.CTkButton(self.file_sharing_tab, text="Select File & Send", command=self.select_and_send_file).grid(row=2, column=2, padx=10, pady=5)
            ctk.CTkLabel(self.file_sharing_tab, text="To:").grid(row=2, column=1, padx=10, pady=5, sticky="e")
            self.to_entry = ctk.CTkEntry(self.file_sharing_tab)
            self.to_entry.grid(row=2, column=2, padx=10, pady=5, sticky="w")

        # Port Configuration
        ctk.CTkLabel(self.file_sharing_tab, text="Port:").grid(row=7, column=0, padx=10, pady=5, sticky="e")
        self.port_entry = ctk.CTkEntry(self.file_sharing_tab)
        self.port_entry.insert(0, str(DEFAULT_PORT))
        self.port_entry.grid(row=7, column=1, padx=10, pady=5, sticky="w")

        # Default download directory
        self.download_dir = os.getcwd()

    def draw_settings_tab(self):
        return

    def log_message(self, widget, message):
        """Logs a message to a specific Text widget."""
        widget.configure(state="normal")
        widget.insert("end", message + "\n")
        widget.configure(state="disabled")
        widget.see("end")

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
        dg = get_default_gateway_windows()
        self.server_log_callback(f"Default gateway: {dg}")

        f_port = 65432
        forwarding_result = setup_port_forwarding(f_port, dg)
        self.server_log_callback(forwarding_result)

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
        username = self.username_entry.get()
        file_path = filedialog.askopenfilename(title="Select a File")
        if file_path:
            self.client_log_callback(f"Selected file: {file_path}")
            host, port = self.get_host_and_port()
            if host and port:
                threading.Thread(target=client, args=(username, file_path, self.client_log_callback, recipiant_username), daemon=True).start()

    def login(self):
        """Handles the login button click."""
        username = self.username_entry.get()

        if len(username) > 16:
            raise ValueError("Username cannot be longer than 16 characters")

        password = self.password_entry.get()
        ip = get_ip()
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
                self.login_button.grid_remove()    
                self.register_button.grid_remove()
                self.user_state.username = username
                self.user_state.port = port
                self.user_state.logged_in = True
                self.draw_file_sharing_tab()

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
        ip = get_ip()
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
    root = ctk.CTk()
    app = P2PApp(root)
    root.mainloop()