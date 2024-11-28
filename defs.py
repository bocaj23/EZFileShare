import os
import shutil
import socket
import ssl
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
import queue
import zlib

# Constants
DEFAULT_HOST = '127.0.0.1'
DEFAULT_PORT = 65432
BUFFER_SIZE = 4096
CERTFILE = "cert.pem"
KEYFILE = "key.pem"

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

def client(host, port, filename, client_log_callback):
    """Runs the P2P client to send a file with integrity verification."""
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations(CERTFILE)

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

                client_log_callback(f"File {filename} sent successfully.")
    except Exception as e:
        client_log_callback(f"Error: {e}")

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
    file_path = filedialog.askopenfilename(title="Select a File")
    if file_path:
        self.client_log_callback(f"Selected file: {file_path}")
        host, port = self.get_host_and_port()
        if host and port:
            threading.Thread(target=client, args=(host, port, file_path, self.client_log_callback), daemon=True).start()
