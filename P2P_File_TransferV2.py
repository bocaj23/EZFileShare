import os
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

# Shared state
server_log_widget = None
client_log_widget = None
download_dir = os.getcwd()
command_queue = queue.Queue()

def create_tls_context():
    """Creates a TLS context."""
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)
    return context

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
    """Runs the P2P server with a command queue for dynamic behavior."""
    global download_dir
    context = create_tls_context()

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

# GUI
def main():
    global server_log_widget, client_log_widget, host_entry, port_entry
    root = tk.Tk()
    root.title("EZFileShare")

    # Server Section
    tk.Label(root, text="Receive").grid(row=0, column=0, padx=10, pady=5, sticky="w")
    server_log_widget = tk.Text(root, height=10, width=50, state="disabled")
    server_log_widget.grid(row=1, column=0, padx=10, pady=5)
    tk.Button(root, text="Start", command=start_server).grid(row=2, column=0, padx=10, pady=5)
    tk.Button(root, text="Select Download Directory", command=select_download_dir).grid(row=3, column=0, padx=10, pady=5)

    # Client Section
    tk.Label(root, text="Send").grid(row=0, column=1, padx=10, pady=5, sticky="w")
    client_log_widget = tk.Text(root, height=10, width=50, state="disabled")
    client_log_widget.grid(row=1, column=1, padx=10, pady=5)
    tk.Button(root, text="Select File & Send", command=select_and_send_file).grid(row=2, column=1, padx=10, pady=5)

    # Host and Port Configuration
    tk.Label(root, text="Host:").grid(row=4, column=0, padx=10, pady=5, sticky="e")
    host_entry = tk.Entry(root)
    host_entry.insert(0, DEFAULT_HOST)
    host_entry.grid(row=4, column=1, padx=10, pady=5, sticky="w")

    tk.Label(root, text="Port:").grid(row=5, column=0, padx=10, pady=5, sticky="e")
    port_entry = tk.Entry(root)
    port_entry.insert(0, str(DEFAULT_PORT))
    port_entry.grid(row=5, column=1, padx=10, pady=5, sticky="w")

    root.mainloop()

if __name__ == "__main__":
    main()