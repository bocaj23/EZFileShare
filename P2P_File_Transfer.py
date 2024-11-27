import os
import socket
import ssl
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
import queue

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
    """Handles an incoming client connection."""
    try:
        filename = conn.recv(BUFFER_SIZE).decode()
        if not filename:
            return

        # Get the latest download directory
        download_dir = current_dir["download_dir"]

        log_callback(f"Receiving file: {filename}")
        file_path = os.path.join(download_dir, filename)
        with open(file_path, "wb") as f:
            while True:
                data = conn.recv(BUFFER_SIZE)
                if not data:
                    break
                f.write(data)

        log_callback(f"File {filename} received successfully to {file_path}.")
    except Exception as e:
        log_callback(f"Error: {e}")
    finally:
        conn.close()


def client(host, port, filename, client_log_callback):
    """Runs the P2P client to send a file."""
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations(CERTFILE)

    try:
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure_socket:
                client_log_callback(f"Connected to {host}:{port}")

                secure_socket.sendall(os.path.basename(filename).encode())

                with open(filename, "rb") as f:
                    while chunk := f.read(BUFFER_SIZE):
                        secure_socket.sendall(chunk)

                client_log_callback(f"File {filename} sent successfully.")
    except Exception as e:
        client_log_callback(f"Error: {e}")


class P2PApp:
    def __init__(self, root):
        self.root = root
        self.root.title("EZFileShare")

        # Command queue for server
        self.command_queue = queue.Queue()

        # Server Section
        tk.Label(root, text="Receive").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.server_log = tk.Text(root, height=10, width=50, state="disabled")
        self.server_log.grid(row=1, column=0, padx=10, pady=5)
        tk.Button(root, text="Start", command=self.start_server).grid(row=2, column=0, padx=10, pady=5)
        tk.Button(root, text="Select Download Directory", command=self.select_download_dir).grid(row=3, column=0, padx=10, pady=5)

        # Client Section
        tk.Label(root, text="Send").grid(row=0, column=1, padx=10, pady=5, sticky="w")
        self.client_log = tk.Text(root, height=10, width=50, state="disabled")
        self.client_log.grid(row=1, column=1, padx=10, pady=5)
        tk.Button(root, text="Select File & Send", command=self.select_and_send_file).grid(row=2, column=1, padx=10, pady=5)

        # Host and Port Configuration
        tk.Label(root, text="Host:").grid(row=4, column=0, padx=10, pady=5, sticky="e")
        self.host_entry = tk.Entry(root)
        self.host_entry.insert(0, DEFAULT_HOST)
        self.host_entry.grid(row=4, column=1, padx=10, pady=5, sticky="w")

        tk.Label(root, text="Port:").grid(row=5, column=0, padx=10, pady=5, sticky="e")
        self.port_entry = tk.Entry(root)
        self.port_entry.insert(0, str(DEFAULT_PORT))
        self.port_entry.grid(row=5, column=1, padx=10, pady=5, sticky="w")

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
        file_path = filedialog.askopenfilename(title="Select a File")
        if file_path:
            self.client_log_callback(f"Selected file: {file_path}")
            host, port = self.get_host_and_port()
            if host and port:
                threading.Thread(target=client, args=(host, port, file_path, self.client_log_callback), daemon=True).start()


if __name__ == "__main__":
    root = tk.Tk()
    app = P2PApp(root)
    root.mainloop()