import os
import shutil
import socket
import ssl
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
import queue
import zlib
from defs import (
    client,
    server,
    client_log_callback,
    server_log_callback,
    DEFAULT_HOST,
    DEFAULT_PORT,
    BUFFER_SIZE,
    CERTFILE,
    KEYFILE
)


# Function to handle button click events
def on_submit():
    # Get the input from the username entry box
    user_input = username_entry.get()
    # Get the input from the password entry box
    pass_input = password_entry.get()
    # Check username and password
    if user_input == "" and pass_input == "":
        # Close current window
        root.destroy()
        
        # Create new main window
        new_root = tk.Tk()
        new_root.title("EZFileShare")  # Window title
        new_root.geometry("1200x900")  # Window size (width x height)
            
        # Create main content frame
        content_frame = tk.Frame(new_root)
        content_frame.pack(expand=True, fill='both', padx=20, pady=20)

        # Command queue for server
        command_queue = queue.Queue()

        # Function to show main content
        def show_main_content():
            
            # Clear friend list if it exists
            for widget in content_frame.winfo_children():
                widget.destroy()
                
            # Welcome header
            welcome_label = tk.Label(content_frame, text="Welcome to EZFileShare", font=("Arial", 24))
            welcome_label.pack(pady=20)

            # Create horizontal frame to hold file operations and list
            h_frame = tk.Frame(content_frame)
            h_frame.pack(fill='both', expand=True, pady=10)

            # Left side frame for buttons
            button_frame = tk.Frame(h_frame)
            button_frame.pack(side='left', padx=20)

            # Friend List Button
            friend_list_button = tk.Button(button_frame, text="Friend List", font=("Arial", 12), command=show_friend_list)
            friend_list_button.pack(pady=10)
            
            # Function to update staging files list
            def update_staging_list():
                staging_listbox.delete(0, tk.END)
                staging_dir = "staging"
                if os.path.exists(staging_dir):
                    for file in os.listdir(staging_dir):
                        staging_listbox.insert(tk.END, file)

            # File browser button that opens file selection dialog
            def browse_files():
                filename = tk.filedialog.askopenfilename(
                    title="Select a file to transfer",
                    filetypes=[("All Files", "*.*")]
                )
                if filename:
                    # Create staging folder if it doesn't exist
                    staging_dir = "staging"
                    if not os.path.exists(staging_dir):
                        os.makedirs(staging_dir)
                    
                    # Copy file to staging folder
                    dest = os.path.join(staging_dir, os.path.basename(filename))
                    shutil.copy2(filename, dest)
                    print(f"Moved {filename} to staging folder")
                    update_staging_list()

            # Function to zip files from staging folder
            def zip_staging_files():
                staging_dir = "staging"
                if os.path.exists(staging_dir) and os.listdir(staging_dir):
                    # Create zip filename with timestamp
                    zip_name = f"shared_files_{os.path.basename(staging_dir)}.zip"
                    # Create temporary directory for files to zip
                    temp_dir = "temp_staging"
                    if not os.path.exists(temp_dir):
                        os.makedirs(temp_dir)
                    
                    # Copy files to temp directory
                    for file in os.listdir(staging_dir):
                        file_path = os.path.join(staging_dir, file)
                        if os.path.isfile(file_path):
                            shutil.copy2(file_path, os.path.join(temp_dir, file))
                    
                    # Create zip file in staging directory
                    zip_path = os.path.join(staging_dir, zip_name)
                    shutil.make_archive(
                        os.path.splitext(zip_path)[0],
                        'zip',
                        temp_dir
                    )
                    print(f"Created zip file: {zip_name}")
                    
                    # Clean up temp directory
                    shutil.rmtree(temp_dir)
                    
                    # Clean up original files from staging
                    for file in os.listdir(staging_dir):
                        file_path = os.path.join(staging_dir, file)
                        if os.path.isfile(file_path) and not file_path.endswith('.zip'):
                            os.remove(file_path)
                    
                    update_staging_list()
                else:
                    print("No files found in staging directory")
                    
            # Select Files Button
            browse_button = tk.Button(button_frame, text="Select Files", font=("Arial", 12), command=browse_files)
            browse_button.pack(pady=10)

            # Remove Selected Files Button
            delete_button = tk.Button(button_frame, text="Remove Selected", font=("Arial", 12), command=lambda: [
                os.remove(os.path.join("staging", staging_listbox.get(staging_listbox.curselection()))) if staging_listbox.curselection() else None,
                update_staging_list()
            ])
            delete_button.pack(pady=10)
            
            # Zip and Encrypt Button
            zip_button = tk.Button(button_frame, text="Zip and Encrypt", font=("Arial", 12), command=zip_staging_files)
            zip_button.pack(pady=10)

            def send_file():
                staging_dir = "staging"
                if not os.path.exists(staging_dir) or not os.listdir(staging_dir):
                    print("No files to send!")
                    return
                
                # Send each file in the staging directory
                for filename in os.listdir(staging_dir):
                    file_path = os.path.join(staging_dir, filename)
                    if os.path.isfile(file_path):
                        threading.Thread(target=client, args=(DEFAULT_HOST, DEFAULT_PORT, file_path, lambda msg: client_log_callback(self, msg)), daemon=True).start()

            # Send File section  
            upload_button = tk.Button(button_frame, text="Send File", font=("Arial", 12), command=send_file)
            upload_button.pack(pady=10)
            
            # Right side frame for staging files list
            staging_frame = tk.Frame(h_frame, relief=tk.SUNKEN, borderwidth=1)
            staging_frame.pack(side='right', fill='both', expand=True, padx=20)
            
            friend_status_frame = tk.Frame(staging_frame)
            friend_status_frame.pack(fill='x', pady=10)
            global selected_friend_label
            selected_friend_label = tk.Label(friend_status_frame, 
                text=f"Selected Friend: {selected_friend if 'selected_friend' in globals() else 'None'}", 
                font=("Arial", 12))
            selected_friend_label.pack(side='left', padx=10)
            staging_label = tk.Label(friend_status_frame, text="Staged Files:", font=("Arial", 14))
            staging_label.pack(side='left', padx=10)
            
            # Listbox for staging files
            staging_listbox = tk.Listbox(staging_frame, width=50, height=10)
            staging_listbox.pack(pady=10, fill='both', expand=True)
            
            # Initialize staging files list
            update_staging_list()
            
            # Quit button at the bottom
            quit_button = tk.Button(content_frame, text="Quit", command=new_root.quit)
            quit_button.pack(pady=10)

        # Function to show friend list
        def show_friend_list():
            global selected_friend
            # Clear main content
            for widget in content_frame.winfo_children():
                widget.destroy()

            # Back button
            back_button = tk.Button(content_frame, text="Back", font=("Arial", 12), command=show_main_content)
            back_button.pack(anchor='nw', pady=10, padx=10)

            # Friend list title
            friend_label = tk.Label(content_frame, text="Select a Friend", font=("Arial", 24))
            friend_label.pack(pady=20)

            # Example friend list (you can modify this with actual friends)
            friends = ["Friend 1", "Friend 2", "Friend 3", "Friend 4"]
            
            # Function to handle friend selection
            def on_select(event):
                global selected_friend
                if friend_listbox.curselection():
                    selected_friend = friend_listbox.get(friend_listbox.curselection())
                    print(f"Selected friend: {selected_friend}")
                    # Start server when friend is selected
                    threading.Thread(target=server, args=(DEFAULT_HOST, DEFAULT_PORT, command_queue, lambda msg: server_log_callback(self, msg)), daemon=True).start()
                    show_main_content()

            # Function to show add friend dialog
            def show_add_friend():
                # Create new window
                add_friend_window = tk.Toplevel()
                add_friend_window.title("Add Friend")
                add_friend_window.geometry("300x200")

                # Username entry
                username_label = tk.Label(add_friend_window, text="Enter Friend's Username:", font=("Arial", 12))
                username_label.pack(pady=10)
                username_entry = tk.Entry(add_friend_window, width=30)
                username_entry.pack(pady=5)

                def add_friend():
                    new_friend = username_entry.get()
                    if new_friend:
                        friends.append(new_friend)
                        friend_listbox.insert(tk.END, new_friend)
                        add_friend_window.destroy()

                # Bind enter key to add_friend function
                username_entry.bind('<Return>', lambda event: add_friend())

                # Add button
                add_button = tk.Button(add_friend_window, text="Add Friend", font=("Arial", 12),
                                     command=add_friend)
                add_button.pack(pady=20)

            # Create listbox for friends
            friend_listbox = tk.Listbox(content_frame, font=("Arial", 12), width=30, height=10)
            friend_listbox.pack(pady=10)
            
            # Populate listbox with friends
            for friend in friends:
                friend_listbox.insert(tk.END, friend)
                
            # Bind double-click and enter key to selection
            friend_listbox.bind('<Double-Button-1>', on_select)
            friend_listbox.bind('<Return>', on_select)
            
            # Button frame for multiple buttons
            button_frame = tk.Frame(content_frame)
            button_frame.pack(pady=5)
            
            # Add select button
            select_button = tk.Button(button_frame, text="Select Friend", font=("Arial", 12),
                                    command=lambda: on_select(None))
            select_button.pack(side='left', padx=5)

            # Add the Add Friend button
            add_friend_button = tk.Button(button_frame, text="Add Friend", font=("Arial", 12),
                                        command=show_add_friend)
            add_friend_button.pack(side='left', padx=5)

        # Show initial main content
        show_main_content()
        
        # Function to clean up staging directory on exit
        def on_closing():
            staging_dir = "staging"
            if os.path.exists(staging_dir):
                for file in os.listdir(staging_dir):
                    file_path = os.path.join(staging_dir, file)
                    if os.path.isfile(file_path):
                        os.remove(file_path)
            new_root.destroy()

        # Set the window close handler
        new_root.protocol("WM_DELETE_WINDOW", on_closing)
        
        # Start the main loop
        new_root.mainloop()
        
    else:
        result_label.config(text="Invalid username or password")

# Create the main application window
root = tk.Tk()
root.title("EZFileShare")  # Window title
root.geometry("400x300")  # Window size (width x height)

# Add a title label
title_label = tk.Label(root, text="Welcome to the EZFileShare App", font=("Arial", 16))
title_label.pack(pady=10)

# Add username label and text entry box
username_label = tk.Label(root, text="Enter username:")
username_label.pack(pady=5)
username_entry = tk.Entry(root, width=30)
username_entry.pack(pady=5)
username_entry.bind('<Return>', lambda event: password_entry.focus())

# Add password label and text entry box 
password_label = tk.Label(root, text="Enter password:")
password_label.pack(pady=5)
password_entry = tk.Entry(root, width=30, show="*")  # show="*" masks the password
password_entry.pack(pady=5)
password_entry.bind('<Return>', lambda event: on_submit())

# Add a submit button
submit_button = tk.Button(root, text="Submit", command=on_submit)
submit_button.pack(pady=10)

# Add a label to display the result
result_label = tk.Label(root, text="", font=("Arial", 12))
result_label.pack(pady=20)

# Add a quit button
quit_button = tk.Button(root, text="Quit", command=root.quit)
quit_button.pack(pady=10)

# Function to clean up staging directory on exit
def on_closing():
    staging_dir = "staging"
    if os.path.exists(staging_dir):
        for file in os.listdir(staging_dir):
            file_path = os.path.join(staging_dir, file)
            if os.path.isfile(file_path):
                os.remove(file_path)
    root.destroy()

# Set the window close handler
root.protocol("WM_DELETE_WINDOW", on_closing)

# Run the main loop to display the window
root.mainloop()
