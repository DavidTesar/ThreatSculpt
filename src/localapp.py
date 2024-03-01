import webbrowser
from tkinter import messagebox
from PIL import Image, ImageTk
import tkinter as tk
import requests
from io import BytesIO
import threading
import os
from flask import Flask, render_template
import webbrowser
import threading
import subprocess
import open_react_app
from flask import Flask, send_file
# Import the 'result' function from the 'main' module
from scan import findHosts as get_scan_result

app = Flask(__name__)

# Define the default username and password
DEFAULT_USERNAME = "123"
DEFAULT_PASSWORD = "123"

app = Flask(__name__)

# Function to authenticate user login
def authenticate(username, password):
    return username == DEFAULT_USERNAME and password == DEFAULT_PASSWORD

# Function to perform the scan
def perform_scan(target):
    # Call the result function directly
    result_content = get_scan_result(target)
    return result_content

# Function to start the scan in a separate thread
def start_scan(target):
    # Perform the scan in a separate thread, passing the target
    scan_thread = threading.Thread(target=perform_scan_and_display_result, args=(target,))
    scan_thread.start()

# Function to perform the scan and display the result
def perform_scan_and_display_result(target):
    # Display scan progress message
    display_scan_progress()

    # Perform the scan
    result_content = perform_scan(target)

    # Close the scan progress window after the scan is completed
    scan_progress_window.destroy()

    # Start the React app
    #open_react_app.start_react_app()

# Function to display the scan progress
def display_scan_progress():
    global scan_progress_window
    scan_progress_window = tk.Toplevel()
    scan_progress_window.title("Scan Progress")
    scan_progress_window.geometry("300x100")

    label = tk.Label(scan_progress_window, text="The scan is in progress. Please wait...")
    label.pack(pady=10)

    # Disable closing of the window
    scan_progress_window.protocol("WM_DELETE_WINDOW", disable_event)

# Function to disable closing of the scan progress window
def disable_event():
    pass  # Do nothing, effectively disabling the close button

# Function to open the scanning window
def open_scan_window():
    scan_window = tk.Tk()
    scan_window.title("Threat Sculpt")

    window_width = 400
    window_height = 250
    screen_width = scan_window.winfo_screenwidth()
    screen_height = scan_window.winfo_screenheight()
    x_coordinate = (screen_width / 2) - (window_width / 2)
    y_coordinate = (screen_height / 2) - (window_height / 2)
    scan_window.geometry("%dx%d+%d+%d" % (window_width, window_height, x_coordinate, y_coordinate))

    # Load the logo image from a URL
    logo_url = "https://brown-friendly-dragon-577.mypinata.cloud/ipfs/QmcnmTnnHkPXCoKKshGuyhm5tNnkpUHxPGBi32CMD5oDLK"
    response = requests.get(logo_url)
    if response.status_code == 200:
        logo_data = response.content
        logo_image = Image.open(BytesIO(logo_data))
        logo_image = logo_image.resize((100, 100))
        logo_photo = ImageTk.PhotoImage(logo_image)
        logo_label = tk.Label(scan_window, image=logo_photo)
        logo_label.image = logo_photo
        logo_label.pack(pady=5)
    else:
        print("Failed to load logo from URL")

    # Label at the center top of the window
    top_label = tk.Label(scan_window, text="Select the type of scan you want to do :", font=("Arial", 12, "bold"))
    top_label.pack()

    # Entry for target domain/subnet
    target_label = tk.Label(scan_window, text="Enter target domain/subnet:")
    target_label.pack()
    target_entry = tk.Entry(scan_window)
    target_entry.pack()

    # Button to start scanning, modified to get target from entry
    start_scan_button = tk.Button(scan_window, text="Classic Scan", command=lambda: start_scan(target_entry.get()))
    start_scan_button.pack(pady=10)

    scan_window.mainloop()

# Function to open the login window
def open_login_window():
    def login():
        entered_username = username_entry.get()
        entered_password = password_entry.get()
        if authenticate(entered_username, entered_password):
            login_window.destroy()  
            open_scan_window()  # Open the scanning window after successful login
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")

    def skip_login():
        login_window.destroy()
        open_scan_window()

    login_window = tk.Tk()
    login_window.title("Login")

    window_width = 350
    window_height = 300
    screen_width = login_window.winfo_screenwidth()
    screen_height = login_window.winfo_screenheight()
    x_coordinate = (screen_width / 2) - (window_width / 2)
    y_coordinate = (screen_height / 2) - (window_height / 2)
    login_window.geometry("%dx%d+%d+%d" % (window_width, window_height, x_coordinate, y_coordinate))

    # Load the logo image from a URL
    logo_url = "https://brown-friendly-dragon-577.mypinata.cloud/ipfs/QmcnmTnnHkPXCoKKshGuyhm5tNnkpUHxPGBi32CMD5oDLK"
    response = requests.get(logo_url)
    if response.status_code == 200:
        logo_data = response.content
        logo_image = Image.open(BytesIO(logo_data))
        logo_image = logo_image.resize((100, 100))
        logo_photo = ImageTk.PhotoImage(logo_image)
        logo_label = tk.Label(login_window, image=logo_photo)
        logo_label.image = logo_photo
        logo_label.pack(pady=5)
    else:
        print("Failed to load logo from URL")

    username_label = tk.Label(login_window, text="Username:")
    username_label.pack()
    username_entry = tk.Entry(login_window)
    username_entry.pack()

    password_label = tk.Label(login_window, text="Password:")
    password_label.pack()
    password_entry = tk.Entry(login_window, show="*")
    password_entry.pack()

    login_button = tk.Button(login_window, text="Login", command=login)
    login_button.pack(pady=10)

    skip_login_label = tk.Label(login_window, text="Skip the login", fg="blue", cursor="hand2")
    skip_login_label.pack(pady=5)
    skip_login_label.bind("<Button-1>", lambda event: skip_login())

    login_window.mainloop()

# Function to open the initial panel
def open_panel():
    open_login_window()

if __name__ == '__main__':
    open_panel()