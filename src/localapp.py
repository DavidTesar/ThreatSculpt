import webbrowser
from tkinter import messagebox
from PIL import Image, ImageTk
import tkinter as tk
import requests
from io import BytesIO
import threading
import os
import re 
from flask import Flask, render_template
import webbrowser
import threading
from trigger_login import trigger_login
import subprocess
import open_react_app
from flask import Flask, request
from pymongo import MongoClient
import hashlib
import requests
from flask import Flask, send_file
from scan import findHosts as get_scan_result
from urllib.parse import quote_plus
from bson.binary import Binary
import threading
from uploadResults import uploadScanResults, create_id
import uuid
import time

# Global variables to store login information
entered_username = None
entered_password = None

# Define your MongoDB credentials
username = quote_plus('user_test')
password = quote_plus('CZ66ttLSf5s0GVe4')

# Construct the MongoDB connection URI
uri = "mongodb+srv://" + username + ":" + password + "@cluster0.zc7grf3.mongodb.net/?retryWrites=true&w=majority"

# Create a new client and connect to the server
client = MongoClient(uri)
db = client['ThreatSculpt']  
users_collection = db['User']  

# Function to authenticate user login against MongoDB
def authenticate(username, password):
    user = users_collection.find_one({'username': username, 'password': password})
    if user:
        entered_username = username
        return True
    else:
        return False
    

# Function to perform the scan
def perform_scan(target, scanType):
    # Call the result function directly
    result_content = get_scan_result(target, scanType)
    return result_content

# Function to start the scan in a separate thread
def start_scan(target, scanType):
    global scan_thread
    scan_thread = True
    # Perform the scan in a separate thread, passing the target
    scan_thread = threading.Thread(target=perform_scan_and_display_result, args=(target,scanType))
    scan_thread.start()

# Function to check if the scan thread is running, and stop it
def stop_scan():
    global scan_thread
    scan_thread = False
    print("Stopping the scan...")
    # print("Scan stopped")
    scan_progress_window.destroy()

# Function to perform the scan and display the result
def perform_scan_and_display_result(target, scanType):
    global scan_thread
    scan_thread = True
    # Display scan progress message
    display_scan_progress()

    # Perform the scan
    result_content = perform_scan(target, scanType)

    # This is very roundabout, but it's the only way I could get it to work
    # We may run into issuses later on with this method
    if scan_thread == True:
        try:
            uploadScanResults('user_test','CZ66ttLSf5s0GVe4', entered_username, result_content)

        except Exception as e:
            print("Error in DB connector")
            print(e)

        # Close the scan progress window after the scan is completed
        scan_progress_window.destroy()

        # Start the React app in a separate process
        subprocess.Popen(["python", "open_react_app.py"])

        # Add a delay of 10 seconds
        time.sleep(15)

        # Trigger the login
        trigger_login(entered_username, entered_password)

    else:
        print("Scan stopped from cancel button.")

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
    
    # Button to cancel scanning
    stop_scan_button = tk.Button(scan_progress_window, text="Cancel Scan", command=stop_scan)
    stop_scan_button.pack(pady=10)

# Function to disable closing of the scan progress window
def disable_event():
    pass  # Do nothing, effectively disabling the close button

# Function to open the scanning window
def open_scan_window():
    scan_window = tk.Tk()
    scan_window.title("Threat Sculpt")

    window_width = 500  # Increased width to accommodate buttons side by side
    window_height = 250
    screen_width = scan_window.winfo_screenwidth()
    screen_height = scan_window.winfo_screenheight()
    x_coordinate = (screen_width / 2) - (window_width / 2)
    y_coordinate = (screen_height / 2) - (window_height / 2)
    scan_window.geometry(f"{window_width}x{window_height}+{int(x_coordinate)}+{int(y_coordinate)}")

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

    # Frame for the buttonsf
    button_frame = tk.Frame(scan_window)
    button_frame.pack(pady=20)

    # Button for 'Simple Scan'
    simple_scan_button = tk.Button(button_frame, text="Simple Scan", command=lambda: start_scan(target_entry.get(), 'simple'))
    simple_scan_button.grid(row=0, column=0, padx=5)

    # Button for 'Classic Scan'
    classic_scan_button = tk.Button(button_frame, text="Classic Scan", command=lambda: start_scan(target_entry.get(), 'classic'))
    classic_scan_button.grid(row=0, column=1, padx=5)

    # Button for 'Complex Scan'
    complex_scan_button = tk.Button(button_frame, text="Complex Scan", command=lambda: start_scan(target_entry.get(), 'complex'))
    complex_scan_button.grid(row=0, column=2, padx=5)

    scan_window.mainloop()

def open_login_window():
    def login():
        global entered_username, entered_password
        entered_username = username_entry.get()
        entered_password = password_entry.get()
        if authenticate(entered_username, entered_password):
            login_window.destroy()
            open_scan_window()
        else:
            messagebox.showerror("Error", "Wrong Username or Password")


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

    create_account_button = tk.Button(login_window, text="Create an Account", command=open_user_creation_window)
    create_account_button.pack(pady=5)

    login_window.mainloop()

# Function to create a new user
def create_user(username, password):
    # Save the user information in the MongoDB collection
    user_data = {
        "username": username,
        "password": password,
        "userID": create_id(username),  
        "scanIDs": [],
        "networkIDs": []
    }
    users_collection.insert_one(user_data)
    messagebox.showinfo("Success", "User created successfully!")

# Function to open the user creation window
def open_user_creation_window():
    def create_account():
        new_username = new_username_entry.get()
        new_password = new_password_entry.get()
        confirm_password = confirm_password_entry.get()

        if new_password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match!")
            return

        # Check if username meets the length requirement
        if len(new_username) < 6:
            messagebox.showerror("Error", "Username must be at least 6 characters long!")
            return

        # Check if password meets the length requirement
        if len(new_password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters long!")
            return

        # Check if password contains at least one capital letter and one special character
        if not re.search(r"[A-Z]", new_password) or not re.search(r"[!@#$%^&*]", new_password):
            messagebox.showerror("Error", "Password must contain at least one capital letter and one special character!")
            return

        # Check if username already exists
        existing_user = users_collection.find_one({"username": new_username})
        if existing_user:
            messagebox.showerror("Error", "Username already exists!")
            return

        # Create the new user
        create_user(new_username, new_password)
        # Close the user creation window upon successful creation
        user_creation_window.destroy()

    #for the back button on account creation 
    def close_window():
        user_creation_window.destroy()

    user_creation_window = tk.Tk()
    user_creation_window.title("Create an Account")

    # Set the size of the window
    window_width = 350
    window_height = 300
    screen_width = user_creation_window.winfo_screenwidth()
    screen_height = user_creation_window.winfo_screenheight()
    x_coordinate = (screen_width / 2) - (window_width / 2)
    y_coordinate = (screen_height / 2) - (window_height / 2)
    user_creation_window.geometry("%dx%d+%d+%d" % (window_width, window_height, x_coordinate, y_coordinate))

    # Add a "Back" button to close the window
    back_button = tk.Button(user_creation_window, text="Back", command=close_window)
    back_button.place(x=10, y=10)

    # Add labels and entry widgets for username, password, and confirm password fields
    new_username_label = tk.Label(user_creation_window, text="Username:")
    new_username_label.place(relx=0.5, rely=0.24, anchor="center")
    new_username_entry = tk.Entry(user_creation_window)
    new_username_entry.place(relx=0.5, rely=0.3, anchor="center")

    new_password_label = tk.Label(user_creation_window, text="Password:")
    new_password_label.place(relx=0.5, rely=0.38, anchor="center")
    new_password_entry = tk.Entry(user_creation_window, show="*")
    new_password_entry.place(relx=0.5, rely=0.44, anchor="center")

    confirm_password_label = tk.Label(user_creation_window, text="Confirm Password:")
    confirm_password_label.place(relx=0.5, rely=0.52, anchor="center")
    confirm_password_entry = tk.Entry(user_creation_window, show="*")
    confirm_password_entry.place(relx=0.5, rely=0.58, anchor="center")

    # Button to submit the user creation form
    create_button = tk.Button(user_creation_window, text="Create Account", command=create_account)
    create_button.place(relx=0.5, rely=0.75, anchor="center")

    user_creation_window.mainloop()


# Function to open the initial panels
def open_panel():
    open_login_window()

if __name__ == '__main__':
    open_panel()
