import tkinter as tk
from tkinter import messagebox
from threading import Thread
from PIL import Image, ImageTk
import requests
from io import BytesIO
from flask import Flask, render_template
import webbrowser


# Define the default username and password
DEFAULT_USERNAME = "123"
DEFAULT_PASSWORD = "123"

app = Flask(__name__)

def authenticate(username, password):
    if username == DEFAULT_USERNAME and password == DEFAULT_PASSWORD:
        return True
    else:
        return False

def start_scan():
    url = 'http://127.0.0.1:5000/'
    webbrowser.open_new(url)

@app.route('/')
def index():
    return render_template('index.html')

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

    # Label at the center top of the window
    top_label = tk.Label(scan_window, text="Select the type of scan you want to do :", font=("Arial", 12, "bold"))
    top_label.place(relx=0.5, rely=0.05, anchor="center")

    # Button to start scanning
    start_scan_button = tk.Button(scan_window, text="Classic Scan", command=start_scan)
    start_scan_button.place(relx=0.5, rely=0.5, anchor="center")

    scan_window.mainloop()

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
    logo_url = "https://brown-friendly-dragon-577.mypinata.cloud/ipfs/QmcnmTnnHkPXCoKKshGuyhm5tNnkpUHxPGBi32CMD5oDLK"  # Replace this with your logo URL
    response = requests.get(logo_url)
    if response.status_code == 200:
        logo_data = response.content
        logo_image = Image.open(BytesIO(logo_data))
        # Resize the image to 100x100 pixels
        logo_image = logo_image.resize((100, 100))
        logo_photo = ImageTk.PhotoImage(logo_image)
        logo_label = tk.Label(login_window, image=logo_photo)
        logo_label.image = logo_photo  # Keep a reference to prevent garbage collection
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

def open_panel():
    open_login_window()

if __name__ == '__main__':
    Thread(target=app.run).start()
    open_panel()