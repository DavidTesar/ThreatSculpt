#this is the script to send the usernam and the password to the react app and connect to a certain user 
# connect.py
import requests

def trigger_login(username, password):
    print("Attempting to login with username:", username, "and password:", password)
    url = 'http://localhost:4000/login'
    data = {'username': username, 'password': password}
    try:
        response = requests.post(url, json=data)
        if response.status_code == 200:
            print("Login successful.")
        else:
            print("Login failed. Invalid username or password.")
    except Exception as e:
        print("Failed to trigger login:", e)