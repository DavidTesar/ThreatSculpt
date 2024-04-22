# Creating a script that grabs the data from the database using the username from the login information from localapp.copy()

import requests

def get_data(username):
    print("Attempting to get data for username:", username)
    url = 'http://localhost:4000/getUserInfo'
    data = {'username': username}
    try:
        response = requests.post(url, json=data)
        if response.status_code == 200:
            print("Data retrieved successfully.")
            
            # Print the data
            print(response.json())
        else:
            print("Failed to retrieve data.")
    except Exception as e:
        print("Failed to get data:", e)