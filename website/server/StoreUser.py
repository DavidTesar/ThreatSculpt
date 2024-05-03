# Creating a script that grabs the data from the database using the username
# from the login information from localapp.copy()

from pymongo import MongoClient
import sys

# MongoDB connection details
username = 'user_test'
password = 'CZ66ttLSf5s0GVe4'
uri = f'mongodb+srv://{username}:{password}@cluster0.zc7grf3.mongodb.net/?retryWrites=true&w=majority'

def getStoredUser(username):
    username = sys.argv[1]
    
    return username
    # print("Getting stored user with username:", username, "from the server and returning it")
    # try:
    #     # Connect to the MongoDB cluster
    #     client = MongoClient(uri)

    #     # Access the ThreatSculpt database and the User collection
    #     db = client['ThreatSculpt']
    #     users_collection = db['User']

    #     # Find the user document based on the provided username
    #     user = users_collection.find_one({'username': username})

    #     # print('This is what is inside the username when passed', username)
    #     # print('This is what is inside user', user)
    #     # print('This is what is inside user.get(username)', user.get('username'))

    #     if (user):
    #         # If user document is found, return the username value
    #         return user.get('username')
    #     else:
    #         # If user document is not found, return an empty value
    #         return "User not found in getStoredUser function"
    # except Exception as e:
    #     print(f"Error: {e}")
    #     return "This is the exception"

if __name__ == "__main__":
    # If the script is executed directly, call getStoredUser function
    if len(sys.argv) != 2:
        print("Usage: Python script_name.py, username")
        sys.exit(1)
    username = sys.argv[1]
    stored_user = getStoredUser(username)
    print(stored_user)
    