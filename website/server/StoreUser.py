# Creating a script that grabs the data from the database using the username
# from the login information from localapp.copy()

from pymongo import MongoClient

# MongoDB connection details
username = 'user_test'
password = 'CZ66ttLSf5s0GVe4'
uri = f'mongodb+srv://{username}:{password}@cluster0.zc7grf3.mongodb.net/?retryWrites=true&w=majority'

def getStoredUser(username):
    try:
        # Connect to the MongoDB cluster
        client = MongoClient(uri)

        # Access the ThreatSculpt database and the User collection
        db = client['ThreatSculpt']
        users_collection = db['User']

        # Find the user document based on the provided username
        user = users_collection.find_one({'username': username})

        if user:
            # If user document is found, return the username value
            return user.get('username')
        else:
            # If user document is not found, return an empty value
            return None
    except Exception as e:
        print(f"Error: {e}")
        return ""

# Example usage
if __name__ == "__main__":
    # If the script is executed directly, call findHosts function
    storedUser = getStoredUser(username)
    print(storedUser)