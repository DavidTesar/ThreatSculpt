# Need to have mongo open to be able to connect
# Make sure your ip is in network access section

from pymongo.mongo_client import MongoClient
from urllib.parse import quote_plus

username = quote_plus('user_test')
password = quote_plus('CZ66ttLSf5s0GVe4')
uri = "mongodb+srv://"+username+":"+password + "@cluster0.zc7grf3.mongodb.net/?retryWrites=true&w=majority"
# Create a new client and connect to the server
client = MongoClient(uri)
# Send a ping to confirm a successful connection
# Checking if connection works
try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)

# example of adding an item into the database
# try:
#     dbname = client.ThreatSculpt
#     col_name = dbname.User
#     scanIDs = [
#         "88906723", "88906722", "88906725"
#     ]
#     networkIDs = [
#         "80978965", "80978964", "80978963"
#     ]
#     User = {
#         "username" : "User2",
#         "password" : "pass2",
#         "userID" : "90878909",
#         "scanIDs" : scanIDs,
#         "networkIDs" : networkIDs
#     }
#     col_name.insert_one(User)
#     print("New User added to the database")
# except Exception as e:
#     print(e)

# example on fetching ALL data from a table
try:
    dbname = client.ThreatSculpt
    col_name = dbname.User
    list_1 = col_name.find()
    for i in list_1:
        print(i)
    print("Chosen Tables Only")
    list_2 = col_name.find()
    for item in list_2:
        print(item['username'], item['password'])
except Exception as e:
    print(e)

# example on fetching one specific data from a table
try:
    dbname = client.ThreatSculpt
    col_name = dbname.User
    query = {"username": "User1"}
    print("Result is:")
    result = col_name.find_one(query)
    print(result)
except Exception as e:
    print(e)

# query = {}
# projection = {table_1: 1, table_2: 0}
# find(query, projection) will return items in the table
# that has information in field 1,
# but doesn't have info in field 2
