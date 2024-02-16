import numpy as np 
from pymongo.mongo_client import MongoClient
from urllib.parse import quote_plus
from scan import findHosts

username = quote_plus('user_test')
password = quote_plus('CZ66ttLSf5s0GVe4')
uri = "mongodb+srv://"+username+":"+password + "@cluster0.zc7grf3.mongodb.net/?retryWrites=true&w=majority"
# Create a new client and connect to the server
client = MongoClient(uri)

# get the data
scanResults = findHosts('localhost')
#print(scanResults)

myHosts = []
myPorts = []
result = []

for host in scanResults.all_hosts():
    print("Host: ", host)
    

    #print("State: ", scanResults[host].state())
    for proto in scanResults[host].all_protocols():
        #print("Protocol: ", proto)
        ports = scanResults[host][proto].keys()
        for port in ports:
        #     print("Port: ", port, "State: ", scanResults[host][proto][port]['state'], "Version: ", scanResults[host][proto][port]['version'])
            myNumber = port
            myState = scanResults[host][proto][port]['state']
            myType = proto
            myPorts.append(ports)
            myVersion = scanResults[host][proto][port]['version']

            portObject = {
                "port_num" : myNumber,
                "port_state" : myState,
                "protocol" : myType,
                "protocol_version" : myVersion
            }

            myPorts.append(portObject)
        
        myResult = {
            "host_num" : host,
            "state" : scanResults[host].state(),
            "ports" : myPorts
            }

        result = myResult

# example of adding an item into the database
try:
    dbname = client.ThreatSculpt
    col_name = dbname.ScanResults

# TODO: hash of the output = id
    scanID = "90234589"

# TODO: hash of the hosts discovered = id
    networkID = "80978966"

    userID = "90878909"

    scan = {
        "userID" : userID,
        "networkID" : networkID,
        "scanID" : scanID,
        "result" : result
    }

    col_name.insert_one(scan)
    print("it should work..")
except Exception as e:
    print(e)