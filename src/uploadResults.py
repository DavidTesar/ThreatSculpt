from pymongo.mongo_client import MongoClient
from urllib.parse import quote_plus
import hashlib

def create_id(input_string):
    # Hash the input string using SHA-256
    hash_object = hashlib.md5(input_string.encode())
    hash_hex = hash_object.hexdigest()
    
    # Combine the hash and the UUID to create a unique scan ID
    id = f"{hash_hex}"
    
    print("ID created: " + id)

    return id

def uploadScanResults(dbusername, dbpassword, username, scanResults):
    # username = quote_plus('user_test')
    # password = quote_plus('CZ66ttLSf5s0GVe4')

    uri = "mongodb+srv://"+dbusername+":"+dbpassword + "@cluster0.zc7grf3.mongodb.net/?retryWrites=true&w=majority"
    # Create a new client and connect to the server
    client = MongoClient(uri)

    # get the data
    # scanResults = findHosts('tesarsolutions.com example.com', 'classic')
    #print(scanResults)

    myHosts = []
    myPorts = []
    result = []

    for host in scanResults.all_hosts():
        print("Host: ", host)
        myHosts.append(host)
        
        #print("State: ", scanResults[host].state())
        for proto in scanResults[host].all_protocols():
            #print("Protocol: ", proto)
            ports = scanResults[host][proto].keys()
            for port in ports:
            #     print("Port: ", port, "State: ", scanResults[host][proto][port]['state'], "Version: ", scanResults[host][proto][port]['version'])
                portNumber = port

                portState = scanResults[host][proto][port]['state']
                portType = proto
                serviceVersion = scanResults[host][proto][port]['version']

                portObject = {
                    "port_num" : portNumber,
                    "port_state" : portState,
                    "protocol" : portType,
                    "protocol_version" : serviceVersion
                }

                myPorts.append(portObject)
            # myPorts.append(list(ports))

            
            myResult = {
                "host_num" : host,
                "state" : scanResults[host].state(),
                "ports" : myPorts
                }

        result.append(myResult)

    # Adding an item into the database
    try:
        dbname = client.ThreatSculpt
        col_name = dbname.ScanResults

        scanID = create_id(str(scanResults))
        networkID = create_id(str(myHosts))
        userID = create_id(username)

        scan = {
            "userID" : userID,
            "networkID" : networkID,
            "scanID" : scanID,
            "result" : result
        }

        col_name.insert_one(scan)
        print("DB Results Upload Successful")

        dbname = client.ThreatSculpt
        col_name = dbname.User

        scanID = create_id(str(scanResults))
        networkID = create_id(str(myHosts))
        userID = create_id(username)

        # Update the user's document by pushing the new scanID and networkID to their respective arrays
        col_name.update_one(
            {"userID": userID},  # Make sure the key used here matches the field in the document
            {
                "$push": {
                    "scanIDs": scanID,  # Assuming 'scanIDs' is the field name in the MongoDB document
                    "networkIDs": networkID  # Assuming 'networkIDs' is the field name in the MongoDB document
                }
            }
        )
        
        print("DB User IDs Update Successful")
    except Exception as e:
        print("exception cought in uploading results into the database..")
        print(e)

        # TODO: Different scans stored under NetworkID with ScanID. If network ID not there, add a new one.