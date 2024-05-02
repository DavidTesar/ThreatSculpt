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

    myHosts = []
    myPorts = []
    result = []

    for host in scanResults.all_hosts():
        print("Host: ", host)
        myHosts.append(host)
        
        for proto in scanResults[host].all_protocols():
            ports = scanResults[host][proto].keys()
            for port in ports:
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

        scanID = create_id(str(scanResults))
        networkID = create_id(str(myHosts))
        userID = create_id(username)
        
        dbname = client.ThreatSculpt
        col_name = dbname.Networks

        networkdb = {
            "networkID" : networkID,
            "host" : scanResults.all_hosts(),
            "scanIDs" : scanID,
            "userID" : userID
        }

        if col_name.count_documents({"networkID": networkID}) == 0:
            try:
                col_name.insert_one(networkdb)
                print("Networks DB updated with new networkID:", networkID)
            except:
                print("Network ID already exists in the database.")
        else:
            print("No update made: Network ID already exists in the database.")

        dbname = client.ThreatSculpt
        col_name = dbname.ScanResults

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

    # PORTION DEDICATED TO UPLOADING VULNERABILTIEIS
        vulnerabilitiesdb = dbname.Vulnerabilities

        for proto in scanResults[host].all_protocols():
            ports = scanResults[host][proto].keys()
            sorted_ports = sorted(ports)  # Display ports in sorted order

            for port in sorted_ports:
                service = scanResults[host][proto][port]['name']
                port_state = scanResults[host][proto][port]['state']
                print(f'Port : {port}\tService: {service}\tState : {port_state}')

                if 'script' in scanResults[host][proto][port]:
                    if 'vulners' in scanResults[host][proto][port]['script']:
                        # Check for vulnerabilities if the 'vulners' script has output
                        vulners_output = scanResults[host][proto][port]['script']['vulners']

                        print('VULNERS OUTPUT:', vulners_output)

                        data = vulners_output

                        vulnerabilities = []

                        # Split the string into lines and iterate over each line
                        for line in data.strip().split('\n'):
                            # Skip empty lines or irrelevant lines
                            if line.strip() and "cpe:" not in line:
                                parts = line.strip().split('\t')
                                if len(parts) >= 3:  # Ensure there are enough elements in the line to consider
                                    identifier = parts[0]
                                    cvss_score = parts[1]
                                    url = parts[2]
                                    # Optional: Check if it contains a CVE code
                                    if "CVE-" in identifier:
                                        cve_code = identifier.split(':')[-1]
                                        vulnerabilities.append({'CVE': cve_code, 'CVSS': cvss_score, 'URL': url})

                        # Display extracted information
                        for v in vulnerabilities:
                            print(f"CVE: {v['CVE']}, CVSS Score: {v['CVSS']}, URL: {v['URL']}")

                            sample_data = {
                                "id": v['CVE'],
                                "url": v['URL'],
                                "cvss": v['CVSS'],
                                "port_id": port,
                                "service": service,
                                "networkID" : networkID,
                                "device_ip": host,
                                "userID": userID
                            }

                            vulnerabilitiesdb.insert_one(sample_data)
                            print("Vulnerabiltiies data inserted successfully.")

    except Exception as e:
        print("exception cought in uploading results into the database..")
        print(e)

        # TODO: Different scans stored under NetworkID with ScanID. If network ID not there, add a new one.