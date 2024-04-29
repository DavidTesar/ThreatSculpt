import nmap
from pymongo import MongoClient
from bson import ObjectId

# DB Connection
dbusername = 'user_test'
dbpassword = 'CZ66ttLSf5s0GVe4'
uri = "mongodb+srv://"+dbusername+":"+dbpassword + "@cluster0.zc7grf3.mongodb.net/?retryWrites=true&w=majority"
client = MongoClient(uri)
db = client['ThreatSculpt']
vulnerabilitiesdb = db['Vulnerabilities']

# Initialize the scanner
nm = nmap.PortScanner()

# Execute the scan with specified arguments
nm.scan(hosts='192.168.56.112', arguments='-sV --script vulners --script-args mincvss=8 -T5')

# Process the scan results
for host in nm.all_hosts():
    print(f"[X] Scanning for host: {host}")
    print(f'Host : {host} ({nm[host].hostname()})')
    print(f'State : {nm[host].state()}')

    for proto in nm[host].all_protocols():
        print('----------')
        print(f'Protocol : {proto}')
        ports = nm[host][proto].keys()
        sorted_ports = sorted(ports)  # Display ports in sorted order

        for port in sorted_ports:
            service = nm[host][proto][port]['name']
            port_state = nm[host][proto][port]['state']
            print(f'Port : {port}\tService: {service}\tState : {port_state}')

            if 'script' in nm[host][proto][port]:
                if 'vulners' in nm[host][proto][port]['script']:
                    # Check for vulnerabilities if the 'vulners' script has output
                    vulners_output = nm[host][proto][port]['script']['vulners']

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
                            "device_ip": host
                        }

                        vulnerabilitiesdb.insert_one(sample_data)
                        print("Data inserted successfully.")

# TODO: Test out printing of through json referenses, 
# Assign data to object
# push to database
# integrate with the rest of the program