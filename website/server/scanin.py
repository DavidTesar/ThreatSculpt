import nmap

def findHosts(subnet, complexity):
    print("Finding devices on the local network")

    # Create a new instance of NmapPortScanner
    nm = nmap.PortScanner()
    options = ""

    if(complexity == 'simple'):
        options = "-sL"
    if(complexity == 'classic'):
        options = "-O -sV"
    if(complexity == 'advanced'):
        options = "-A"

    # Perform a ping scan on the specified subnet
    nm.scan(hosts=subnet, arguments=options)

    # Print the scan results
    for host in nm.all_hosts():
        print("Host: ", host)
        print("State: ", nm[host].state())
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                print("Protocol: ", proto)
                print("Port: ", port, "State: ", nm[host][proto][port]['state'], "Version: ", nm[host][proto][port]['version'])

    return nm


def findVulns():
    print("finding vulns")

if __name__ == "__main__":
    # If the script is executed directly, call findHosts function
    findHosts("localhost", "classic")