import nmap
import sys

def findHosts(subnet, complexity):
     # Extracting subnet and complexity from command line arguments
    subnet = sys.argv[1]
    complexity = sys.argv[2]

    print("Performing Nmap scan with subnet:", subnet, "and complexity:", complexity)

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
    if len(sys.argv) != 3:
        print("Usage: python script_name.py subnet complexity")
        sys.exit(1)
    subnet = sys.argv[1]
    complexity = sys.argv[2]
    findHosts(subnet, complexity)