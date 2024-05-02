import nmap
import sys

def findHosts(subnet, complexity):
    print("Finding devices on the local network")

    # Create a new instance of NmapPortScanner
    nm = nmap.PortScanner()
    options = ""

    if(complexity == 'simple'):
        options = ""
    if(complexity == 'classic'):
        options = "-O -sV -T5"
    if(complexity == 'complex'):
        options = "-sV --script vulners --script-args mincvss=8 -T5"

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
            if 'script' in nm[host][proto][port]:
                if 'vulners' in nm[host][proto][port]['script']:
                    # Check for vulnerabilities if the 'vulners' script has output
                    vulners_output = nm[host][proto][port]['script']['vulners']

                    print('VULNERS OUTPUT:', vulners_output)
    return nm

if __name__ == "__main__":
    # If the script is executed directly, call findHosts function
    if len(sys.argv) != 3:
        print("Usage: python script_name.py subnet complexity")
        sys.exit(1)
    subnet = sys.argv[1]
    complexity = sys.argv[2]
    findHosts(subnet, complexity)