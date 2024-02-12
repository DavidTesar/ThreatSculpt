import nmap

def findHosts(subnet):
    print("Finding devices on the local network")

    # Create a new instance of NmapPortScanner
    nm = nmap.PortScanner()

    # Perform a ping scan on the specified subnet
    nm.scan(hosts=subnet, arguments='-sn')

    # Extract the list of hosts that responded to the ping scan
    hosts_list = [x for x in nm.all_hosts() if nm[x]['status']['state'] == 'up']

    print("Hosts in the local subnet:", hosts_list)

    return hosts_list


def findVulns():
    print("finding vulns")