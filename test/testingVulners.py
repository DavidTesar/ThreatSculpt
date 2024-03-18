import nmap

# Create an Nmap scanner object
nm = nmap.PortScanner()

# Run the scan with the defined script, --script-args can limit CVEs that are displayed
nm.scan('192.168.56.102 --script vulners --script-args mincvss=5 -oX vulnerableOutput.xml')

# Display the result
for host in nm.all_hosts():
    print("[X] Scanning for host: " + host)
    print(f'Host : {host} ({nm[host].hostname()})')
    print(f'State : {nm[host].state()}')
    for proto in nm[host].all_protocols():
        print(f'----------')
        print(f'Protocol : {proto}')
        lport = nm[host][proto].keys()
        for port in lport:
            print(f'port : {port}\tstate : {nm[host][proto][port]["state"]}')
            if 'script' in nm[host][proto][port]:
                for script_out in nm[host][proto][port]['script']:
                    print(f'Script: {script_out}, Output: {nm[host][proto][port]["script"][script_out]}')
