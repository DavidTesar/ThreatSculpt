import nmap

# Create an Nmap scanner object
nm = nmap.PortScanner()

nm.scan(hosts='192.168.89.1', arguments='-sV --script vulners --script-args mincvss=6')

# Display the result
for host in nm.all_hosts():
    print("[X] Scanning for host: " + host)
    print(f'Host : {host} ({nm[host].hostname()})')
    print(f'State : {nm[host].state()}')
    for proto in nm[host].all_protocols():
        print(f'----------')
        print(f'Protocol : {proto}')
        lport = nm[host][proto].keys()
        sorted_ports = sorted(lport)  # It's often more readable to display ports in order
        for port in sorted_ports:
            print(f'Port : {port}\tState : {nm[host][proto][port]["state"]}')
            # Check if there are any scripts in the output, and if the 'vulners' script has output
            if 'script' in nm[host][proto][port]:
                # It's a good idea to also check if 'vulners' specifically is in the script output
                if 'vulners' in nm[host][proto][port]['script']:
                    # Print the output of the 'vulners' script
                    print(f"Vulnerabilities (CVEs with CVSS >= 6.0):")
                    vulners_output = nm[host][proto][port]['script']['vulners']
                    print(vulners_output)
                else:
                    for script_id, script_output in nm[host][proto][port]['script'].items():
                        print(f'Script: {script_id}, Output: {script_output}')
