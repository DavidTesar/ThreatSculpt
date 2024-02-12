from scan import findHosts, findVulns
from api import makeRequestPulseDive, makeRequestVuln
# TODO: install libraries outside, first.

def main():

    #subnet = '10.100.19.0/24'
    subnet = '127.0.0.1'
    findHosts(subnet)
    findVulns()

    #makeRequestPulseDive("zeus")
    #makeRequestVuln("CVE_2017_14174")



if __name__ == "__main__":
    main()