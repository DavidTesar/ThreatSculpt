from scan import findHosts, findVulns
from api import makeRequestPulseDive, makeRequestVuln
# TODO: install libraries outside, first.

def result():

    #subnet = '10.100.19.0/24'
    subnet = 'tesarsolutions.com'
    findHosts(subnet)
    findVulns()

    #makeRequestPulseDive("zeus")
    #makeRequestVuln("CVE_2017_14174")



if __name__ == "__main__":
    result()