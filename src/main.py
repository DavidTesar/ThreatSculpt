from scan import findHosts, findVulns
from api import makeRequestPulseDive, makeRequestVuln
# TODO: install libraries outside, first.

def main():
    print("Checking for libraries...")

    # This is where modules are called
    findHosts()
    findVulns()

    makeRequestPulseDive("zeus")
    makeRequestVuln("CVE_2017_14174")



if __name__ == "__main__":
    main()