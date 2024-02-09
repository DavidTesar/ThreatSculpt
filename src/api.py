# needs requests library
import requests
import vulners

# 1,000 requests /day
# 10 Analyze scans /day
# 1,000 Explore results
def makeRequestPulseDive(vulnName):
    API_KEY = "64d1215568a8e3381c9f02c98e332ef7d8ebc0316bfeacf95ec7a0523598105c"
    threatName = vulnName #example name for now
    api_url = "https://pulsedive.com/api/info.php?threat=" + threatName + "&pretty=1&" + API_KEY

    response = requests.get(api_url)
    
    print(response.json())

def makeRequestVuln(cve):
    vulners_api = vulners.VulnersApi(api_key="M7FNIPK3PMW0JUJHAB82S71XVF6OC1470SUTBXSML94M5X7S2ZK1KO9RY9K8OERL")
    CVE_2017_14174 = vulners_api.get_bulletin(cve)

    print(CVE_2017_14174)