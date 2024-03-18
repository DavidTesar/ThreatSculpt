import importlib.util
import subprocess
import os
import requests

print("Checking for libraries...")

# Check if python-nmap is installed
spec = importlib.util.find_spec("nmap")
if spec is None:
    print("nmap library is not installed. Installing...")
    subprocess.run(["pip", "install", "python-nmap"])
    print("nmap library has been installed successfully.")
else:
    print("nmap library is already installed.")

# vulners database
spec = importlib.util.find_spec("vulners")
if spec is None:
    print("vulners library is not installed. Installing...")
    subprocess.run(["pip", "install", "vulners"])
    print("vulners library has been installed successfully.")
else:
    print("vulners library is already installed.")

# API works
spec = importlib.util.find_spec("requests")
if spec is None:
    print("requests library is not installed. Installing...")
    subprocess.run(["pip", "install", "requests"])
    print("requests library has been installed successfully.")
else:
    print("requests library is already installed.")

def download_and_place_vulners_nse(target_dir=r"C:\Program Files (x86)\Nmap\scripts"):
    vulners_url = "https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse"
    nse_path = os.path.join(target_dir, "vulners.nse")
    
    # Check if the vulners.nse script already exists
    if os.path.exists(nse_path):
        print("vulners.nse script already present in the target directory.")
        return
    
    try:
        # Download the vulners.nse script
        print(f"Downloading vulners.nse script to {nse_path}")
        response = requests.get(vulners_url)
        response.raise_for_status()  # Raise an exception for HTTP errors

        # Write the content to the target directory
        with open(nse_path, 'wb') as nse_file:
            nse_file.write(response.content)

        print("vulners.nse script downloaded and placed successfully.")
    except requests.RequestException as e:
        print(f"Failed to download vulners.nse script: {e}")

download_and_place_vulners_nse()