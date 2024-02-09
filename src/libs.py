import importlib.util
import subprocess

def nmapLib():
    # Check if python-nmap is installed
    spec = importlib.util.find_spec("nmap")
    if spec is None:
        print("nmap library is not installed. Installing...")
        subprocess.run(["pip", "install", "python-nmap"])
        print("nmap library has been installed successfully.")
    else:
        print("nmap library is already installed.")

def vulnsLib():
    spec = importlib.util.find_spec("vulners")
    if spec is None:
        print("vulners library is not installed. Installing...")
        subprocess.run(["pip", "install", "vulners"])
        print("vulners library has been installed successfully.")
    else:
        print("vulners library is already installed.")

def apiLib():
    spec = importlib.util.find_spec("requests")
    if spec is None:
        print("requests library is not installed. Installing...")
        subprocess.run(["pip", "install", "requests"])
        print("requests library has been installed successfully.")
    else:
        print("requests library is already installed.")