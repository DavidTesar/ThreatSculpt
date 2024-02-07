import importlib.util
import subprocess

# Check if python-nmap is installed
spec = importlib.util.find_spec("nmap")
if spec is None:
    print("nmap library is not installed. Installing...")
    subprocess.run(["pip", "install", "python-nmap"])
    print("nmap library has been installed successfully.")
else:
    print("nmap library is already installed.")
