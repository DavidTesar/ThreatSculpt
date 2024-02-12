import os
import subprocess
import requests

def install_nmap():
    # Define the URL to download the nmap installer
    url = "https://nmap.org/dist/nmap-7.94-setup.exe"
    
    # Define the path where the installer will be saved
    installer_path = "nmap_setup.exe"

    try:
        # Download the installer
        response = requests.get(url)
        with open(installer_path, 'wb') as f:
            f.write(response.content)
        
        # Execute the installer silently
        subprocess.run([installer_path, '/S'], check=True)

        print("nmap installed successfully.")
    except Exception as e:
        print("Error installing nmap:", e)
    finally:
        # Clean up: Delete the installer after installation
        if os.path.exists(installer_path):
            os.remove(installer_path)

# Call the function to install nmap
install_nmap()