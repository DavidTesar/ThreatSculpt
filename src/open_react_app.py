import subprocess
import os

# Define the path to the React app directory
react_app_path = r'C:\Users\MasseyCharles\OneDrive - University of Wisconsin-Stout\Documents\sesh 6\Soft Practicium\Updated version\ThreatSculpt\website'

# Define a function to start the React app
def start_react_app():
    subprocess.Popen('npm start', cwd=react_app_path, shell=True)

if __name__ == '__main__':
    start_react_app()