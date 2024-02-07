![alt text](https://github.com/DavidTesar/ThreatSculpt/blob/main/doc/logo.png)

# Threat Sculpt

## Introduction

### Problem Statement
Threat Sculpt aims to address the challenge of understanding the impact of vulnerabilities on business systems. It provides visualization tools to help bridge the gap between cybersecurity experts and non-technical executives.

### Scope
The project focuses on visualizing vulnerabilities and their potential risks rather than active session control or network pivoting.

### Justification
Threat Sculpt fills a crucial gap by emphasizing the real-world impact of vulnerabilities, making it a valuable tool for organizations seeking to enhance their security strategies.

## Objectives

### Must-have Features
- **Scanning**: Perform network scans to identify devices and vulnerabilities.
- **Vulnerability Exposure Visualization**: Analyze scan results to visualize potential business impact.
- **Report Generation**: Generate presentable reports summarizing findings.
- **User-Friendly**: Provide a simple and configurable user interface suitable for non-technical users.

### Nice-to-have Features
- **Cross-Platform Hosting**: Execute scans locally while displaying results via a web interface.
- **Speed Selections**: Offer different scanning options affecting scan speed.
- **Login**: Allow users to log in and access past scans.
- **Licensing**: Provide licensing options for tailored functionality.
- **Multi-Platform Operations**: Support mobile devices for scanning and accessing results.
- **Multi-Profiles**: Group scanning techniques into accessible profiles.
- **Comparing with Previous Scan**: Compare current scan results with past scans to track security improvements.

## System Architecture

### Multi-Tiered Architecture
- **Components**: UI, Application Functionality, Data Storage, Website.
- **Communication**: UI communicates with application and data storage. Website communicates with application and database.
- **Platform**: Desktop application with a local website.
- **Underlying Programming Language**: Python.
- **Hosting**: Local hosting.
- **Dependencies**: Nmap library for Python, Apache for hosting.
