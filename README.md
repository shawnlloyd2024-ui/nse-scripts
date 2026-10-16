# Custom Nmap NSE Scripts for HTTP Fingerprinting and CVE Intelligence

## Project Overview

This project contains two custom Nmap Scripting Engine (NSE) scripts developed using Lua. The scripts help identify HTTP server information and retrieve publicly available vulnerability information from the National Vulnerability Database (NVD).

The project demonstrates how Nmap can be extended with custom scripts to perform HTTP service fingerprinting and vulnerability intelligence gathering.

## Objectives

- Identify HTTP server software and version information.
- Collect server headers using multiple HTTP methods.
- Detect common web server HTML signatures and generator meta tags.
- Calculate a heuristic confidence score based on collected information.
- Query the NVD API using detected product and version information.
- Display relevant CVE identifiers, descriptions, CVSS scores, severity, and publication dates.

## Project Files

### 1. `http-version-detector.nse`

This script identifies information about an HTTP service through multiple HTTP requests.

**Features:**

- Sends GET, HEAD, and OPTIONS requests.
- Extracts the HTTP Server header.
- Identifies the product and version when available.
- Checks for common Apache, Nginx, IIS, and LiteSpeed HTML signatures.
- Extracts the HTML generator meta tag when present.
- Compares server headers across HTTP methods.
- Displays a heuristic confidence score and consistency status.

**Purpose:** To demonstrate multi-source HTTP server fingerprinting using Nmap NSE.

### 2. `http-cve-intelligence.nse`

This script uses the product and version information detected by Nmap to search the National Vulnerability Database.

**Features:**

- Uses Nmap service-version information.
- Constructs a keyword search using the detected product and version.
- Queries the NVD CVE API.
- Extracts CVE identifiers and publication dates.
- Displays English vulnerability descriptions.
- Extracts available CVSS scores and severity information.
- Provides links to the corresponding NVD vulnerability pages.

**Purpose:** To demonstrate automated vulnerability information retrieval using a public vulnerability database.

## Technologies Used

- Nmap
- Nmap Scripting Engine (NSE)
- Lua
- HTTP and HTTPS
- National Vulnerability Database (NVD) REST API
- JSON response parsing
- GitHub

## Requirements

- Nmap installed on the system.
- The custom NSE script files.
- Network connectivity to the HTTP target.
- Internet connectivity for NVD API queries.
- A compatible Nmap NSE environment with the required libraries.

## Installation

### Step 1: Download the Repository

Clone the repository:

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
```

Move into the downloaded directory:

```bash
cd YOUR_REPOSITORY_NAME
```

Replace the placeholders with your actual GitHub repository URL and repository folder name.

### Step 2: Copy the Scripts

On Kali Linux or another Linux system with Nmap installed, copy the scripts into the Nmap scripts directory:

```bash
sudo cp http-version-detector.nse /usr/share/nmap/scripts/
sudo cp http-cve-intelligence.nse /usr/share/nmap/scripts/
```

### Step 3: Update the NSE Script Database

Run:

```bash
sudo nmap --script-updatedb
```

This updates Nmap's local script database.

## Usage

> **Only scan systems you own or have permission to test.**

### Script 1: HTTP Version Detector

Run the script against an authorized HTTP target:

```bash
nmap -sV -p 80 --script http-version-detector <TARGET_IP>
```

For an HTTPS service, test the appropriate HTTPS port and verify that the script supports the target's TLS configuration.

The output can include:

- Target IP address
- Port and service
- Detected product and version
- Server headers from GET, HEAD, and OPTIONS
- HTML signature
- Generator tag
- Header consistency
- Heuristic confidence score

### Script 2: HTTP CVE Intelligence

Run service-version detection and the CVE script:

```bash
nmap -sV -p 80 --script http-cve-intelligence <TARGET_IP>
```

The script uses product and version information detected by Nmap to query the NVD API.

The output can include:

- Detected product and version
- Search keyword
- CVE identifiers
- Publication dates
- Vulnerability descriptions
- CVSS scores and severity, when available
- NVD vulnerability links

**Note:** The exact results depend on the target service, Nmap's version detection, API availability, and the NVD response.

## How the Scripts Work Together

1. The HTTP Version Detector collects HTTP headers and page information.
2. The detected server information can help identify the software running on the target.
3. Nmap service-version detection supplies product and version information to the CVE Intelligence script.
4. The CVE Intelligence script searches the NVD API using that information.
5. The returned vulnerability information helps with further investigation.

The scripts are separate and can be executed independently.

## Limitations

- HTTP Server headers may be missing, hidde

---

*Text automatically formatted with [Format Magic](https://formatmagic.ai)*
