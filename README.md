# WEB VULNERABILITY SCANNER TOOL

🎷 **OnixD - WEB VULNERABILITY SCANNER TOOL**  🎷
°。°。°。°。°。。°。°。°。°。°°。°。°。°。°。。°。°。°。°。°

### **Why OnixD?**  
Performing multiple security scans manually can be time-consuming and inefficient. Without automation, running different security tools one by one for each engagement is a complex task. OnixD simplifies this process by integrating multiple scanning tools, filtering out false positives, correlating results, and saving valuable time—all within a single tool.  

### **Features:**  
- **Easy Installation** – One-step setup.  
- **Automated Multi-Tool Execution** – Runs multiple security tools like `nmap`, `dnsrecon`, `wafw00f`, `uniscan`, `sslyze`, `fierce`, `theharvester`, `amass`, and `nikto` in a single command.  
- **Time Efficient** – Reduces scanning time significantly.  
- **Enhanced Accuracy** – Cross-checks vulnerabilities with multiple tools to minimize false positives.  
- **Lightweight & Efficient** – Uses minimal system resources.  
- **User-Friendly Controls** – Displays estimated scan time, allowing users to skip long-running tests.  
- **OWASP Top 10 & CWE 25 Integration** *(in progress)* – Aligns findings with well-known security standards.  
- **Vulnerability Classification** – Categorizes issues as Critical, High, Medium, Low, or Informational.  
- **Remediation Suggestions** – Provides guidance on how to fix discovered vulnerabilities.  
- **Executive Summary** – Generates a clear report summarizing key findings.  


### **Current Capabilities:**  
- Detects Load Balancers & Web Application Firewalls  
- CMS Detection (Joomla, WordPress, Drupal)  
- SSL Vulnerability Checks (Heartbleed, FREAK, POODLE, CCS Injection, Logjam, OCSP Stapling)  
- Open Ports & DNS Zone Transfer Analysis  
- Subdomain Enumeration (DNSMap, amass, nikto)  
- Brute-Force Testing for Open Directories & Files  
- Basic XSS, SQL Injection & Blind SQL Injection Detection  
- DoS Attacks (Slowloris), Local/Remote File Inclusion (LFI/RFI), and Remote Code Execution (RCE)  


### **Requirements:**  
- Python 3  
- Kali Linux (Preferred, as most tools are pre-installed)  
- Also tested on Parrot OS & Ubuntu  

### **Install and Run from GitHub on Kali Linux**
If the repo is on GitHub, use these commands in Kali Linux:

```bash
# Clone the repository from GitHub
git clone https://github.com/Digvijay8580/OnixD.git
cd OnixD

# Install required Kali packages (if not already installed)
sudo apt update
sudo apt install python3 python3-venv python3-pip nmap curl dnsutils -y

# Create and activate a Python virtual environment
python3 -m venv venv
source venv/bin/activate

# Install the project package
python3 -m pip install .
```

### **How to Run the Scanner**

```bash
# Run a scan against a target
python3 onixscanner.py http://example.com

# Update the scanner to the latest version
python3 onixscanner.py -u

# Skip specific sub-tools (e.g. skip wapiti)
python3 onixscanner.py -s wapiti http://example.com

# Disable the idle loader/spinner
python3 onixscanner.py -n http://example.com

# Show the help menu
python3 onixscanner.py -h
```

If the package install succeeded, you can also run:

```bash
onixscanner http://example.com
```
