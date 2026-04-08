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

### **How to Run in a Live Environment**
To execute the OnixD in your live environment, run the primary `te.py` script and pass your target URL:

```bash
# Basic scan against a live target
python te.py http://example.com

# Update the scanner to the latest version
python te.py -u

# Skip specific sub-tools (e.g. skip wapiti)
python te.py -s wapiti http://example.com

# Disable the idle loader/spinner
python te.py -n http://example.com

# Show the help menu
python te.py -h
```
