# 🛡️ AVI: Automated Vulnerability Interrogator

![Python](https://img.shields.io/badge/Language-Python%203.10%2B-blue)
![Security](https://img.shields.io/badge/Field-Cybersecurity-red)
![Tool](https://img.shields.io/badge/Tool-Nmap%20Automation-orange)

**AVI** is a surgical security scanner designed to bridge the gap between "finding a device" and "finding a hole." Instead of simply listing open ports, AVI automatically consults its internal metadata library to identify and execute the exact scripts needed to prove vulnerabilities.

---

## 🚀 The Mission
Manual scanning is tedious, and scanning with every available script creates too much noise. **AVI** automates the middle ground:
* **Identifies** the live services.
* **Consults** the Librarian for matching weapons.
* **Executes** a targeted "Strike Plan" for high-speed, high-accuracy results.

---

## ⚙️ How It Works: The 3-Step Flow

### 1. The Scout (Discovery)
Scans the local network for live hosts using **ARP** (via `arp-scan`). It bypasses the noise of dead IPs and identifies exactly which services (FTP, SSH, HTTP, etc.) are listening.

### 2. The Librarian (Indexing)
Crawls the local system's Nmap Scripting Engine (NSE) directory. It parses script metadata to map specific scripts to their corresponding services and categories.

### 3. The Interrogator (Execution)
Matches discovered services with "High-Value" scripts (targeted at `vuln`, `exploit`, or `brute`). It runs them surgically and extracts the "Shine"—the proof of vulnerability—for the final report.

---

## 🛠️ Key Features

- [x] **Zero Noise:** Only executes scripts matching the detected service.
- [x] **Smart Filtering:** Automatically prioritizes high-impact tags (`vuln`, `exploit`, `auth`, `brute`).
- [x] **Fail-Safe Logic:** Built-in 5-minute timeouts per strike and robust error handling to prevent hangs on stubborn targets.
- [x] **Evidence Capture:** Intelligently scrapes raw Nmap output to isolate the specific "VULNERABLE" findings.

---

## 🚀 Usage

> [!IMPORTANT]
> This tool requires **Root/Sudo privileges** to perform ARP scans and execute advanced Nmap scripts.

### Prerequisites
* **Python 3.10+**
* `nmap` and `arp-scan` installed on the host.
* Target environment (e.g., specialized lab targets like *Tr0ll*).

### Execution
```bash
# Clone the repository
git clone [https://github.com/yourusername/avi-interrogator.git](https://github.com/yourusername/avi-interrogator.git)
cd avi-interrogator

# Run the scanner
sudo python3 avi_scanner.py 192.168.1.0/24
