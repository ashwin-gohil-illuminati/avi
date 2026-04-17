AVI: Automated Vulnerability Interrogator
AVI is a smart security scanner that bridges the gap between finding a device and finding a hole. Instead of just telling you a port is open, AVI automatically consults its internal "Library" to find and fire the exact script needed to test for vulnerabilities.

The Mission
Manual scanning is slow. Scanning everything is noisy. AVI automates the middle ground: it identifies the service, picks the right weapon from Nmap's Scripting Engine (NSE), and generates a "Strike Plan" to get results fast.

How It Works (The 3-Step Flow)
The Scout (Discovery): Scans the local network for live hosts using ARP and identifies exactly which services (like FTP, SSH, or HTTP) are running.

The Librarian (Indexing): Crawls your system's Nmap script folder. It reads the metadata of every script to understand what it does and which service it targets.

The Interrogator (Execution): Matches the found services with "High-Value" scripts (like those for exploits or brute-forcing). It runs them surgically and extracts the proof of vulnerability for your final report.

Key Features
Zero Noise: Only runs scripts that match the detected service.

Smart Filtering: Prioritizes scripts tagged with vuln, exploit, auth, or brute.

Fail-Safe: Built-in timeouts and error handling so the script doesn't hang on a single stubborn target.

Evidence Capture: Automatically pulls the "Shine" (vulnerability results) out of messy Nmap outputs.
