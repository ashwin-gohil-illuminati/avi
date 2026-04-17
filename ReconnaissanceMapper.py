#Author : Ashwin Gohil
#Github : https://github.com/ashwin-gohil-illuminati

import subprocess
import re
import sys
from pathlib import Path
from typing import Any, List, Dict

scripts_path:str = "/usr/share/nmap/scripts/"
input_ip:str = ""
input_test:str = "192.168.1.1/24"
card_catalog: dict[str, list[dict]] = {}

def sanitize_input()->str:
    regexCode:str = r"\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3}/(8|16|24|32)$"
    result = re.match(regexCode, input_ip)
    if(result != None):
        sample_input = result.group()
        splits = sample_input.split(".",4)
        split_fourth = splits[3].split("/",2)
        """
        print(splits[0])
        print(splits[1])
        print(splits[2])
        print(split_fourth[0])
        print(split_fourth[1])
        """
        if(int(splits[0]) < 256 and int(splits[1]) < 256 and int(splits[2]) <256
            and int(split_fourth[0]) <256):
            print("Input matched the pattern!")
            print("The matched input is : ", result.group())
            return result.group()
        else:
            print("Incorrect command line argument provided. Exiting...")
            sys.exit(1)
    else:
        print("Incorrect command line argument provided")
        print("Exiting...")
        sys.exit(1)
    

def initiate_arpScan(ipToScan:str):
    ipMatches:list = []

    try:
        completedProcessObject = subprocess.run(["arp-scan", input_ip], capture_output=True, shell=False, timeout=3600, 
                        check=True, encoding="utf-8", errors='ignore', text=True)
        scan_result = completedProcessObject.stdout
        """
        print("Result of arp-scan is : ")
        print(scan_result)
        """
        ipMatches = re.findall(r"\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3}", scan_result)
        if not ipMatches:
            print("[!] No live hosts found via ARP. Check your network interface/sudo permissions.")
            return []
        print(ipMatches)

        completedProcessObject1 = subprocess.run(["hostname", "-I"], capture_output=True, shell=False, timeout=3600, 
                        check=True, encoding="utf-8", errors='ignore', text=True)
        hostnameIP = completedProcessObject1.stdout.strip()
        local_ips = hostnameIP.split()
        ipMatches = [ip for ip in ipMatches if ip not in local_ips]

        return ipMatches
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"CRITICAL ERROR: arp-scan failed. Ensure it is installed and run with sudo. Details: {e}")
        sys.exit(1)


def enumerate_scanList(scanlist:list) -> dict[str, dict[str, Any]]:
    enumeration_result:dict[str, dict] = {} # important
    regex_pattern = r"^(\d+)/tcp\s+open\s+(\S+)\s+(.*)$"
    for ip in scanlist:
        try:
            nmap_result = subprocess.run(["nmap", "-sV", "--top-ports", "100", "--open", ip],
                                            capture_output=True, shell=False, timeout=3600, 
                                            check=True, encoding="utf-8", errors='ignore', text=True).stdout
            
            if nmap_result:
                enumeration_result[ip] = {"status":"up", "services":[]}

                for line in nmap_result.splitlines():
                    matchOutput = re.search(regex_pattern,line)
                    if matchOutput:
                        new_entry: dict = {"port":matchOutput.group(1), "service":matchOutput.group(2),
                                        "version":matchOutput.group(3)}

                        enumeration_result[ip]["services"].append(new_entry)
        except Exception as e:
            print(f"    [!] Warning: Failed to enumerate {ip}: {e}")
            continue

    if enumeration_result:
        #print(enumeration_result)
        return enumeration_result


def index_nse_library():
    filename:str = ""
    script_key:str = ""
    content_buffer:str = ""
    cat_pattern = r'categories\s*=\s*\{([^}]*)\}'
    desc_pattern = r'description\s*=\s*\[\[(.*?)\]\]'
    folder_path = Path(scripts_path)

    # FAIL-SAFE: Check if the scripts directory exists before looping.
    if not folder_path.exists():
        print(f"CRITICAL ERROR: Nmap scripts path not found at {scripts_path}. Ensure nmap is installed correctly.")
        sys.exit(1)

    for script_file in folder_path.glob("*.nse"):
        #print(f"Reading.. {script_file.name}")
        script_key = script_file.name.split('-')[0]
        filename = script_file.name
        #print(f"Script-key : {script_key}")
        #print(f"Filename : {script_file.name}")

        # Initialize defaults to prevent UnboundLocalError if regex fails
        cleaned_cats = []
        cleaned_desc = "No description found."

        try:
            with script_file.open('r', encoding="utf-8", errors='ignore') as f:
                #print(f"Reading metadata of {script_file.name}")
                for _ in range(50):
                    line = f.readline()
                    if not line:
                        break
                    content_buffer += line
                cat_match = re.search(cat_pattern, content_buffer)
                desc_match = re.search(desc_pattern, content_buffer, re.S)
                if cat_match:
                    raw_cats = cat_match.group(1)
                    # Clean up: remove quotes, spaces, and split by comma
                    cleaned_cats = re.findall(r'[\w-]+', raw_cats)
                    # Result: ["intrusive", "exploit", "dos", "vuln"]
                    #print(f"CATEGORIES OBTAINED : {cleaned_cats}")
                if desc_match:
                    # Clean up: strip leading/trailing whitespace and internal newlines
                    cleaned_desc = desc_match.group(1).strip()
                    #print(f"DESCRIPTION OBTAINED : {cleaned_desc}")
                content_buffer = ""

                # 1. Check if we've seen this service before. If not, create an empty list.
                if script_key not in card_catalog:
                    card_catalog[script_key] = []

                script_entry = {
                    "filename": filename,
                    "categories": cleaned_cats,
                    "description": cleaned_desc
                }

                card_catalog[script_key].append(script_entry)                
                
        except PermissionError:
            print(f"Error: {script_file.name} does not have permission to read.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
        #print()


def read_indexed_library():
    print("__Card_catalog__")
    print(f"card_catalog dictonary length {len(card_catalog)}")
    for key, value in card_catalog.items():
        print(f"script-key : {key}")
        print(f"scipt-key attributes : {value}")
        print()


def generate_strike_plan(enumeration_result: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Phase 4: Matches discovered services against the Card Catalog.
    Returns a list of 'Strikes' (Planned NSE executions).
    """

    # FAIL-SAFE: If enumeration_result is None (no hosts up), return empty list.
    if not enumeration_result:
        print("[!] No results to match. Strike plan empty.")
        return []    

    strike_plan = []

    print("\n[+] Generating Targeted Strike Plan...")

    for ip, details in enumeration_result.items():
        if details['status'] != 'up':
            continue

        for item in details['services']:
            port = item['port']
            service = item['service']
            
            # Step 1: Consult the Librarian (Global card_catalog)
            # We use .get() to avoid errors if a service has no scripts
            potential_scripts = card_catalog.get(service, [])

            if not potential_scripts:
                continue

            # Step 2: Filter for 'High Value' scripts (vuln, exploit, or auth)
            for script in potential_scripts:
                # We prioritize scripts that actually find holes
                is_high_value = False

                # The list of 'interesting' tags we are looking for
                target_tags = ['vuln', 'exploit', 'auth', 'brute']

                # Check each tag in the script's categories
                for tag in script['categories']:
                    if tag in target_tags:
                        is_high_value = True
                        break  # We found one, no need to keep looking
                
                
                if is_high_value:
                    strike = {
                        "ip": ip,
                        "port": port,
                        "service": service,
                        "script_name": script['filename'],
                        "category": script['categories'],
                        "intent": script['description'].split('\n')[0] # Grab just the first line
                    }
                    strike_plan.append(strike)
                    
                    print(f"    [MATCH] {ip}:{port} ({service}) -> {script['filename']}")

    print(f"[!] Total Targeted Strikes Identified: {len(strike_plan)}")
    return strike_plan


def read_strike_plan(strike_plan: list[dict[str, Any]]):
    for element in strike_plan:
        print(element)
    print()


def execute_strike_plan(strike_plan: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Phase 5: Iterates through the strike plan and executes targeted NSE scripts.
    Captures the output and stores it for the final report.
    """
    final_findings = []

    print(f"\n[!] Commencing Execution of {len(strike_plan)} targeted strikes...")

    for strike in strike_plan:
        ip = strike['ip']
        port = strike['port']
        script = strike['script_name']

        print(f"    [RUNNING] {script} against {ip}:{port}...")

        # Construct the command
        # -sV helps Nmap match versions, -Pn treats host as up
        cmd = ["nmap", "-sV", "-p", port, "--script", script, ip]

        try:
            # Execute the strike
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Capture the output
            if result.returncode == 0:
                # We store the strike info PLUS the raw output from Nmap
                finding = strike.copy()
                finding['raw_output'] = result.stdout
                final_findings.append(finding)
                print(f"    [SUCCESS] Captured output for {script}")
            else:
                print(f"    [ERROR] Script {script} failed with exit code {result.returncode}")

        except subprocess.TimeoutExpired:
            print(f"    [TIMEOUT] {script} took too long on {ip}:{port}. Skipping.")
        except Exception as e:
            print(f"    [EXCEPTION] {str(e)}")

    print(f"\n[+] Execution Complete. {len(final_findings)} findings ready for reporting.")
    return final_findings


def generate_final_report(final_findings: List[Dict[str, Any]]):
    # FAIL-SAFE: Handle empty results safely
    if not final_findings:
        print("\n[!] No vulnerability findings to report.")
        return
    
    print("\n" + "="*60)
    print("                FINAL RECONNAISSANCE REPORT")
    print("="*60)

    for finding in final_findings:
        print(f"\n[TARGET] {finding['ip']}:{finding['port']} ({finding['service']})")
        print(f"[SCRIPT] {finding['script_name']}")
        print(f"[INTENT] {finding['intent']}")
        
        # Extracting the "Shine" (NSE Output)
        print("[RESULT] Findings:")
        lines = finding['raw_output'].split('\n')
        found_result = False
        
        for line in lines:
            # NSE results in Nmap output always start with | or |_
            if line.startswith('|') or line.startswith('|_'):
                print(f"    {line}")
                found_result = True
        
        if not found_result:
            print("    [!] No specific vulnerabilities or information exposed.")
        
        print("-" * 30)

def main():
    global input_ip
    ipToScan:str = ""
    ipMatches:list = []
    enumeration_result: dict[str, dict[str, Any]] = {}
    strike_plan: list[dict[str, Any]] = []
    final_findings: List[Dict[str, Any]] = []

    if len(sys.argv) != 2:
        print("Incorrect number of program arguments")
        print("Exiting...")
        sys.exit(1)
    else:
        input_ip = sys.argv[1]

    ipToScan = sanitize_input()
    ipMatches = initiate_arpScan(ipToScan)

    # FAIL-SAFE: Stop execution if no live IPs are found to prevent cascading errors
    if not ipMatches:
        print("Exiting: No target IPs identified.")
        sys.exit(0)

    print("Live Ips collected are : ")
    print(ipMatches)

    print("Enumerating ips....")
    enumeration_result = enumerate_scanList(ipMatches)

    # FAIL-SAFE: Check if any services were found
    if not enumeration_result:
        print("Exiting: No open ports discovered.")
        sys.exit(0)

    print(f"Enumeration Result : {enumeration_result}")

    print()
    print("Indexing nse scripts ...")
    index_nse_library()
    print()

    #read_indexed_library()

    strike_plan = generate_strike_plan(enumeration_result)
    #read_strike_plan(strike_plan)

    # FAIL-SAFE: Skip execution if no scripts matched
    if strike_plan:
        final_findings = execute_strike_plan(strike_plan)
        if final_findings:
            generate_final_report(final_findings)
    else:
        print("[!] No targeted scripts found for the discovered services.")


if __name__ == "__main__":
    main()

   
    