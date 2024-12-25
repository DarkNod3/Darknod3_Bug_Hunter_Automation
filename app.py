

# ------------------------------
# Import necessary modules
# ------------------------------
from flask import Flask, render_template, request, jsonify, Response, send_file
import subprocess
import threading
import os
import time
import random
import json
import requests
from concurrent.futures import ThreadPoolExecutor
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from datetime import datetime, timedelta
from typing import Optional, Dict, Any















# Get the current user's home directory
USER_HOME = os.path.expanduser("~")

# Base directory for scripts
SCRIPTS_DIR = os.path.join(USER_HOME, "darknod3_tool/scripts")

# Function to get the full path of a script
def get_script_path(tool_name):
    script_map = {
        "ping": "bug_hunt.sh",
        "special_subdomain_scan": "special_subdomain_scan.sh",
        "new_bash1": "new_bash1.sh",
        "new_bash2": "new_bash2.sh",
        "new_bash3": "new_bash3.sh",
        "new_bash4": "new_bash4.sh",
        "new_bash5": "new_bash5.sh",
        "new_bash6": "new_bash6.sh",
        "new_bash7": "new_bash7.sh",
        "new_bash8": "new_bash8.sh",
        "nmap_ad": "nmap_scan.sh",
        "sub_sscan": "sublist3r_scan.sh",
        "dir_scan": "dirsearch_scan.sh",
        "custom": "custom_scan.sh"
    }





    # Get the script filename from the map
    script_filename = script_map.get(tool_name)

    # If the tool name is not found in the map, return None
    if not script_filename:
        return None

    # Construct the full script path
    return os.path.join(SCRIPTS_DIR, script_filename)





# ------------------------------
# Initialize the Flask application
# ------------------------------
app = Flask(__name__)










# ------------------------------
# Global variables
# ------------------------------
scan_in_progress = False        # Indicates if a scan is currently running
current_process = None          # Stores the current running process
output_text = ""                # Stores the scan output text
output_file_path = "scan_output.txt"  # Path to store scan output file
current_processes = []  # List to store all running scan processes








# ------------------------------
# Home route
# Renders the main HTML page (index.html)
# ------------------------------
@app.route('/')
def index():
    return render_template('index.html')





def clean_ansi_codes(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    cleaned_text = ansi_escape.sub('', text)
    cleaned_text = re.sub(r'\[\[[0-9;]*m[A-Z]+\[0m\]', '', cleaned_text)
    return cleaned_text.strip()








# ------------------------------
# Tool Installation Route
# Installs specified tools based on user input
# ------------------------------
@app.route('/install_tool', methods=['POST'])
def install_tool():
    data = request.get_json()
    tool = data.get('tool')
    apiProvider = data.get('apiProvider', "")
    apiKey = data.get('apiKey', "")
    config_file = "/home/kali/.config/subfinder/provider-config.yaml"

    # Validate the tool name
    if not tool:
        return jsonify({"status": "error", "message": "No tool specified"})

    install_command = ""

    if tool == "subfinder":
        install_command = "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    elif tool == "httpx":
        install_command = "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
    elif tool == "nuclei":
        install_command = "sudo apt install nuclei -y"
    elif tool == "amass":
        install_command = "go install -v github.com/owasp-amass/amass/v3/...@latest"
    elif tool == "sublist3r":
        install_command = """
        git clone https://github.com/aboul3la/Sublist3r.git sublist3r && \
        cd sublist3r && \
        sudo apt update && \
        sudo apt install python3-pip -y && \
        pip3 install -r requirements.txt
        """
    elif tool == "sublist3r_install_api":
        install_command = """
        git clone https://github.com/aboul3la/Sublist3r.git sublist3r && \
        cd sublist3r && \
        sudo apt update && \
        sudo apt install python3-pip -y && \
        pip3 install -r requirements.txt
        """
        # Update API key in the configuration file
        if apiProvider and apiKey:
            try:
                with open(config_file, "r") as file:
                    lines = file.readlines()

                # Rewrite existing API key or add new entry
                with open(config_file, "w") as file:
                    updated = False
                    for line in lines:
                        if line.startswith(f"{apiProvider}:"):
                            file.write(f"{apiProvider}: [{apiKey}]\n")
                            updated = True
                        else:
                            file.write(line)
                    if not updated:
                        file.write(f"{apiProvider}: [{apiKey}]\n")

                return jsonify({"status": "success", "output": f"API key for {apiProvider} updated successfully."})
            except Exception as e:
                return jsonify({"status": "error", "message": f"Failed to update API key: {str(e)}"})
    else:
        return jsonify({"status": "error", "message": "Unknown tool specified"})

    # Execute the installation command
    try:
        process = subprocess.Popen(install_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()

        if process.returncode == 0:
            return jsonify({"status": "success", "output": stdout})
        else:
            return jsonify({"status": "error", "message": stderr})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})









def get_script_path(tool_name: str) -> Optional[str]:
    """Get the path for external script if it exists"""
    script_dir = "scripts"
    script_path = os.path.join(script_dir, f"{tool_name}.sh")
    return script_path if os.path.exists(script_path) else None

@app.route('/get_command', methods=['POST'])
def get_command():
    try:
        data = request.form if request.form else request.get_json()
        scan_type = data.get('scan_type', '').lower()
        tool_name = data.get('tool_name', '').lower()
        target_url = data.get('target_url', '')
        token = data.get('token', '')

        if not all([scan_type, tool_name, target_url]):
            return jsonify({
                "status": "error",
                "message": "Missing required information. Please provide scan_type, tool_name, and target_url."
            }), 400

        commands = {
            "recon_scan": {
                "nmap": f"nmap -sC -sV -O -p- -T4 {target_url}",
                "masscan": f"masscan -p1-65535 {target_url} --rate=1000",
                "ping": f"ping -c 4 {target_url}",
                "theharvester": f"theHarvester -d {target_url} -b all -l 500",
                "reconng": f"recon-ng -m marketplace install all; recon-ng -w recon_workspace",
                "spiderfoot": f"spiderfoot -s {target_url} -l 127.0.0.1:5001",
                "metagoofil": f"metagoofil -d {target_url} -t pdf,doc,xls,ppt,odp,ods,docx,xlsx,pptx -o /tmp/results",
                "shodan": f"shodan domain {target_url}",
                "censys": f"censys search '{target_url}'",
                "dnsenum": f"dnsenum --noreverse {target_url}",
                "wafw00f": f"wafw00f {target_url}",
                "whatweb": f"whatweb -a 3 {target_url}"
            },
            "allinone_scan": {
                "nuclei": f"nuclei -u {target_url} -silent -severity critical,high,medium",
                "special_subdomain_scan": f"special_subdomain_scan {target_url}",
                "new_bash1": f"new_bash1 {target_url}",
                "new_bash2": f"new_bash2 {target_url}",
                "new_bash3": f"new_bash3 {target_url}",
                "new_bash4": f"new_bash4 {target_url}",
                "new_bash5": f"new_bash5 {target_url}",
                "new_bash6": f"new_bash6 {target_url}",
                "new_bash7": f"new_bash7 {target_url}",
                "new_bash8": f"new_bash8 {target_url}",
                "nikto": f"nikto -h {target_url} -Tuning x 123458",
                "arachni": f"arachni {target_url} --scope-directory-depth-limit=5 --report-save-path=/tmp/arachni_report.afr",
                "wapiti": f"wapiti -u {target_url} -f html -m all",
                "openvas": f"gvm-cli socket --xml '<commands>'",
                "zap": f"zap-cli quick-scan -s all -r {target_url}",
                "acunetix": f"acunetix_console --scan {target_url}",
                "burpsuite": f"burpsuite_cli --unpause-spider-and-scan {target_url}"
            },
            "dorks_scan": {
                "googledorks": f"python3 googledorker.py -d {target_url} -t 10",
                "ghdb": f"python3 ghdb_scraper.py -d {target_url} --category all",
                "gospider": f"gospider -s {target_url} -d 3 -c 5 -t 100",
                "githubdorks": f"python3 github_dorks.py -d {target_url} -t github_tokens.txt",
                "pagodo": f"python3 pagodo.py -d {target_url} -g dorks.txt",
                "snitch": f"snitch -C {target_url}",
                "gitgraber": f"gitGraber.py -k keywords.txt -d {target_url}"
            },
            "subdomain_scan": {
                "amass": f"amass enum -active -d {target_url} -config config.ini",
                "subfinder": f"subfinder -d {target_url} -all -cs",
                "assetfinder": f"assetfinder --subs-only {target_url}",
                "findomain": f"findomain -t {target_url} --output",
                "massdns": f"massdns -r resolvers.txt -t A -o S -w results.txt {target_url}",
                "knockpy": f"knockpy {target_url}",
                "altdns": f"altdns -i subdomains.txt -o output.txt -w words.txt",
                "shuffledns": f"shuffledns -d {target_url} -w wordlist.txt -r resolvers.txt",
                "sudomy": f"sudomy -d {target_url} -dP",
                "chaos": f"chaos -d {target_url} -key YOUR_API_KEY -o output.txt"
            },
            "vuln_scan": {
                "nuclei": f"nuclei -u {target_url} -t nuclei-templates -severity critical,high -silent",
                "nikto": f"nikto -h {target_url} -Tuning 123bcd",
                "wapiti": f"wapiti -u {target_url} -m all except backup",
                "arachni": f"arachni {target_url} --checks=*",
                "openvas": f"gvm-cli socket --xml '<commands>'",
                "acunetix": f"acunetix_console --scan {target_url}",
                "nessus": f"nessuscli scan --targets {target_url}",
                "nexpose": f"nexpose-cli -r {target_url}",
                "qualys": f"qualys-cli scan start -t {target_url}"
            },
            "xss_scan": {
                "xsstrike": f"xsstrike -u {target_url} --crawl --fuzzer --params",
                "dalfox": f"dalfox url {target_url} -b hahwul.xss.ht --deep-domxss",
                "brutexss": f"brutexss -u {target_url} -p payloads.txt",
                "kxss": f"kxss {target_url}",
                "xsshunter": f"xsshunter-client -u {target_url}",
                "findom-xss": f"findom-xss.py -u {target_url}",
                "xspear": f"xspear -u {target_url} --cookie='csrf=token'",
                "axiom": f"axiom-scan {target_url} -m xss"
            },
            "sql_scan": {
                "sqlmap": f"sqlmap -u {target_url} --batch --risk=3 --level=5 --threads=10 --tamper=space2comment",
                "nosqlmap": f"nosqlmap -u {target_url} --bruteforce",
                "bbqsql": f"bbqsql -u {target_url}",
                "jsql": f"java -jar jsql-injection.jar -u {target_url}",
                "mssqlproxy": f"mssqlproxy -t {target_url}",
                "sqlninja": f"sqlninja -m test -t {target_url}",
                "powerupSQL": f"PowerUpSQL.ps1 -Instance {target_url}",
                "sqlbrute": f"sqlbrute -t {target_url} -u users.txt -p passes.txt"
            },
            "files_scan": {
                "gobuster": f"gobuster dir -u {target_url} -w /usr/share/wordlists/dirb/big.txt -t 50 -x php,asp,aspx,jsp,html,zip,jar,sql",
                "dirsearch": f"dirsearch -u {target_url} -e php,asp,aspx,jsp,html,zip,jar -x 403,404 -t 50",
                "ffuf": f"ffuf -u {target_url}/FUZZ -w /usr/share/wordlists/dirb/big.txt -mc 200,204,301,302,307,401,403",
                "wfuzz": f"wfuzz -c -z file,/usr/share/wordlists/dirb/big.txt --hc 404 {target_url}/FUZZ",
                "feroxbuster": f"feroxbuster -u {target_url} -w /usr/share/wordlists/dirb/big.txt -x php,asp,aspx,jsp,html,zip",
                "dirb": f"dirb {target_url} /usr/share/wordlists/dirb/big.txt -X .php,.asp,.aspx,.jsp,.html,.zip",
                "rustbuster": f"rustbuster dir -u {target_url} -w wordlist.txt",
                "dirbuster": f"java -jar DirBuster.jar -u {target_url}"
            },
            "file_upload_scan": {
                "burp_upload_scanner": "Run Burp Suite and enable Upload Scanner extension",
                "upload_exploiter": f"python3 upload_exploiter.py {target_url}",
                "fuxploider": f"fuxploider -u {target_url} -e php,asp,aspx,jsp,html",
                "nmap_upload_script": f"nmap -p 80 --script http-fileupload-exploiter {target_url}",
                "metasploit_upload": f"msfconsole -x 'use auxiliary/scanner/http/upload_scanner'",
                "uploadscanner": f"uploadscanner -t {target_url} -f payloads/",
                "multipart_scanner": f"multipart-scanner {target_url}",
                "putterpwnr": f"putterpwnr.py -t {target_url}"
            },
            "csrf_scan": {
                "burp_csrf_poc": "Generate CSRF PoC using Burp Suite",
                "zap_csrf_scan": f"zap-cli csrf-scan {target_url}",
                "xsstrike_csrf": f"xsstrike -u {target_url} --csrf",
                "owasp_csrf_tester": f"java -jar CSRFT.jar -u {target_url}",
                "csrfpocmaker": f"csrfpocmaker -u {target_url}",
                "csrf_scanner": f"csrf-scanner {target_url}",
                "csrftester": f"csrftester -u {target_url}",
                "breacher": f"breacher.py -u {target_url}"
            },
            "open_redirect_scan": {
                "kxss": f"kxss {target_url}",
                "open_redirect_scanner": f"python3 openredscan.py -u {target_url}",
                "burp_redirect": "Use Burp Suite Open Redirect Extension",
                "nuclei_redirect": f"nuclei -u {target_url} -t workflows/open-redirect.yaml",
                "oralyzer": f"oralyzer -u {target_url}",
                "redirexer": f"redirexer -u {target_url}",
                "dom_redirect": f"dom-redirect-scanner {target_url}",
                "urlredirect_scanner": f"urlredirect-scanner {target_url}"
            },
            "idor_scan": {
                "autorize": "Run Burp Suite and enable Autorize extension",
                "arjun": f"arjun -u {target_url} --headers ~/headers.txt",
                "burp_idor": "Use Burp Active Scan for IDOR",
                "postman_idor": "Test IDOR using Postman API scripts",
                "idor_hunter": f"idor-hunter -u {target_url}",
                "idfinder": f"idfinder -u {target_url}",
                "authz": f"authz -u {target_url}",
                "autorize_automated": f"autorize-automated {target_url}"
            },
            "race_condition_scan": {
                "race_the_web": f"race-the-web {target_url} --threads 100 --requests 1000",
                "turbo_intruder": "Run Turbo Intruder in Burp Suite",
                "concurrent_request_tester": f"python3 concurrent_tester.py -u {target_url} -t 50",
                "wrath": f"wrath -u {target_url} --threads 50",
                "racepwtotal": f"racepwtotal -u {target_url}",
                "race_condition_exploit": f"race-condition-exploit {target_url}",
                "racer": f"racer -u {target_url} -n 100",
                "racefuzz": f"racefuzz -u {target_url}"
            },
            "server_misconfig_scan": {
                "nikto": f"nikto -h {target_url} -Tuning 123457890abc",
                "nmap_vuln": f"nmap -sV --script=vuln,http-enum,http-headers {target_url}",
                "testssl": f"testssl.sh --severity HIGH --parallel {target_url}",
                "wapiti": f"wapiti -u {target_url} -m mod_security,backup,htaccess",
                "lynis": f"lynis audit system --quick",
                "configaudit": f"configaudit -t {target_url}",
                "prowler": f"prowler -T {target_url}",
                "scout": f"scout {target_url}"
            },
            "security_header_scan": {
                "curl_headers": f"curl -sI {target_url} | grep -i 'security'",
                "nmap_headers": f"nmap --script http-security-headers -p 443 {target_url}",
                "hardenize": f"hardenize-cli scan {target_url}",
                "mozilla_observatory": f"observatory {target_url} --format=report",
                "shcheck": f"shcheck.py {target_url}",
                "headercheck": f"headercheck -u {target_url}",
                "securityheaders": f"securityheaders-cli {target_url}",
                "header_scanner": f"header-scanner {target_url}"
            },
            "broken_auth_scan": {
                "jwt_tool": f"python3 jwt_tool.py {token if token else '--help'} -C -d -b" if token else "python3 jwt_tool.py --help",
                "burp_jwt_cracker": "Run Burp Suite JWT Cracker extension",
                "authmatrix": "Run AuthMatrix in Burp Suite",
                "hydra": f"hydra -L users.txt -P passes.txt {target_url} http-post-form '/login:user=^USER^&pass=^PASS^:F=Invalid'",
                "patator": f"patator http_fuzz url={target_url}/login method=POST body='user=FILE0&pass=FILE1'",
                "medusa": f"medusa -h {target_url} -U users.txt -P passes.txt -M http",
                "crowbar": f"crowbar -b web-form -c config.xml -u {target_url}",
                "auth_analyzer": f"auth-analyzer {target_url}"
            },
            "api_security_scan": {
                "astra": f"astra -t {target_url} --api",
                "arjun": f"arjun -u {target_url}/api -m GET,POST,PUT",
                "imperva": f"imperva-api-security scan {target_url}",
                "dredd": f"dredd api-description.yml {target_url}",
                "owasp_zap_api": f"zap-api-scan.py -t {target_url} -f openapi",
                "taurus": f"bzt api-test.yml",
                "gotestwaf": f"gotestwaf -u {target_url}"
            }
        }

        # Check for external script first
        script_path = get_script_path(tool_name)
        if script_path:
            command = f"bash {script_path} {target_url}"
            return jsonify({
                "status": "success",
                "command": command,
                "message": "External command constructed"
            })

        # Get the category-specific commands
        category_commands = commands.get(scan_type)
        if not category_commands:
            return jsonify({
                "status": "error",
                "message": f"Invalid scan type: {scan_type}"
            }), 400

        # Get the specific tool command
        command = category_commands.get(tool_name)
        if not command:
            return jsonify({
                "status": "error",
                "message": f"Invalid tool name: {tool_name} for scan type: {scan_type}"
            }), 400

        # For tools that require GUI or manual intervention
        if command.startswith("Run ") or command.startswith("Use ") or command.startswith("Test "):
            return jsonify({
                "status": "success",
                "command": command,
                "message": "Manual intervention required",
                "requires_manual": True
            })

        # Execute the command asynchronously
        try:
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            return jsonify({
                "status": "success",
                "command": command,
                "message": "Command running asynchronously",
                "pid": process.pid
            })
            
        except subprocess.SubprocessError as e:
            return jsonify({
                "status": "error",
                "message": f"Command execution failed: {str(e)}",
                "command": command
            }), 500
            
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"An unexpected error occurred: {str(e)}"
        }), 500

# Add a route to check command status
@app.route('/command_status/<int:pid>', methods=['GET'])
def command_status(pid):
    try:
        # Check if process is still running
        os.kill(pid, 0)
        return jsonify({
            "status": "success",
            "running": True,
            "message": "Command still running"
        })
    except ProcessLookupError:
        return jsonify({
            "status": "success",
            "running": False,
            "message": "Command completed"
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error checking command status: {str(e)}"
        }), 500
































# Global variables
proxy_sources = [
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt"
]

proxy_list = []
working_proxies = []
current_proxy = None
proxy_enabled = False
proxy_server_running = False
auto_rotate_interval = 60
validation_threads = 20
proxy_lock = threading.Lock()
PROXY_CACHE_FILE = "proxy_cache.json"

# ------------------------------
# Proxy Management Functions
# ------------------------------

def fetch_proxies():
    """Fetch proxies from sources"""
    temp_proxies = []
    for url in proxy_sources:
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                proxies = response.text.splitlines()
                temp_proxies.extend([proxy.strip() for proxy in proxies if proxy.strip()])
                print(f"Fetched {len(proxies)} proxies from {url}")
        except Exception as e:
            print(f"Error fetching proxies from {url}: {e}")
    return temp_proxies

def validate_proxy(proxy):
    """Test a single proxy"""
    try:
        proxy_dict = {"http": f"http://{proxy}", "https": f"http://{proxy}"}
        response = requests.get("https://api.ipify.org?format=json", proxies=proxy_dict, timeout=5)
        if response.status_code == 200:
            print(f"Valid proxy found: {proxy}")
            return proxy
    except:
        pass
    return None

def validate_proxies(proxy_list):
    """Validate multiple proxies in parallel"""
    print("Validating proxies...")
    valid_proxies = []
    with ThreadPoolExecutor(max_workers=validation_threads) as executor:
        results = list(executor.map(validate_proxy, proxy_list))
        valid_proxies = [proxy for proxy in results if proxy]
    print(f"Found {len(valid_proxies)} working proxies")
    return valid_proxies

def rotate_proxy():
    """Select a new proxy from working proxies"""
    global current_proxy
    with proxy_lock:
        if working_proxies:
            current_proxy = random.choice(working_proxies)
            print(f"Rotated to proxy: {current_proxy}")
            return True
        current_proxy = None
        print("No working proxies available")
        return False

def auto_rotate_proxies():
    """Automatically rotate proxies at intervals"""
    while proxy_server_running:
        if proxy_enabled and working_proxies:
            rotate_proxy()
        time.sleep(auto_rotate_interval)

def save_working_proxies():
    """Save validated proxies to a cache file"""
    try:
        cache_data = {
            "timestamp": datetime.now().isoformat(),
            "proxies": list(working_proxies)
        }
        with open(PROXY_CACHE_FILE, "w") as f:
            json.dump(cache_data, f)
            print(f"Saved {len(working_proxies)} working proxies to cache")
    except Exception as e:
        print(f"Error saving proxies: {e}")

def load_cached_proxies():
    """Load proxies from cache if valid"""
    try:
        if os.path.exists(PROXY_CACHE_FILE):
            with open(PROXY_CACHE_FILE, "r") as f:
                cache_data = json.load(f)
                cache_time = datetime.fromisoformat(cache_data["timestamp"])
                if datetime.now() - cache_time < timedelta(hours=24):
                    print(f"Loading {len(cache_data['proxies'])} proxies from cache")
                    return cache_data["proxies"]
    except Exception as e:
        print(f"Error loading proxies: {e}")
    return None

def proxy_manager():
    """Main proxy management function"""
    global working_proxies, proxy_list
    while proxy_server_running:
        try:
            cached_proxies = load_cached_proxies()
            if cached_proxies:
                working_proxies = cached_proxies
                print(f"Using {len(working_proxies)} cached proxies")
            else:
                print("Fetching new proxies...")
                proxy_list = fetch_proxies()
                working_proxies = validate_proxies(proxy_list)
                if working_proxies:
                    save_working_proxies()
                    print(f"Found {len(working_proxies)} new working proxies")

            if working_proxies:
                rotate_proxy()
            time.sleep(3600)  # Refresh every hour
        except Exception as e:
            print(f"Error in proxy manager: {e}")
            time.sleep(300)

# ------------------------------
# API Endpoints
# ------------------------------

@app.route('/startProxyServer', methods=['POST'])
def start_proxy_server():
    global proxy_server_running, proxy_enabled
    with proxy_lock:
        if not proxy_server_running:
            proxy_server_running = True
            proxy_enabled = True
            threading.Thread(target=proxy_manager, daemon=True, name="ProxyManager").start()
            threading.Thread(target=auto_rotate_proxies, daemon=True, name="ProxyRotator").start()
            return jsonify({"status": "success", "message": "Proxy server started"})
    return jsonify({"status": "error", "message": "Server already running"})

@app.route('/stopProxyServer', methods=['POST'])
def stop_proxy_server():
    global proxy_server_running, proxy_enabled, current_proxy
    with proxy_lock:
        proxy_server_running = False
        proxy_enabled = False
        current_proxy = None
        return jsonify({"status": "success", "message": "Proxy server stopped"})

@app.route('/get_ip', methods=['GET'])
def get_ip():
    try:
        if proxy_enabled and current_proxy:
            try:
                proxy_dict = {"http": f"http://{current_proxy}", "https": f"http://{current_proxy}"}
                response = requests.get("https://api.ipify.org?format=json", proxies=proxy_dict, timeout=5)
                if response.status_code == 200:
                    ip = response.json().get('ip')
                    print(f"Using proxy: {current_proxy} | IP: {ip}")
                    return jsonify({
                        "status": "success",
                        "ip": ip,
                        "proxy": True,
                        "proxy_server": current_proxy
                    })
            except Exception as e:
                print(f"Proxy request failed: {e}")
                rotate_proxy()

        # Direct connection if proxy is disabled or failed
        response = requests.get("https://api.ipify.org?format=json", timeout=5)
        return jsonify({
            "status": "success",
            "ip": response.json().get('ip'),
            "proxy": False
        })
    except Exception as e:
        print(f"Error fetching IP: {e}")
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

# Start background threads
threading.Thread(target=auto_rotate_proxies, daemon=True, name="AutoRotateProxies").start()

































































# ------------------------------
# Function to  reset Scan
#
# ------------------------------




@app.route('/reset_scan', methods=['POST'])
def reset_scan():
    global scan_in_progress, current_processes
    
    try:
        # First attempt to terminate all processes gracefully
        if scan_in_progress:
            for process in current_processes:
                try:
                    # Try graceful termination first
                    process.terminate()
                    # Give process time to terminate gracefully
                    process.wait(timeout=3)
                except TimeoutError:
                    # If process doesn't terminate in time, force kill
                    try:
                        process.kill()
                        process.wait(timeout=1)
                    except Exception as e:
                        print(f"Error force killing process: {e}")
                except Exception as e:
                    print(f"Error terminating process: {e}")
            
            current_processes.clear()
        
        # Reset the scan flag
        scan_in_progress = False
        
        # Clean up output file if it exists
        if os.path.exists(output_file_path):
            try:
                os.remove(output_file_path)
            except PermissionError as e:
                return jsonify({
                    "status": "error",
                    "message": f"Could not remove output file: Permission denied"
                }), 500
            except Exception as e:
                return jsonify({
                    "status": "error",
                    "message": f"Could not remove output file: {str(e)}"
                }), 500
                
        return jsonify({
            "status": "success",
            "message": "Scan reset successfully"
        })
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error during reset: {str(e)}"
        }), 500

# ------------------------------
# Function to run a Bash command
# Saves the output to a file
# ------------------------------
def run_bash_command(command):
    global output_text, scan_in_progress
    output_text = ""
    
    try:
        with open(output_file_path, "w", encoding='utf-8') as output_file:
            # Use list for command arguments to prevent shell injection
            current_process = subprocess.Popen(
                command,
                shell=True,  # Be careful with shell=True, consider using shell=False with command list
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # Merge stderr into stdout
                text=True,
                bufsize=1,  # Line buffered
                universal_newlines=True
            )
            
            current_processes.append(current_process)  # Add to global process list
            
            try:
                while current_process.poll() is None:  # While process is running
                    line = current_process.stdout.readline()
                    if line:
                        output_text += line
                        output_file.write(line)
                        output_file.flush()
                        
                # Get remaining output after process completes
                remaining_output, _ = current_process.communicate()
                if remaining_output:
                    output_text += remaining_output
                    output_file.write(remaining_output)
                    output_file.flush()
                    
            except Exception as e:
                print(f"Error reading process output: {e}")
                current_process.terminate()
                raise
                
            finally:
                # Clean up
                if current_process in current_processes:
                    current_processes.remove(current_process)
                scan_in_progress = False
                
            # Check process return code
            if current_process.returncode != 0:
                raise subprocess.CalledProcessError(
                    current_process.returncode, 
                    command
                )
                
    except (IOError, OSError) as e:
        print(f"File operation error: {e}")
        scan_in_progress = False
        raise
        
    except Exception as e:
        print(f"Unexpected error in run_bash_command: {e}")
        scan_in_progress = False
        raise

    return output_text


# ------------------------------
# Scan Start Route
# Initiates the scan in a new thread
# ------------------------------
@app.route('/start_scan', methods=['POST'])
def start_scan():
    global scan_in_progress

    if scan_in_progress:
        return jsonify({"status": "error", "message": "Scan already in progress"})

    command_input = request.form.get('command_input')

    if not command_input:
        return jsonify({"status": "error", "message": "No command provided"})

    scan_in_progress = True
    threading.Thread(target=run_bash_command, args=(command_input,)).start()

    return jsonify({"status": "Scan started"})

# ------------------------------
# Real-time Output Fetch Route
# Returns the current scan output
# ------------------------------
@app.route('/get_output', methods=['GET'])
def get_output():
    global scan_in_progress
    return jsonify({"output": output_text, "scan_in_progress": scan_in_progress})

# ------------------------------
# Stop Scan Route
# Terminates the ongoing scan process
# ------------------------------
@app.route('/stop_scan', methods=['POST'])
def stop_scan():
    global scan_in_progress, current_process

    if current_process:
        current_process.terminate()
        scan_in_progress = False
        current_process = None

    return jsonify({"status": "Scan stopped"})



























# ------------------------------
# Help Output Route
# Provides help information for specified tools
# ------------------------------
@app.route('/get_help_output', methods=['GET'])
def get_help_output():
    tool = request.args.get('tool')

    # Commands to fetch the tool's default help output
    help_command = {
        # Recon Scan Tools
        "nmap": "nmap -h",
        "masscan": "masscan -h",
        "ping": "ping -h",
        "theharvester": "theHarvester -h",
        "reconng": "recon-ng -h",
        "spiderfoot": "spiderfoot -h",
        "metagoofil": "metagoofil -h",
        "shodan": "shodan -h",
        "censys": "censys help",
        "dnsenum": "dnsenum -h",
        "wafw00f": "wafw00f -h",
        "whatweb": "whatweb -h",

        # All-in-One Scan Tools
        "nuclei": "nuclei -h",
        "nikto": "nikto -h",
        "arachni": "arachni -h",
        "wapiti": "wapiti -h",
        "openvas": "gvm-cli -h",
        "zap": "zap-cli -h",
        "acunetix": "acunetix_console -h",
        "burpsuite": "burpsuite_cli -h",

        # Dorks Scan Tools
        "googledorks": "python3 googledorker.py -h",
        "ghdb": "python3 ghdb_scraper.py -h",
        "gospider": "gospider -h",
        "githubdorks": "python3 github_dorks.py -h",
        "pagodo": "python3 pagodo.py -h",
        "snitch": "snitch -h",
        "gitgraber": "gitGraber.py -h",

        # Subdomain Scan Tools
        "amass": "amass -h",
        "subfinder": "subfinder -h",
        "assetfinder": "assetfinder -h",
        "findomain": "findomain -h",
        "massdns": "massdns -h",
        "knockpy": "knockpy -h",
        "altdns": "altdns -h",
        "shuffledns": "shuffledns -h",
        "sudomy": "sudomy -h",
        "chaos": "chaos -h",

        # Vulnerability Scan Tools
        "nessus": "nessuscli scan -h",
        "nexpose": "nexpose-cli -h",
        "qualys": "qualys-cli -h",

        # XSS Scan Tools
        "xsstrike": "python3 xsstrike.py -h",
        "dalfox": "dalfox -h",
        "brutexss": "brutexss -h",
        "kxss": "kxss -h",
        "xsshunter": "xsshunter-client -h",
        "findom-xss": "findom-xss.py -h",
        "xspear": "xspear -h",
        "axiom": "axiom-scan -h",

        # SQL Scan Tools
        "sqlmap": "sqlmap -h",
        "nosqlmap": "nosqlmap -h",
        "bbqsql": "bbqsql -h",
        "jsql": "java -jar jsql-injection.jar --help",
        "mssqlproxy": "mssqlproxy -h",
        "sqlninja": "sqlninja -h",
        "powerupSQL": "PowerUpSQL.ps1 -h",
        "sqlbrute": "sqlbrute -h",

        # Files Scan Tools
        "gobuster": "gobuster -h",
        "dirsearch": "dirsearch -h",
        "ffuf": "ffuf -h",
        "wfuzz": "wfuzz -h",
        "feroxbuster": "feroxbuster -h",
        "dirb": "dirb -h",
        "rustbuster": "rustbuster -h",
        "dirbuster": "java -jar DirBuster.jar -h",

        # File Upload Scan Tools
        "fuxploider": "python3 fuxploider.py -h",
        "uploadscanner": "uploadscanner -h",
        "multipart_scanner": "multipart-scanner -h",
        "putterpwnr": "putterpwnr.py -h",

        # CSRF Scan Tools
        "csrfpocmaker": "csrfpocmaker -h",
        "csrf_scanner": "csrf-scanner -h",
        "csrftester": "csrftester -h",
        "breacher": "breacher.py -h",

        # Open Redirect Scan Tools
        "oralyzer": "oralyzer -h",
        "redirexer": "redirexer -h",
        "dom_redirect": "dom-redirect-scanner -h",
        "urlredirect_scanner": "urlredirect-scanner -h",

        # IDOR Scan Tools
        "idor_hunter": "idor-hunter -h",
        "idfinder": "idfinder -h",
        "authz": "authz -h",
        "autorize_automated": "autorize-automated -h",

        # Race Condition Scan Tools
        "race_the_web": "race-the-web -h",
        "racepwtotal": "racepwtotal -h",
        "racer": "racer -h",
        "racefuzz": "racefuzz -h",

        # Server Misconfig Scan Tools
        "lynis": "lynis -h",
        "configaudit": "configaudit -h",
        "prowler": "prowler -h",
        "scout": "scout -h",

        # Security Header Scan Tools
        "shcheck": "shcheck.py -h",
        "headercheck": "headercheck -h",
        "securityheaders": "securityheaders-cli -h",
        "header_scanner": "header-scanner -h",

        # Broken Auth Scan Tools
        "jwt_tool": "python3 jwt_tool.py -h",
        "hydra": "hydra -h",
        "patator": "patator -h",
        "medusa": "medusa -h",
        "crowbar": "crowbar -h",
        "auth_analyzer": "auth-analyzer -h",

        # API Security Scan Tools
        "astra": "astra -h",
        "arjun": "arjun -h",
        "dredd": "dredd --help",
        "taurus": "bzt -h",
        "gotestwaf": "gotestwaf -h"
    }

    # Custom help information with detailed usage examples
    custom_help = {
        # Recon Scan Tools
        "nmap": """🔍 **Nmap Usage Guide**:
1. Basic scan: `nmap -sV -sC <target>`
2. Full port scan: `nmap -p- <target>`
3. OS detection: `nmap -O <target>`
4. Script scan: `nmap --script=vuln <target>`
5. Tips:
   - Use `-sS` for SYN scan
   - Use `-sV` for service version detection
   - Use `-oN output.txt` to save results""",

        "masscan": """🔍 **Masscan Usage Guide**:
1. Basic scan: `masscan <target> -p80,443`
2. Full port range: `masscan <target> -p0-65535`
3. Rate limiting: `masscan <target> --rate=1000`
4. Tips:
   - Be careful with scan rate
   - Use `--banners` for service detection""",

        # More tools' custom help would follow the same pattern...
        # Adding a few key ones as examples:

        "nuclei": """🔍 **Nuclei Usage Guide**:
1. Basic scan: `nuclei -u <target>`
2. Template selection: `nuclei -t nuclei-templates`
3. Severity based: `nuclei -s high,critical`
4. Tips:
   - Use `-silent` for clean output
   - Update templates regularly
   - Use `-c` for concurrent execution""",

        "sqlmap": """🔍 **SQLMap Usage Guide**:
1. Basic scan: `sqlmap -u "<url>"`
2. Post data: `sqlmap -u "<url>" --data="id=1"`
3. Database dump: `sqlmap -u "<url>" --dbs`
4. Tips:
   - Use `--batch` for automated runs
   - Use `--risk=3` for thorough testing
   - Use `--threads=10` for faster scanning""",

        "subfinder": """🔍 **Subfinder Usage Guide**:
1. Basic enumeration: `subfinder -d <domain>`
2. Silent mode: `subfinder -d <domain> -silent`
3. All sources: `subfinder -d <domain> -all`
4. Tips:
   - Use `-oJ` for JSON output
   - Configure API keys for better results
   - Use `-recursive` for thorough scanning"""
    }

    help_cmd = help_command.get(tool)
    custom_info = custom_help.get(tool, "No custom help information available for this tool.")

    if not help_cmd:
        return jsonify({
            "status": "error",
            "message": f"Help information not available for {tool}",
            "custom_help": custom_info
        })

    try:
        # Execute help command and capture output
        help_output = subprocess.check_output(
            help_cmd.split(),
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )
        return jsonify({
            "status": "success",
            "help_output": help_output,
            "custom_help": custom_info
        })
    except subprocess.CalledProcessError as e:
        return jsonify({
            "status": "error",
            "message": f"Error executing help command: {str(e)}",
            "custom_help": custom_info
        })

    # Check if the tool command exists
    if not help_command:
        return jsonify({"status": "error", "message": "No help available for this tool"})

    try:
        # Run the tool's help command
        process = subprocess.Popen(help_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()

        # Fetch custom steps if available
        custom_steps = custom_help.get(tool, "")

        # Format the output with custom steps first, followed by default help
        output = f"{custom_steps}\n\n{'='*40}\n{stdout.strip()}"

        if process.returncode == 0:
            return jsonify({"status": "success", "output": output})
        else:
            return jsonify({"status": "error", "message": stderr})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})





# ------------------------------
# File Download Route
# Allows the user to download the scan output file
# ------------------------------
@app.route('/download', methods=['GET'])
def download():
    target = request.args.get('target', 'output')
    if os.path.exists(output_file_path):
        return send_file(output_file_path, as_attachment=True, download_name=f"{target}.txt")
    else:
        return "No output file available.", 404










# ------------------------------
# Main function
# Starts the Flask application
# ------------------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=770, debug=True)













