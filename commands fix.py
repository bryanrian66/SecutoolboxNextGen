# commands.py
import datetime
import subprocess
import logging
from constants import RESET, RED

# Setup logging
logging.basicConfig(filename="scan_log.log", level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

def save_to_html(results, output_file="results.html"):
    try:
        with open(output_file, "w") as file:
            file.write("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Scan Results</title>
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; margin: 20px; }
                    pre { background: #f4f4f4; padding: 10px; border:1px solid #ccc; }
                    hr { border: 1px solid #ddd; margin: 20px 0; }
                </style>
            </head>
            <body>
            <h1>Scan Results</h1>
            """)
            file.write(results)
            file.write("""
            </body>
            </html>
            """)
        print(f"Results saved to {output_file}")
    except Exception as e:
        print(f"Error saving results to HTML: {e}")

def log_to_html(tool_name, command, output):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html_content = f"""
    <div style="margin-bottom:20px;">
        <h2>{tool_name}</h2>
        <p><b>Time:</b> {timestamp}</p>
        <p><b>Command:</b> <code>{command}</code></p>
        <pre style="background:#f4f4f4;padding:10px;border:1px solid #ccc;">{output}</pre>
        <hr>
    </div>
    """
    with open("scan_report.html", "a") as f:
        f.write(html_content)

def run_addhosts(host, ip):
    try:
        command = f"sudo -- sh -c -e \"echo '{ip} {host}' >> /etc/hosts\";"
        logging.info(f"Running command: {command}") # Log the command
        subprocess.run(command, shell=True)
        logging.info(f"Successfully added {host} with IP {ip} to /etc/hosts") # Log success
    except Exception as e:
        logging.error(f"Error running addhost: {e}") # Log error if it occurs
        print(f"{RED}Error running addhost: {e}{RESET}")

def run_ffuf_subdomain(url, wordlist, word):
    try:
        command = f"ffuf -u 'http://{url}' -H 'Host: FUZZ.{url}' -w {wordlist} -F {word}"
        logging.info(f"Running command: {command}") # Log the command
        result = subprocess.getoutput(command)
        logging.info(f"FFUF command executed successfully: {command}") # Log success
        log_to_html("FFUF Subdomain", command, result) # Simpan hasil ke HTML
        print(result) # Cetak hasil di terminal
    except Exception as e:
        logging.error(f"Error running ffuf: {e}") # Log error if it occurs
        print(f"{RED}Error running ffuf: {e}{RESET}")

def run_ffuf(url, wordlist):
    try:
        command = f"ffuf -u {url}/FUZZ -w {wordlist} -t 100"
        result = subprocess.getoutput(command)
        print(result) # Cetak hasil di terminal
        log_to_html("FFUF", command, result) # Simpan hasil ke HTML
    except Exception as e:
        print(f"{RED}Error running ffuf: {e}{RESET}")

def run_nmap_full(target):
    try:
        command = f"sudo nmap -sC -sV -O --open -p 1-1000 --stats-every 10s {target} -Pn"
        logging.info(f"Running command: {command}") # Log command
        print(f"{RED}[INFO]{RESET} Running command: {command}") # Indikator progres
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=300) # Timeout 5 menit
        log_to_html("Nmap Full Scan", command, result.stdout) # Simpan hasil
        print(result.stdout) # Tampilkan hasil di terminal
    except subprocess.TimeoutExpired:
        print(f"{RED}Nmap process timed out!{RESET}")
        logging.error(f"Nmap process timed out: {command}")
    except Exception as e:
        print(f"{RED}Error running nmap: {e}{RESET}")
        logging.error(f"Error running nmap: {e}")

def run_nmap_udp(target):
    try:
        command = f"sudo nmap -Pn -sU -sV -sC --top-ports=20 {target}"
        result = subprocess.getoutput(command)
        print(result) # Cetak hasil di terminal
        log_to_html("Nmap UDP Scan", command, result) # Simpan hasil ke HTML
    except Exception as e:
        print(f"{RED}Error running nmap: {e}{RESET}")

def run_nmap_custom(target, custom):
    try:
        command = f"sudo nmap {custom} {target}"
        logging.info(f"Running command: {command}") # Log command
        print(f"{RED}[INFO]{RESET} Running command: {command}") # Indikator progres
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=300) # Timeout 5 menit
        log_to_html("Nmap Custom Scan", command, result.stdout) # Simpan hasil
        print(result.stdout) # Tampilkan hasil di terminal
    except subprocess.TimeoutExpired:
        print(f"{RED}Nmap custom process timed out!{RESET}")
        logging.error(f"Nmap custom process timed out: {command}")
    except Exception as e:
        print(f"{RED}Error running custom nmap: {e}{RESET}")
        logging.error(f"Error running custom nmap: {e}")

def run_whatweb(url):
    try:
        command = f"whatweb {url}"
        result = subprocess.getoutput(command)
        print(result) # Cetak hasil di terminal
        log_to_html("WhatWeb", command, result) # Simpan hasil ke HTML
    except Exception as e:
        print(f"{RED}Error running whatweb: {e}{RESET}")

def run_wfuzz(url, wordlist, word):
    try:
        command = f"wfuzz -c -t 100 -w {wordlist} -u http://{url} -H 'Host: FUZZ.{url}' --hw {word}"
        result = subprocess.getoutput(command)
        print(result) # Cetak hasil di terminal
        log_to_html("WFuzz", command, result) # Simpan hasil ke HTML
    except Exception as e:
        print(f"{RED}Error running wfuzz: {e}{RESET}")

def run_gobuster_dir(url, wordlist):
    try:
        command = f"gobuster dir -u {url} -w {wordlist} -t 100"
        result = subprocess.getoutput(command)
        print(result) # Cetak hasil di terminal
        log_to_html("Gobuster Directory", command, result) # Simpan hasil ke HTML
    except Exception as e:
        print(f"{RED}Error running gobuster: {e}{RESET}")

def run_gobuster_dns(url, wordlist, need):
    try:
        command = f"gobuster dns -d {url} -t 50 -w {wordlist} {need}"
        result = subprocess.getoutput(command)
        print(result) # Cetak hasil di terminal
        log_to_html("Gobuster DNS", command, result) # Simpan hasil ke HTML
    except Exception as e:
        print(f"{RED}Error running gobuster: {e}{RESET}")

def run_gobuster_vhost(url, wordlist):
    try:
        command = f"gobuster vhost -u {url} -t 50 -w {wordlist} --append-domain"
        result = subprocess.getoutput(command)
        print(result) # Cetak hasil di terminal
        log_to_html("Gobuster VHost", command, result) # Simpan hasil ke HTML
    except Exception as e:
        print(f"{RED}Error running gobuster: {e}{RESET}")

def run_dirsearch(url, wordlist):
    try:
        command = f"dirsearch -u {url} -e txt,bak,php,html,js,asp,aspx -x 403,404 -w {wordlist}"
        result = subprocess.getoutput(command)
        print(result) # Cetak hasil di terminal
        log_to_html("Dirsearch", command, result) # Simpan hasil ke HTML
    except Exception as e:
        print(f"{RED}Error running dirsearch: {e}{RESET}")

def run_feroxbuster(url, wordlist):
    try:
        command = f"feroxbuster -u {url} -w {wordlist} -k -x txt,bak,php,html,js,asp,aspx -C 503"
        result = subprocess.getoutput(command)
        print(result) # Cetak hasil di terminal
        log_to_html("Feroxbuster", command, result) # Simpan hasil ke HTML
    except Exception as e:
        print(f"{RED}Error running feroxbuster: {e}{RESET}")

# Active Directory        

def run_smbclient(url):
    try:
        command = f"smbclient -L \\\\{url} -N"
        result = subprocess.getoutput(command)
        print(result) # Cetak hasil di terminal
        log_to_html("SMBClient", command, result) # Simpan hasil ke HTML
    except Exception as e:
        print(f"{RED}Error running smbclient: {e}{RESET}")

def run_smbclient_user(url, user, password):
    try:
        command = f"smbclient -U {user}%{password} -L //{url}/"
        result = subprocess.getoutput(command)
        print(result) # Cetak hasil di terminal
        log_to_html("SMBClient User", command, result) # Simpan hasil ke HTML
    except Exception as e:
        print(f"{RED}Error running smbclient: {e}{RESET}")

def run_smbclient_login(url, user, share):
    try:
        command = f"smbclient -U {user} //{url}/{share}"
        result = subprocess.getoutput(command)
        print(result) # Cetak hasil di terminal
        log_to_html("SMBClient Login", command, result) # Simpan hasil ke HTML
    except Exception as e:
        print(f"{RED}Error running smbclient: {e}{RESET}")

def run_smbmap(url):
    try:
        command = f"smbmap -u '' -p '' -H {url}"
        result = subprocess.getoutput(command)
        print(result) # Cetak hasil di terminal
        log_to_html("Smbmap", command, result) # Simpan hasil ke HTML
    except Exception as e:
        print(f"{RED}Error running smbmap: {e}{RESET}")
def run_smbmap_user(url, user, password):
    try:
        command = f"smbmap -u {user} -p {password} -H {url}"
        result = subprocess.getoutput(command)
        print(result) # Cetak hasil di terminal
        log_to_html("Smbmap User", command, result) # Simpan hasil ke HTML
    except Exception as e:
        print(f"{RED}Error running smbmap: {e}{RESET}")

def run_evilwinrm_password(url, username, password):
    try:
        command = f"evil-winrm -i {url} -u {username} -p '{password}'"
        result = subprocess.getoutput(command)
        print(result) # Cetak hasil di terminal
        log_to_html("EvilWinRM Password", command, result) # Simpan hasil ke HTML
    except Exception as e:
        print(f"{RED}Error running evilwinrm: {e}{RESET}")

def run_evilwinrm_hash(url, username, hash):
    try:
        command = f"evil-winrm -i {url} -u {username} -H {hash}"
        result = subprocess.getoutput(command) # Tangkap outputnya
        print(result) # Cetak hasil di terminal
        log_to_html("EvilWinRM Hash", command, result) # Simpan hasil ke HTML
    except Exception as e:
        print(f"{RED}Error running evilwinrm: {e}{RESET}")

def run_crackmapexec_smb_password(url, username, password):
    try:
        command = f"sudo crackmapexec smb {url} -u {username} -p '{password}'"
        result = subprocess.getoutput(command) # Tangkap outputnya
        print(result) # Cetak hasil di terminal
        log_to_html("CrackMapExec SMB Password", command, result) # Simpan hasil ke HTML
    except Exception as e:
        print(f"{RED}Error running crackmapexec: {e}{RESET}")

def run_crackmapexec_smb_hash(url, username, hash):
    try:
        command = f"sudo crackmapexec smb {url} -u {username} -H {hash}"
        result = subprocess.getoutput(command) # Tangkap outputnya
        print(result) # Cetak hasil di terminal
        log_to_html("CrackMapExec SMB Hash", command, result) # Simpan hasil ke HTML
    except Exception as e:
        print(f"{RED}Error running crackmapexec: {e}{RESET}")

def run_crackmapexec_evil_password(url, username, password):
    try:
        command = f"sudo crackmapexec winrm {url} -u {username} -p '{password}' -x whoami --local-auth"
        result = subprocess.getoutput(command) # Tangkap outputnya
        print(result) # Cetak hasil di terminal
        log_to_html("CrackMapExec Evil Password", command, result) # Simpan hasil ke HTML
    except Exception as e:
        print(f"{RED}Error running crackmapexec: {e}{RESET}")

def run_crackmapexec_evil_hash(url, username, hash):
    try:
        command = f"sudo crackmapexec winrm {url} -u {username} -H {hash} -x whoami --local-auth"
        result = subprocess.getoutput(command) # Tangkap outputnya
        print(result) # Cetak hasil di terminal
        log_to_html("CrackMapExec Evil Hash", command, result) # Simpan hasil ke HTML
    except Exception as e:
        print(f"{RED}Error running crackmapexec: {e}{RESET}")

def run_rpcclient(url):
    try:
        command = f"rpcclient -U '' -N {url}"
        result = subprocess.getoutput(command) # Tangkap outputnya
        print(result) # Cetak hasil di terminal
        log_to_html("RPCClient", command, result) # Simpan hasil ke HTML
    except Exception as e:
        print(f"{RED}Error running rpcclient: {e}{RESET}")

def run_enum4linux(url):
    try:
        command = f"enum4linux -a {url}"
        result = subprocess.getoutput(command) # Tangkap outputnya
        print(result) # Cetak hasil di terminal
        log_to_html("Enum4Linux", command, result) # Simpan hasil ke HTML
    except Exception as e:
        print(f"{RED}Error running enum4linux: {e}{RESET}")

def run_snmpwalk_all(url):
    try:
        command = f"snmpwalk -c public -v1 -t 10 {url}"
        result = subprocess.getoutput(command) # Tangkap outputnya
        print(result) # Cetak hasil di terminal
        log_to_html("SNMPWalk All", command, result) # Simpan hasil ke HTML
    except Exception as e:
        print(f"{RED}Error running snmpwalk: {e}{RESET}")

def run_snmpwalk_extend(url):
    try:
        command = f"snmpwalk -v1 -c public {url} NET-SNMP-EXTEND-MIB::nsExtendObjects"
        result = subprocess.getoutput(command) # Tangkap outputnya
        print(result) # Cetak hasil di terminal
        log_to_html("SNMPWalk Extend", command, result) # Simpan hasil ke HTML
    except Exception as e:
        print(f"{RED}Error running snmpwalk: {e}{RESET}")

def run_xfreerdp(url, username, password):
    try:
        command = f"xfreerdp /u:{username} /p:{password} /v:{url}"
        result = subprocess.getoutput(command) # Tangkap outputnya
        print(result) # Cetak hasil di terminal
        log_to_html("XFreeRDP", command, result) # Simpan hasil ke HTML
    except Exception as e:
        print(f"{RED}Error running xfreerdp: {e}{RESET}")

def run_dnsenum(url, domain):
    try:
        command = f"dnsenum --dnsserver {url} -f /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt {domain} dnsenum VERSION:1.2.6"
        result = subprocess.getoutput(command) # Tangkap outputnya
        print(result) # Cetak hasil di terminal
        log_to_html("Dnsenum", command, result) # Simpan hasil ke HTML
    except Exception as e:
        print(f"{RED}Error running dnsenum: {e}{RESET}")

def run_kerbrute(url, domain, user):
    try:
        command = f"./kerbrute userenum --dc {url} -d {domain} {user}"
        result = subprocess.getoutput(command) # Tangkap outputnya
        print(result) # Cetak hasil di terminal
        log_to_html("Kerbrute", command, result) # Simpan hasil ke HTML
    except Exception as e:
        print(f"{RED}Error running kerbrute: {e}{RESET}")

def run_GetNPUsers(url, domain):
    try:
        command = f"impacket-GetNPUsers -dc-ip {url} -request '{domain}/'"
        result = subprocess.getoutput(command) # Tangkap outputnya
        print(result) # Cetak hasil di terminal
        log_to_html("GetNPUsers", command, result) # Simpan hasil ke HTML
    except Exception as e:
        print(f"{RED}Error running GetNPUsers: {e}{RESET}")

def run_psexec_password(url, user, password):
    try:
        command = f"impacket-psexec {user}:{password}@{url} cmd.exe"
        result = subprocess.getoutput(command) # Tangkap outputnya
        print(result) # Cetak hasil di terminal
        log_to_html("Psexec Password", command, result) # Simpan hasil ke HTML
    except Exception as e:
        print(f"{RED}Error running psexec: {e}{RESET}")

def run_psexec_hash(url, user, hash):
    try:
        command = f"impacket-psexec -hashes {hash} {user}@{url}"
        result = subprocess.getoutput(command) # Tangkap outputnya
        print(result) # Cetak hasil di terminal
        log_to_html("Psexec Hash", command, result) # Simpan hasil ke HTML
    except Exception as e:
        print(f"{RED}Error running psexec: {e}{RESET}")

def run_GetADUsers(url, domain, user):
    try:
        command = f"GetADUsers.py -all '{domain}/{user}' -dc-ip {url}"
        result = subprocess.getoutput(command) # Tangkap outputnya
        print(result) # Cetak hasil di terminal
        log_to_html("GetADUsers", command, result) # Simpan hasil ke HTML
    except Exception as e:
        print(f"{RED}Error running GetADUsers: {e}{RESET}")

def run_ldap(url, dc_1, dc_2):
    try:
        command = f"ldapsearch -x -H ldap://{url} -b 'DC={dc_1},DC={dc_2}'"
        result = subprocess.getoutput(command) # Tangkap outputnya
        print(result) # Cetak hasil di terminal
        log_to_html("LDAP", command, result) # Simpan hasil ke HTML
    except Exception as e:
        print(f"{RED}Error running GetADUsers: {e}{RESET}")

def run_secretsdump(url, domain, username, password):
    try:
        command = f"secretsdump.py {domain}/{username}:'{password}'@{url}"
        result = subprocess.getoutput(command) # Tangkap outputnya
        print(result) # Cetak hasil di terminal
        log_to_html("SecretsDump", command, result) # Simpan hasil ke HTML
    except Exception as e:
        print(f"{RED}Error running secretsdump: {e}{RESET}")

def run_mssqlclient(url, domain, username, password, db):
    try:
        command = f"mssqlclient.py -db {db} {domain}/{username}:'{password}'@{url} -windows-auth"
        result = subprocess.getoutput(command) # Tangkap outputnya
        print(result) # Cetak hasil di terminal
        log_to_html("MSSQLClient", command, result) # Simpan hasil ke HTML
    except Exception as e:
        print(f"{RED}Error running mssqlclient: {e}{RESET}")

def run_GetUserSPNs(url, domain, user):
    try:
        command = f"GetUserSPNs.py {domain}/{user} -dc-ip {url} -request"
        result = subprocess.getoutput(command) # Tangkap outputnya
        print(result) # Cetak hasil di terminal
        log_to_html("GetUserSPNs", command, result) # Simpan hasil ke HTML
    except Exception as e:
        print(f"{RED}Error running mssqlclient: {e}{RESET}")

def run_GetNPUsers_file(url, domain, username):
    try:
        command = f"GetNPUsers.py '{domain}/' -usersfile {username} -dc-ip {url}"
        result = subprocess.getoutput(command) # Tangkap outputnya
        print(result) # Cetak hasil di terminal
        log_to_html("GetNPUsers File", command, result) # Simpan hasil ke HTML
    except Exception as e:
        print(f"{RED}Error running GetNPUsers: {e}{RESET}")

def print_scanning_results():
    try:
        with open("scan_report.html", "r") as f:
            content = f.read()
        print(content)
    except FileNotFoundError:
        print(f"{RED}No scanning results found. The report file 'scan_report.html' does not exist.{RESET}")
    except Exception as e:
        print(f"{RED}Error reading scanning results: {e}{RESET}")

