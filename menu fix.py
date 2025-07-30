# menu.py
import subprocess
import os
import webbrowser
from commands import (
    run_GetADUsers, run_GetNPUsers, run_GetNPUsers_file, run_GetUserSPNs, run_addhosts,
    run_crackmapexec_evil_hash, run_crackmapexec_evil_password, run_crackmapexec_smb_hash,
    run_crackmapexec_smb_password, run_dirsearch, run_dnsenum, run_enum4linux, run_evilwinrm_hash,
    run_evilwinrm_password, run_feroxbuster, run_ffuf, run_ffuf_subdomain, run_gobuster_dir,
    run_gobuster_dns, run_gobuster_vhost, run_kerbrute, run_ldap, run_mssqlclient, run_nmap_full,
    run_nmap_udp, run_nmap_custom, run_psexec_hash, run_psexec_password, run_rpcclient,
    run_secretsdump, run_smbclient, run_smbclient_login, run_smbclient_user, run_smbmap,
    run_smbmap_user, run_snmpwalk_all, run_snmpwalk_extend, run_wfuzz, run_whatweb,
    run_xfreerdp, print_scanning_results, save_to_html
)
from constants import BOLD, GREEN, LCYAN, LPURPLE, RESET, RED

# Preset wordlists and filters
PRESET = {
    "ffuf_dir": {
        "wordlist": "/usr/share/seclists/Discovery/Web-Content/quickhits.txt",
        "filter": "20"
    },
    "ffuf_subdomain": {
        "wordlist": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "filter": "0"
    },
    "gobuster_dir": {
        "wordlist": "/usr/share/seclists/Discovery/Web-Content/quickhits.txt"
    },
    "gobuster_dns": {
        "wordlist": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    },
    "gobuster_vhost": {
        "wordlist": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    },
    "wfuzz_subdomain": {
        "wordlist": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "filter": "0"
    },
    "dirsearch": {
        "wordlist": "/usr/share/seclists/Discovery/Web-Content/quickhits.txt"
    },
    "feroxbuster": {
        "wordlist": "/usr/share/seclists/Discovery/Web-Content/quickhits.txt"
    }
}

def input_or_default(prompt, default):
    value = input(f"{prompt} (default: {default}): ").strip()
    return value if value else default

def run_command(command, timeout=None):
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True, timeout=timeout)
        result.check_returncode()
        return result.stdout
    except subprocess.TimeoutExpired:
        return f"Error: Command '{command}' timed out."
    except subprocess.CalledProcessError as e:
        return f"Error: {e.stderr}"

def format_to_html(scan_results, output_file):
    """Format scan results into a modern, clear, and visually separated HTML file."""
    import html

    # Split results into sections for each tool
    sections = scan_results.split("\n\n")

    html_content = """
    <!DOCTYPE html>
    <html lang="id">
    <head>
        <meta charset="UTF-8">
        <title>Hasil Scanning Tools</title>
        <style>
            body { font-family: 'Segoe UI', Arial, sans-serif; background: #f5f7fa; margin: 0; padding: 0; }
            .container { max-width: 950px; margin: 40px auto; background: #fff; border-radius: 12px; box-shadow: 0 4px 20px #0002; padding: 36px 32px; }
            h1 { color: #1976d2; text-align: center; margin-bottom: 28px; }
            .tool-section { border: 2px solid #e3f2fd; border-radius: 10px; margin-bottom: 32px; background: #fbfcfe; box-shadow: 0 2px 8px #0001; }
            .tool-title { background: #e3f2fd; padding: 13px 22px; border-radius: 10px 10px 0 0; font-size: 1.17em; color: #1976d2; font-weight: bold; border-bottom: 1px solid #bbdefb; letter-spacing: 0.5px; }
            .tool-content { padding: 18px 22px; font-size: 1.04em; color: #222; }
            pre { background: #f1f3f4; color: #333; border-radius: 4px; padding: 12px 15px; white-space: pre-wrap; word-break: break-word; font-size: 0.97em; margin-top: 0; margin-bottom: 0; }
            .footer { color: #888; text-align: center; margin-top: 40px; font-size: 0.98em; }
            @media print { body { background: #fff; } .container { box-shadow: none; border: 1px solid #aaa; } }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Laporan Hasil Scanning Tools</h1>
    """

    for section in sections:
        lines = section.strip().splitlines()
        if not lines:
            continue
        title_line = lines[0]
        tool_name = title_line.replace("[", "").replace("]", "").replace(" RESULT", "")
        tool_name = html.escape(tool_name.strip())

        description = "\n".join(lines[1:]).replace("[0m", "").replace("[31m", "").replace("[32m", "").strip()
        description = html.escape(description) if description else "Tidak ada hasil ditemukan atau tool tidak menghasilkan output."

        html_content += f"""
        <div class="tool-section">
            <div class="tool-title">{tool_name}</div>
            <div class="tool-content">
                <pre>{description}</pre>
            </div>
        </div>
        """

    html_content += """
            <div class="footer">
                &copy; 2025 Bryan | Semua hasil otomatis dipisahkan berdasarkan tools.
            </div>
        </div>
    </body>
    </html>
    """

    with open(output_file, "w") as file:
        file.write(html_content)
    print(f"[INFO] Results formatted and saved to {output_file}")

def print_scanning_results():
    """Tampilkan hasil gabungan di browser."""
    combined_file = "combined_scan_results.txt"
    if os.path.exists(combined_file):
        with open(combined_file, "r") as f:
            scan_results = f.read()
        format_to_html(scan_results, "combined_scan_results.html")
        webbrowser.open("combined_scan_results.html")
    else:
        print("[ERROR] Tidak ada hasil scanning yang ditemukan. Jalankan scan terlebih dahulu.")

def append_to_combined_results(tool_name, results, clear=False):
    """Tambahkan hasil setiap tool ke file hasil gabungan, dengan info tambahan jika error/timeout/paranoid."""
    combined_file = "combined_scan_results.txt"
    extra_info = ""
    # Deteksi error umum untuk enum AD
    if (
        "timed out" in results
        or "NT_STATUS" in results
        or "Error:" in results
        or "failed" in results.lower()
        or "connection refused" in results.lower()
        or "Tidak ada hasil ditemukan atau tool tidak menghasilkan output." in results
        or not results.strip()
    ):
        extra_info = ("\n[INFO] Hasil scanning dari tool ini gagal, timeout, atau tidak ada output. "
                      "Hal ini biasanya disebabkan oleh:\n"
                      "- Target Active Directory menerapkan firewall, rate limit, atau membatasi koneksi anonymous\n"
                      "- Server sedang overload/lambat\n"
                      "- Koneksi ke server terputus\n"
                      "Coba ulangi saat port benar-benar open dan lab dalam keadaan fresh!\n")
    if clear and os.path.exists(combined_file):
        with open(combined_file, "w") as f:
            f.write("")
    with open(combined_file, "a") as f:
        f.write(f"[{tool_name} RESULT]\n")
        if not results.strip():
            f.write("Tidak ada hasil ditemukan atau tool tidak menghasilkan output.\n")
        else:
            f.write(results)
        if extra_info:
            f.write(extra_info)
        f.write("\n\n")

def quick_scan_linux():
    target = input("Masukkan target (Linux host): ").strip()
    print(f"[INFO] Memulai Quick Scan untuk Linux pada {target}...")

    # 1. Nmap
    nmap_command = f"nmap -Pn -sC -sV --top-ports 100 {target} --host-timeout 90s"
    nmap_results = run_command(nmap_command, timeout=110)
    append_to_combined_results("NMAP TOP 100 SCAN", nmap_results, clear=True)

    # 2. FFUF Directory
    ffuf_command = f"ffuf -u http://{target}/FUZZ -w {PRESET['ffuf_dir']['wordlist']} -t 30"
    ffuf_results = run_command(ffuf_command, timeout=90)
    append_to_combined_results("FFUF DIRECTORY SCAN", ffuf_results)

    # 3. WhatWeb
    whatweb_command = f"whatweb http://{target}"
    whatweb_results = run_command(whatweb_command, timeout=60)
    append_to_combined_results("WHATWEB SCAN", whatweb_results)

    # 4. Gobuster Directory
    gobuster_command = f"gobuster dir -u http://{target} -w {PRESET['gobuster_dir']['wordlist']} -t 30"
    gobuster_results = run_command(gobuster_command, timeout=90)
    append_to_combined_results("GOBUSTER DIRECTORY SCAN", gobuster_results)

    # 5. Dirsearch
    dirsearch_command = f"dirsearch -u http://{target} -e php,html,js,asp,aspx -x 403,404 -w {PRESET['dirsearch']['wordlist']}"
    dirsearch_results = run_command(dirsearch_command, timeout=90)
    append_to_combined_results("DIRSEARCH SCAN", dirsearch_results)

    # 6. Feroxbuster
    feroxbuster_command = f"feroxbuster -u http://{target} -w {PRESET['feroxbuster']['wordlist']} -k -x php,html,js"
    feroxbuster_results = run_command(feroxbuster_command, timeout=90)
    append_to_combined_results("FEROXBUSTER SCAN", feroxbuster_results)

    # 7. Nikto
    nikto_command = f"nikto -h http://{target}"
    nikto_results = run_command(nikto_command, timeout=110)
    append_to_combined_results("NIKTO SCAN", nikto_results)

    print("[INFO] Quick Scan untuk Linux selesai. Gunakan menu 100 untuk lihat hasil.")

def quick_scan_ad():
    while True:
        target = input("Masukkan target (Active Directory host/IP): ").strip()
        domain = input("Masukkan nama domain (misal: domain.local): ").strip()
        if not target or not domain:
            print("[ERROR] Target dan domain tidak boleh kosong! Silakan isi ulang.")
            continue
        break

    print(f"[INFO] Memulai Quick Scan untuk Active Directory pada {target}...")

    # 1. Nmap with LDAP and SMB scripts (top AD ports)
    nmap_command = (
        f"nmap -Pn -sC -sV -p 53,88,135,139,389,445,464,636,3268,3269 "
        f"--script=ldap-search,smb-enum-shares,smb-enum-users "
        f"{target} --host-timeout 120s"
    )
    nmap_results = run_command(nmap_command, timeout=180)
    append_to_combined_results("NMAP AD PORTS+SCRIPT SCAN", nmap_results, clear=True)

    # 2. CrackMapExec SMB (Anonymous)
    cme_command = f"crackmapexec smb {target} -u '' -p '' --shares --users"
    cme_results = run_command(cme_command, timeout=90)
    append_to_combined_results("CRACKMAPEXEC SMB ENUM", cme_results)

    # 3. Enum4linux (classic)
    enum4_command = f"enum4linux -a {target}"
    enum4_results = run_command(enum4_command, timeout=180)
    append_to_combined_results("ENUM4LINUX SCAN", enum4_results)

    # 4. LDAPSearch (Anonymous, langsung query sAMAccountName)
    ldap_base = ",".join([f"DC={d}" for d in domain.split(".")])
    ldap_command = (
        f"ldapsearch -x -H ldap://{target} -b '{ldap_base}' "
        f"'(objectClass=person)' sAMAccountName"
    )
    ldap_results = run_command(ldap_command, timeout=180)
    append_to_combined_results("LDAPSEARCH SCAN", ldap_results)

    # 5. Kerbrute userenum (pakai wordlist yang benar, huruf besar U!)
    kerbrute_command = (
        f"kerbrute userenum --dc {target} -d {domain} /usr/share/seclists/Usernames/cirt-default-usernames.txt"
    )
    kerbrute_results = run_command(kerbrute_command, timeout=180)
    append_to_combined_results("KERBRUTE USERENUM", kerbrute_results)

    # 6. GetNPUsers (AS-REP Roast, wordlist sama)
    getnp_command = (
        f"impacket-GetNPUsers {domain}/ -no-pass -dc-ip {target} "
        f"-usersfile /usr/share/seclists/Usernames/cirt-default-usernames.txt"
    )
    getnp_results = run_command(getnp_command, timeout=180)
    append_to_combined_results("GETNPUSERS SCAN", getnp_results)

    print("[INFO] Quick Scan untuk Active Directory selesai. Gunakan menu 100 untuk lihat hasil.")

def print_menu():
    ascii_art = f"""{LCYAN}{BOLD}
                                                                               
 ,---.                       ,--------.             ,--.,--.                    
 '   .-'  ,---.  ,---.,--.,--.'--.  .--',---.  ,---. |  ||  |-.  ,---.,--.  ,--. 
 `.  `-. | .-. :| .--'|  ||  |   |  |  | .-. || .-. ||  || .-. '| .-. |\\  `'  /  
 .-'    |\\   --.\\ `--.'  ''  '   |  |  ' '-' '' '-' '|  || `-' |' '-' '/  /.  \\  
 `-----'  `----' `---' `----'    `--'   `---'  `---' `--' `---'  `---''--'  '--' 
                                                                               

def display_menu():
    print(f"{BOLD}{GREEN}\nTools :{RESET}")
    print(f"{LCYAN}\nLinux & Windows{RESET}")
    print("1. Run ffuf (subdomain)")
    print("2. Run ffuf (directory)")
    print("3. Run nmap (full)")
    print("4. Run nmap (udp)")
    print("5. Run nmap (custom commands)")
    print("6. Run whatweb")
    print("7. Run wfuzz (subdomain)")
    print("8. Run gobuster (directory)")
    print("9. Run gobuster (dns)")
    print("10. Run gobuster (vhost)")
    print("11. Run dirsearch")
    print("12. Run feroxbuster")
    print("13. Quick Scan for Linux")
    print(f"{LPURPLE}\nActive Directory{RESET}")
    print("20. Run smbclient (guest)")
    print("21. Run smbclient (user & password)")
    print("22. Run smbclient (login)")
    print("23. Run smbmap")
    print("24. Run smbmap (user & password)")
    print("25. Run evilwinrm (password)")
    print("26. Run evilwinrm (hash)")
    print("27. Run crackmapexec smb (password)")
    print("28. Run crackmapexec smb (hash)")
    print("29. Run crackmapexec evilwinrm (password)")
    print("30. Run crackmapexec evilwinrm (hash)")
    print("31. Run rpcclient")
    print("32. Run enum4linux")
    print("33. Run snmpwalk")
    print("34. Run snmpwalk extend")
    print("35. Run xfreerdp")
    print("36. Run dnsenum")
    print("37. Run kerbrute (userenum)")
    print("38. Run GetNPUsers")
    print("39. Run Psexec (password)")
    print("40. Run Psexec (hash)")
    print("41. Run GetADUsers (optional User & Password)")
    print("42. Run ldapsearch")
    print("43. Run secretsdump (username & password)")
    print("44. Run mssqlclient (username, password & database)")
    print("45. Run getUserSPNs (username & password)")
    print("46. Run GetNPUsers (BruteForce Username.txt)")
    print("47. Quick Scan for Active Directory")
    print("99. Addhosts")
    print("100. Print Hasil Scanning")
    print("0. Exit")


def get_user_choice():
    try:
        choice = input(f"{BOLD}{GREEN}\nEnter your choice: {RESET}")
        if not choice.isdigit():
            print(f"{RED}Invalid input! Please enter a number.{RESET}")
            return '0'
        return choice
    except (EOFError, KeyboardInterrupt):
        print(f"\n{RED}Input interrupted. Exiting...{RESET}")
        return '0'

def display_file_contents(file_path):
    """Display the contents of a file."""
    try:
        with open(file_path, 'r') as file:
            print(file.read())
    except FileNotFoundError:
        print(f"{RED}File '{file_path}' not found.{RESET}")
    except Exception as e:
        print(f"{RED}Error reading file: {e}{RESET}")

def run_ffuf_subdomain(url, wordlist=None, word_size=None):
    # Apply preset if not provided
    if not wordlist:
        wordlist = PRESET["ffuf_subdomain"]["wordlist"]
    if not word_size:
        word_size = PRESET["ffuf_subdomain"]["filter"]
    command = f"ffuf -u '{url}' -H 'Host: FUZZ.{url}' -w {wordlist} -c -t 100 -fw {word_size}"
    subprocess.run(command, shell=True)

def run_ffuf_path(url, wordlist=None):
    if not wordlist:
        wordlist = PRESET["ffuf_dir"]["wordlist"]
    command = f"ffuf -u {url}/FUZZ -w {wordlist} -t 100"
    results = run_command(command, timeout=90)
    append_to_combined_results("FFUF SCAN", results)
    print("[INFO] Hasil FFUF disimpan.")

def run_gobuster_dir(url, wordlist=None):
    if not wordlist:
        wordlist = PRESET["gobuster_dir"]["wordlist"]
    command = f"gobuster dir -u {url} -w {wordlist} -t 100"
    results = run_command(command, timeout=90)
    append_to_combined_results("GOBUSTER DIRECTORY SCAN", results)
    print("[INFO] Hasil Gobuster (directory) disimpan.")

def run_gobuster_dns(url, wordlist=None, need=""):
    if not wordlist:
        wordlist = PRESET["gobuster_dns"]["wordlist"]
    command = f"gobuster dns -d {url} -t 50 -w {wordlist} {need}"
    results = run_command(command, timeout=90)
    append_to_combined_results("GOBUSTER DNS SCAN", results)
    print("[INFO] Hasil Gobuster (dns) disimpan.")

def run_gobuster_vhost(url, wordlist=None):
    if not wordlist:
        wordlist = PRESET["gobuster_vhost"]["wordlist"]
    command = f"gobuster vhost -u {url} -t 50 -w {wordlist} --append-domain"
    results = run_command(command, timeout=90)
    append_to_combined_results("GOBUSTER VHOST SCAN", results)
    print("[INFO] Hasil Gobuster (vhost) disimpan.")

def run_wfuzz(url, wordlist=None, word=None):
    if not wordlist:
        wordlist = PRESET["wfuzz_subdomain"]["wordlist"]
    if not word:
        word = PRESET["wfuzz_subdomain"]["filter"]
    command = f"wfuzz -c -t 100 -w {wordlist} -u http://{url} -H 'Host: FUZZ.{url}' --hw {word}"
    results = run_command(command, timeout=90)
    append_to_combined_results("WFUZZ SCAN", results)
    print("[INFO] Hasil WFUZZ disimpan.")

def run_dirsearch(url, wordlist=None):
    if not wordlist:
        wordlist = PRESET["dirsearch"]["wordlist"]
    command = f"dirsearch -u {url} -e txt,bak,php,html,js,asp,aspx -x 403,404 -w {wordlist}"
    results = run_command(command, timeout=90)
    append_to_combined_results("DIRSEARCH SCAN", results)
    print("[INFO] Hasil Dirsearch disimpan.")

def run_feroxbuster(url, wordlist=None):
    if not wordlist:
        wordlist = PRESET["feroxbuster"]["wordlist"]
    command = f"feroxbuster -u {url} -w {wordlist} -k -x txt,bak,php,html,js,asp,aspx -C 503"
    results = run_command(command, timeout=90)
    append_to_combined_results("FEROXBUSTER SCAN", results)
    print("[INFO] Hasil Feroxbuster disimpan.")

def run_nmap_full(target):
    print("[INFO] Menjalankan Nmap (Full)...")
    command = f"sudo nmap -sC -sV -O --open -p 1-1000 --stats-every 10s {target} -Pn"
    results = run_command(command, timeout=300)
    append_to_combined_results("NMAP FULL SCAN", results)
    print("[INFO] Hasil Nmap (Full) disimpan.")

def run_nmap_udp(target):
    print("[INFO] Menjalankan Nmap (UDP)...")
    command = f"sudo nmap -Pn -sU -sV -sC --top-ports=20 {target}"
    results = run_command(command, timeout=300)
    append_to_combined_results("NMAP UDP SCAN", results)
    print("[INFO] Hasil Nmap (UDP) disimpan.")

def run_whatweb(target):
    print("[INFO] Menjalankan WhatWeb...")
    command = f"whatweb {target}"
    results = run_command(command, timeout=60)
    append_to_combined_results("WHATWEB SCAN", results)
    print("[INFO] Hasil WhatWeb disimpan.")


    # Linux & Windows

def execute_command(command, function, *args):
    print(f"{LPURPLE}Executing:{RESET} {command}")
    function(*args)

def handle_choice(choice):
    try:
        if choice == '1':
            url = input("Enter the URL: ").strip()
            wordlist = input_or_default("Enter the path to the wordlist", PRESET["ffuf_subdomain"]["wordlist"])
            word = input_or_default("Enter word size to filter", PRESET["ffuf_subdomain"]["filter"])
            run_ffuf_subdomain(url, wordlist, word)
        elif choice == '2':
            url = input("Enter the URL: ").strip()
            wordlist = input_or_default("Enter the path to the wordlist", PRESET["ffuf_dir"]["wordlist"])
            run_ffuf_path(url, wordlist)
        elif choice == '3':
            target = input("Enter the target: ").strip()
            run_nmap_full(target)
        elif choice == '4':
            target = input("Enter the target: ").strip()
            run_nmap_udp(target)
        elif choice == '5':
            target = input("Enter the target: ").strip()
            custom = input("Enter the custom commands: ").strip()
            run_nmap_custom(target, custom)
        elif choice == '6':
            url = input("Enter the URL: ").strip()
            run_whatweb(url)
        elif choice == '7':
            url = input("Enter the URL: ").strip()
            wordlist = input_or_default("Enter the path to the wordlist", PRESET["wfuzz_subdomain"]["wordlist"])
            word = input_or_default("Enter word size to filter", PRESET["wfuzz_subdomain"]["filter"])
            run_wfuzz(url, wordlist, word)
        elif choice == '8':
            url = input("Enter the URL: ").strip()
            wordlist = input_or_default("Enter the path to the wordlist", PRESET["gobuster_dir"]["wordlist"])
            run_gobuster_dir(url, wordlist)
        elif choice == '9':
            url = input("Enter the URL: ").strip()
            wordlist = input_or_default("Enter the path to the wordlist", PRESET["gobuster_dns"]["wordlist"])
            need = input("Need --wildcard: (default: none): ").strip()
            run_gobuster_dns(url, wordlist, need)
        elif choice == '10':
            url = input("Enter the URL: ").strip()
            wordlist = input_or_default("Enter the path to the wordlist", PRESET["gobuster_vhost"]["wordlist"])
            run_gobuster_vhost(url, wordlist)
        elif choice == '11':
            url = input("Enter the URL: ").strip()
            wordlist = input_or_default("Enter the path to the wordlist", PRESET["dirsearch"]["wordlist"])
            run_dirsearch(url, wordlist)
        elif choice == '12':
            url = input("Enter the URL: ").strip()
            wordlist = input_or_default("Enter the path to the wordlist", PRESET["feroxbuster"]["wordlist"])
            run_feroxbuster(url, wordlist)
        elif choice == '13':
            quick_scan_linux()
        # Active Directory choices start here


    # Active Directory

        elif choice == '20':
            url = input("Enter the URL: ")
            command = f"smbclient -L \\\\{url} -N"
            print("")
            print(f"{LPURPLE}Executing:{RESET} {command}")
            run_smbclient(url)
        elif choice == '21':
            url = input("Enter the URL: ")
            user = input("Enter User: ")
            password = input("Enter Password: ")
            command = f"smbclient -U {user}%{password} -L //{url}/"
            print("")
            print(f"{LPURPLE}Executing:{RESET} {command}")
            run_smbclient_user(url, user, password)
        elif choice == '22':
            url = input("Enter the URL: ")
            user = input("Enter User: ")
            share = input("Enter SMB Share: ")
            command = f"smbclient -U {user} //{url}/{share}"
            print("")
            print(f"{LPURPLE}Executing:{RESET} {command}")
            run_smbclient_login(url, user, share)
        elif choice == '23':
            url = input("Enter the URL: ")
            command = f"smbmap -u '' -p '' -H {url}"
            print("")
            print(f"{LPURPLE}Executing:{RESET} {command}")
            run_smbmap(url)
        elif choice == '24':
            url = input("Enter the URL: ")
            user = input("Enter User: ")
            password = input("Enter Password: ")
            command = f"smbmap -u {user} -p {password} -H {url}"
            print("")
            print(f"{LPURPLE}Executing:{RESET} {command}")
            run_smbmap_user(url, user, password)
        elif choice == '25':
            url = input("Enter the URL: ")
            username = input("Enter username: ")
            password = input("Enter password: ")
            command = f"evil-winrm -i {url} -u {username} -p '{password}'"
            print("")
            print(f"{LPURPLE}Executing:{RESET} {command}")
            run_evilwinrm_password(url, username, password)
        elif choice == '26':
            url = input("Enter the URL: ")
            username = input("Enter username: ")
            hash = input("Enter hash: ")
            command = f"evil-winrm -i {url} -u {username} -H {hash}"
            print("")
            print(f"{LPURPLE}Executing:{RESET} {command}")
            run_evilwinrm_hash(url, username, hash)
        elif choice == '27':
            url = input("Enter the URL: ")
            username = input("Enter username/username.txt: ")
            password = input("Enter password/password.txt: ")
            command = f"sudo crackmapexec smb {url} -u {username} -p '{password}'"
            print("")
            print(f"{LPURPLE}Executing:{RESET} {command}")
            run_crackmapexec_smb_password(url, username, password)
        elif choice == '28':
            url = input("Enter the URL: ")
            username = input("Enter username/username.txt: ")
            hash = input("Enter hash: ")
            command = f"sudo crackmapexec smb {url} -u {username} -H {hash}"
            print("")
            print(f"{LPURPLE}Executing:{RESET} {command}")
            run_crackmapexec_smb_hash(url, username, hash)
        elif choice == '29':
            url = input("Enter the URL: ")
            username = input("Enter username/username.txt: ")
            password = input("Enter password/password.txt: ")
            command = f"sudo crackmapexec winrm {url} -u {username} -p '{password}' -x whoami --local-auth"
            print("")
            print(f"{LPURPLE}Executing:{RESET} {command}")
            run_crackmapexec_evil_password(url, username, password)
        elif choice == '30':
            url = input("Enter the URL: ")
            username = input("Enter username/username.txt: ")
            hash = input("Enter hash: ")
            command = f"sudo crackmapexec winrm {url} -u {username} -H {hash} -x whoami --local-auth"
            print("")
            print(f"{LPURPLE}Executing:{RESET} {command}")
            run_crackmapexec_evil_hash(url, username, hash)
        elif choice == '31':
            url = input("Enter the URL: ")
            command = f"rpcclient -U '' -N {url}"
            print("")
            print(f"{LPURPLE}Executing:{RESET} {command}")
            run_rpcclient(url)
        elif choice == '32':
            url = input("Enter the URL: ")
            command = f"enum4linux -a {url}"
            print("")
            print(f"{LPURPLE}Executing:{RESET} {command}")
            run_enum4linux(url)
        elif choice == '33':
            url = input("Enter the URL: ")
            command = f"snmpwalk -c public -v1 -t 10 {url}"
            print("")
            print(f"{LPURPLE}Executing:{RESET} {command}")
            run_snmpwalk_all(url)
        elif choice == '34':
            url = input("Enter the URL: ")
            command = f"snmpwalk -v1 -c public {url} NET-SNMP-EXTEND-MIB::nsExtendObjects"
            print("")
            print(f"{LPURPLE}Executing:{RESET} {command}")
            run_snmpwalk_extend(url)
        elif choice == '35':
            url = input("Enter the URL: ")
            username = input("Enter username: ")
            password = input("Enter password: ")
            command = f"xfreerdp /u:{username} /p:{password} /v:{url}"
            print("")
            print(f"{LPURPLE}Executing:{RESET} {command}")
            run_xfreerdp(url, username, password)
        elif choice == '36':
            url = input("Enter the URL: ")
            domain = input("Enter domain: ")
            command = f"dnsenum --dnsserver {url} -f /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt {domain} dnsenum VERSION:1.2.6"
            print("")
            print(f"{LPURPLE}Executing:{RESET} {command}")
            run_dnsenum(url, domain)
        elif choice == '37':
            url = input("Enter the IP: ")
            domain = input("Enter domain: ")
            user = input("Enter username/username.txt: ")
            command = f"./kerbrute userenum --dc {url} -d {domain} {user}"
            print("")
            print(f"{LPURPLE}Executing:{RESET} {command}")
            run_kerbrute(url, domain, user)
        elif choice == '38':
            url = input("Enter the IP: ")
            domain = input("Enter domain: ")
            command = f"impacket-GetNPUsers -dc-ip {url} -request '{domain}/'"
            print("")
            print(f"{LPURPLE}Executing:{RESET} {command}")
            run_GetNPUsers(url, domain)
        elif choice == '39':
            url = input("Enter the IP: ")
            user = input("Enter username: ")
            password = input("Enter password: ")
            command = f"impacket-psexec {user}:{password}@{url} cmd.exe"
            print("")
            print(f"{LPURPLE}Executing:{RESET} {command}")
            run_psexec_password(url, user, password)
        elif choice == '40':
            url = input("Enter the IP: ").strip()
            user = input("Enter username: ").strip()
            hash = input("Enter hash: ").strip()
            command = f"impacket-psexec -hashes {hash} {user}@{url}"
            print(f"\n{LPURPLE}Executing:{RESET} {command}")
            run_psexec_hash(url, user, hash)
        elif choice == '41':
            url = input("Enter the IP: ").strip()
            domain = input("Enter domain: ").strip()
            user = input("Enter user: ").strip()
            command = f"GetADUsers.py -all '{domain}/{user}' -dc-ip {url}"
            print(f"\n{LPURPLE}Executing:{RESET} {command}")
            run_GetADUsers(url, domain, user)
        elif choice == '42':
            url = input("Enter the IP: ").strip()
            dc_1 = input("Enter DC_1: ").strip()
            dc_2 = input("Enter DC_2: ").strip()
            command = f"ldapsearch -x -H ldap://{url} -b 'DC={dc_1},DC={dc_2}'"
            print(f"\n{LPURPLE}Executing:{RESET} {command}")
            run_ldap(url, dc_1, dc_2)
        elif choice == '43':
            url = input("Enter the IP: ").strip()
            domain = input("Enter domain: ").strip()
            username = input("Enter username: ").strip()
            password = input("Enter password: ").strip()
            command = f"secretsdump.py {domain}/{username}:'{password}'@{url}"
            print("")
            print(f"\n{LPURPLE}Executing:{RESET} {command}")
            run_secretsdump(url, domain, username, password)
        elif choice == '44':
            url = input("Enter the IP: ").strip()
            domain = input("Enter domain: ").strip()
            username = input("Enter username: ").strip()
            password = input("Enter password: ").strip()
            db = input("Enter database/volume: ").strip()
            command = f"mssqlclient.py -db {db} {domain}/{username}:'{password}'@{url} -windows-auth"
            print(f"\n{LPURPLE}Executing:{RESET} {command}")
            run_mssqlclient(url, domain, username, password, db)
        elif choice == '45':
            url = input("Enter the IP: ").strip()
            domain = input("Enter domain: ").strip()
            username = input("Enter username: ").strip()
            command = f"GetUserSPNs.py {domain}/{username} -dc-ip {url} -request"
            print("")
            print(f"{LPURPLE}Executing:{RESET} {command}")
            run_GetUserSPNs(url, domain, username)
        elif choice == '46':
            url = input("Enter the IP: ").strip()
            domain = input("Enter domain: ").strip()
            username = input("Enter username.txt: ").strip()
            command = f"GetNPUsers.py '{domain}/' -usersfile {username} -dc-ip {url}"
            print(f"\n{LPURPLE}Executing:{RESET} {command}")
            run_GetNPUsers_file(url, domain, username)
        elif choice == '47':
            quick_scan_ad()
        elif choice == '99':
            ip = input("Enter the IP: ").strip()
            host = input("Enter host: ").strip()
            command = f"sudo -- sh -c -e \"echo '{ip} {host}' >> /etc/hosts\";"
            print(f"\n{LPURPLE}Executing:{RESET} {command}")
            run_addhosts(host, ip)
        elif choice == '100':
            print(f"\n{LPURPLE}Menampilkan hasil scanning yang telah disimpan:{RESET}")
            print_scanning_results()
        elif choice == '0':
            return False # Pastikan 'return False' diindentasi dengan benar
        else:
            print(f"{RED}Invalid choice. Please try again.{RESET}")
            return True
    except Exception as e:
        print(f"{RED}Error: {e}{RESET}")
        return True
