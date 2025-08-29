import subprocess
import os
import json
import webbrowser
from datetime import datetime
from command import PRESET
from format_to_html import format_to_html

JSON_RESULT_PATH = "combined_scan_results.json"
HTML_TEMPLATE_PATH = "combined_scan_results.html"

def print_banner():
    print("\033[1;31m" + "="*80)
    print(" " * 9 + "██████████████████████████████████████████████████████████████████████")
    print(" " * 9 + "█                                                                █")
    print(" " * 9 + "█                  SECUTOOLBOX V2                                █")
    print(" " * 9 + "█               by SECUTOOLBOX Team                              █")
    print(" " * 9 + "█                                                                █")
    print(" " * 9 + "██████████████████████████████████████████████████████████████████████")
    print("="*80 + "\033[0m")

def get_now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def duration_seconds(start, end):
    fmt = "%Y-%m-%d %H:%M:%S"
    return (datetime.strptime(end, fmt) - datetime.strptime(start, fmt)).total_seconds()

def find_tool(tool):
    for path in os.environ["PATH"].split(os.pathsep):
        exe = os.path.join(path, tool)
        if os.path.isfile(exe) and os.access(exe, os.X_OK):
            return exe
    pipx_path = os.path.expanduser(f"~/.local/bin/{tool}")
    if os.path.isfile(pipx_path) and os.access(pipx_path, os.X_OK):
        return pipx_path
    bin_path = f"/usr/bin/{tool}"
    if os.path.isfile(bin_path) and os.access(bin_path, os.X_OK):
        return bin_path
    return None

def check_wordlist(wordlist_path):
    if not os.path.isfile(wordlist_path):
        print(f"[WARNING] Wordlist {wordlist_path} tidak ditemukan!")
        return False
    return True

def run_tool(tool_name, command, description, timeout=None, clear=False):
    cmd_parts = command.split()
    binary = cmd_parts[0]
    exe = find_tool(binary)
    if not exe:
        print(f"[WARNING] {tool_name} ({binary}) tidak ditemukan di PATH, ~/.local/bin, atau /usr/bin! Command di-skip.")
        return
    cmd_parts[0] = exe
    command_fixed = " ".join(cmd_parts)
    print(f"[INFO] Menjalankan {tool_name}...")
    start_time = get_now()
    try:
        result = subprocess.run(command_fixed, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True, timeout=timeout)
        output = result.stdout + ("\n" + result.stderr if result.stderr else "")
        result.check_returncode()
        status = "success"
        error_message = ""
    except subprocess.TimeoutExpired:
        output = ""
        status = "timeout"
        error_message = f"Error: Command '{command_fixed}' timed out."
    except subprocess.CalledProcessError as e:
        output = e.stderr or ""
        status = "error"
        error_message = f"Error: {e.stderr or 'Gagal menjalankan perintah.'}"
    except Exception as e:
        output = ""
        status = "error"
        error_message = f"Error: {str(e)}"
    end_time = get_now()
    entry = {
        "tool_name": tool_name,
        "command": command_fixed,
        "description": description,
        "result": output if output.strip() else "Tidak ada hasil atau output kosong.",
        "status": status,
        "error_message": error_message,
        "start_time": start_time,
        "end_time": end_time,
        "duration": duration_seconds(start_time, end_time)
    }
    if clear or not os.path.exists(JSON_RESULT_PATH):
        data = []
    else:
        with open(JSON_RESULT_PATH, "r") as f:
            data = json.load(f)
    data.append(entry)
    with open(JSON_RESULT_PATH, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[INFO] {tool_name}: {status.upper()} - {error_message if error_message else 'OK'}")

def append_to_json_results(tool_name, command, description, output, start_time, end_time, clear=False):
    entry = {
        "tool_name": tool_name,
        "command": command,
        "description": description,
        "result": output,
        "status": "summary",
        "error_message": "",
        "start_time": start_time,
        "end_time": end_time,
        "duration": duration_seconds(start_time, end_time)
    }
    if clear or not os.path.exists(JSON_RESULT_PATH):
        data = []
    else:
        with open(JSON_RESULT_PATH, "r") as f:
            data = json.load(f)
    data.append(entry)
    with open(JSON_RESULT_PATH, "w") as f:
        json.dump(data, f, indent=2)

def print_scanning_results():
    if os.path.exists(JSON_RESULT_PATH):
        format_to_html(JSON_RESULT_PATH, HTML_TEMPLATE_PATH)
        webbrowser.open(HTML_TEMPLATE_PATH)
    else:
        print("[ERROR] Tidak ada hasil scanning yang ditemukan. Jalankan scan terlebih dahulu.")

def prompt_command(default_cmd):
    custom = input(f"Custom command (tekan Enter untuk default):\n[{default_cmd}]\n> ").strip()
    return custom if custom else default_cmd

def quick_scan_linux():
    target = input("Target (IP/domain): ").strip()
    scan_start = get_now()
    
    # Check wordlists
    # Ubah 'quick_dir_fuzz' jika tidak sesuai dengan PRESET Anda
    check_wordlist(PRESET['dir_fuzz']) # Ganti 'quick_dir_fuzz'
    check_wordlist(PRESET['subdomain_fuzz']) # Ganti 'quick_subdomain_fuzz'

    # Nmap Scan: Port populer, deteksi service, dan kerentanan dasar.
    # Waktu eksekusi diharapkan di bawah 3 menit.
    run_tool("NMAP QUICK SCAN",
        f"nmap -T4 --top-ports 1000 -sC -sV --open {target} -Pn",
        "Scan 1000 port populer, deteksi service & vuln dasar (nmap).", timeout=180, clear=True)

    # WhatWeb Scan: Identifikasi teknologi web
    run_tool("WHATWEB SCAN",
        f"whatweb http://{target}",
        "Deteksi framework & teknologi web.", timeout=60)

    # FFUF Directory Scan: Brute-force direktori dengan wordlist cepat dan thread terbatas.
    run_tool("FFUF DIRECTORY SCAN",
        f"ffuf -u http://{target}/FUZZ -w {PRESET['dir_fuzz']} -t 30 -c -v", # Ganti 'quick_dir_fuzz'
        "Brute-force direktori/file web (ffuf).", timeout=120)

    # Nikto Scan: Scan kerentanan web server
    # Digabungkan dengan quick scan karena pentingnya info vuln awal.
    run_tool("NIKTO SCAN",
        f"nikto -h http://{target}",
        "Scan vulnerability web server (nikto).", timeout=180)

    # Gobuster DNS Scan: Cari subdomain
    # Menggunakan wordlist yang lebih ringkas untuk quick scan.
    run_tool("GOBUSTER SUBDOMAIN SCAN",
        f"gobuster dns -d {target} -w {PRESET['subdomain_fuzz']} --timeout 15s", # Ganti 'quick_subdomain_fuzz'
        "Cari subdomain pada domain target (gobuster).", timeout=120)

    # Tambahan: Dirsearch sebagai alternatif/konfirmasi
    run_tool("DIRSEARCH SCAN",
        f"dirsearch -u http://{target} -e php,html,js,asp,aspx -w {PRESET['dir_fuzz']}", # Ganti 'quick_dir_fuzz'
        "Brute-force direktori/file web advance (dirsearch).", timeout=120)

    # Tambahan Feroxbuster
    run_tool("FEROXBUSTER SCAN",
        f"feroxbuster -u http://{target} -w {PRESET['feroxbuster']} -k -x php,html,js",
        "Web fuzzing paralel (feroxbuster).", timeout=120)
        
    scan_end = get_now()
    append_to_json_results(
        "SUMMARY", "-", "Total waktu eksekusi quick scan Linux",
        f"{duration_seconds(scan_start, scan_end)} detik",
        scan_start, scan_end
    )
    print("[INFO] Quick Scan Linux selesai. Gunakan menu 100 untuk lihat hasil.")

def quick_scan_ad():
    target = input("Target (IP AD): ").strip()
    domain = input("Domain (misal: domain.local): ").strip()
    scan_start = get_now()
    # Nmap scan port AD/SMB/LDAP
    run_tool("NMAP AD QUICK SCAN",
        f"nmap -Pn -sS -p 53,88,135,139,389,445,464,636,3268,3269 {target} --host-timeout 60s",
        "Scan port AD/SMB/LDAP (quick mode).", timeout=60, clear=True)
    # Cek hasil nmap: jika semua port filtered/closed, tampilkan warning, skip tool lain
    # (Tambahkan logika parsing hasil nmap jika mau, atau manual cek sebelum lanjut)
    run_tool("ENUM4LINUX SCAN",
        f"enum4linux -a {target}",
        "Enum user/group/share SMB (enum4linux).", timeout=60)
    run_tool("CRACKMAPEXEC SMB SCAN",
        f"crackmapexec smb {target} -u '' -p '' --shares --users",
        "SMB enum + policy + share (crackmapexec).", timeout=60)
    ldap_base = ",".join([f"DC={d}" for d in domain.split(".")])
    run_tool("LDAPSEARCH SCAN",
        f"ldapsearch -x -H ldap://{target} -b '{ldap_base}' '(objectClass=person)' sAMAccountName",
        "Dump user/group AD via LDAP.", timeout=60)
    run_tool("KERBRUTE USERENUM",
        f"kerbrute userenum --dc {target} -d {domain} /usr/share/seclists/Usernames/cirt-default-usernames.txt",
        "Enum user valid Kerberos (kerbrute).", timeout=60)
    run_tool("GETNPUSERS SCAN",
        f"python3 $(which GetNPUsers.py) {domain}/ -no-pass -dc-ip {target} -usersfile /usr/share/seclists/Usernames/cirt-default-usernames.txt",
        "Cari user AS-REP roasting vuln.", timeout=60)
    run_tool("SMBCLIENT GUEST",
        f"smbclient -L \\\\{target} -N",
        "Test akses share SMB (guest/anon).", timeout=60)
    scan_end = get_now()
    append_to_json_results(
        "SUMMARY", "-", "Total waktu eksekusi quick scan AD",
        f"{duration_seconds(scan_start, scan_end)} detik",
        scan_start, scan_end
    )
    print("[INFO] Quick Scan AD selesai. Gunakan menu 100 untuk lihat hasil.")
    
def main():
    while True:
        print_banner()
        print("Linux/Web & General:")
        print(" 1.  Run nmap (full)                  - Scan seluruh port TCP, deteksi service & versi")
        print(" 2.  Run whatweb                      - Deteksi framework & teknologi web target")
        print(" 3.  Run ffuf (subdomain)             - Cari subdomain pada domain target (web enumeration)")
        print(" 4.  Run ffuf (directory)             - Bruteforce direktori/file tersembunyi di web")
        print(" 5.  Run gobuster (directory)         - Bruteforce direktori/file web (gobuster)")
        print(" 6.  Run dirsearch                    - Cari direktori/file tersembunyi (dirsearch)")
        print(" 7.  Run feroxbuster                  - Web fuzzing paralel, cepat (feroxbuster)")
        print(" 8.  Run nikto                        - Scan vulnerability web server (nikto)")
        print(" 9.  Quick Scan for Linux             - Otomatisasi scan web, enum, vuln (1-8)")
        print("-" * 48)
        print("\033[95mActive Directory & Internal (Utama):\033[0m")
        print("10.  Run nmap (AD script)             - Scan port AD/SMB/LDAP dengan script enum")
        print("11.  Run enum4linux                   - Enum user/group/share SMB (enum4linux, guest/anon)")
        print("12.  Run crackmapexec smb             - SMB enum + auth (crackmapexec, guest/anon)")
        print("13.  Run ldapsearch                   - Enum user/group AD (ldapsearch)")
        print("14.  Run kerbrute (userenum)          - Enum user Kerberos (kerbrute)")
        print("15.  Run GetNPUsers                   - Enum user AS-REP roasting (impacket-GetNPUsers)")
        print("16.  Run smbclient (guest)            - Enum share SMB tanpa login (guest/anon)")
        print("17.  Quick Scan for Active Directory  - Otomatisasi enum AD, SMB, Kerberos, dll (10-16)")
        print("-" * 48)
        print("\033[94mActive Directory & Internal (Lanjutan/Opsional):\033[0m")
        print("18.  Run smbmap (guest)               - Enum share SMB (smbmap, guest/anon)")
        print("19.  Run smbmap (user & password)     - Enum share SMB (smbmap, authenticated)")
        print("20.  Run evilwinrm (password)         - Remote shell ke Windows (evilwinrm, password)")
        print("21.  Run evilwinrm (hash)             - Remote shell ke Windows (evilwinrm, hash)")
        print("22.  Run crackmapexec smb (password)  - SMB enum + auth (crackmapexec, password)")
        print("23.  Run crackmapexec smb (hash)      - SMB enum + auth (crackmapexec, hash)")
        print("24.  Run crackmapexec winrm (password)- WinRM enum+exec (crackmapexec, password)")
        print("25.  Run crackmapexec winrm (hash)    - WinRM enum+exec (crackmapexec, hash)")
        print("26.  Run rpcclient                    - Enum info Windows (rpcclient, guest/anon)")
        print("27.  Run snmpwalk                     - Enum SNMP v1 (public)")
        print("28.  Run snmpwalk extend              - Enum SNMP extend (public)")
        print("29.  Run xfreerdp                     - Remote desktop RDP (xfreerdp)")
        print("30.  Run dnsenum                      - Enum DNS, subdomain, zone transfer")
        print("31.  Run Psexec (password)            - Remote command Windows (psexec, password)")
        print("32.  Run Psexec (hash)                - Remote command Windows (psexec, hash)")
        print("33.  Run GetADUsers                   - Dump user Active Directory (impacket-GetADUsers)")
        print("34.  Run secretsdump                  - Dump hash/password AD (impacket-secretsdump)")
        print("35.  Run mssqlclient                  - Enum SQL Server (impacket-mssqlclient)")
        print("36.  Run getUserSPNs                  - Cari SPN user (kerberoasting/ad privesc)")
        print("37.  Run GetNPUsers (BruteForce List) - Brute-force user AS-REP roasting")
        print("-" * 48)
        print("100. Print Hasil Scanning             - Lihat hasil scan dalam format HTML/PDF")
        print("0.   Exit")
        choice = input("Pilih menu: ").strip()
        if choice == "1":
            target = input("Target (IP/domain): ").strip()
            default_cmd = f"nmap --top-ports 100 -sS -T4 {target} -Pn"
            cmd = prompt_command(default_cmd)
            run_tool("NMAP QUICK SCAN", cmd, "Scan port populer dan deteksi service (nmap).", timeout=90, clear=True)
        elif choice == "2":
            target = input("Target (URL): ").strip()
            default_cmd = f"whatweb {target}"
            cmd = prompt_command(default_cmd)
            run_tool("WHATWEB SCAN", cmd, "Deteksi framework & teknologi web.", timeout=60)
        elif choice == "3":
            domain = input("Domain: ").strip()
            check_wordlist(PRESET['ffuf_subdomain'])
            default_cmd = f"ffuf -u http://{domain}/ -H 'Host: FUZZ.{domain}' -w {PRESET['ffuf_subdomain']} -c -t 50"
            cmd = prompt_command(default_cmd)
            run_tool("FFUF SUBDOMAIN SCAN", cmd, "Cari subdomain pada domain target (ffuf).", timeout=60)
        elif choice == "4":
            target = input("Target (domain/IP): ").strip()
            check_wordlist(PRESET['ffuf_dir'])
            default_cmd = f"ffuf -u http://{target}/FUZZ -w {PRESET['ffuf_dir']} -t 50"
            cmd = prompt_command(default_cmd)
            run_tool("FFUF DIRECTORY SCAN", cmd, "Brute-force direktori/file web (ffuf).", timeout=90)
        elif choice == "5":
            target = input("Target (URL): ").strip()
            check_wordlist(PRESET['gobuster_dir'])
            default_cmd = f"gobuster dir -u {target} -w {PRESET['gobuster_dir']} -t 50"
            cmd = prompt_command(default_cmd)
            run_tool("GOBUSTER DIRECTORY SCAN", cmd, "Brute-force direktori/file web (gobuster).", timeout=90)
        elif choice == "6":
            target = input("Target (URL): ").strip()
            check_wordlist(PRESET['dirsearch'])
            default_cmd = f"dirsearch -u {target} -e php,html,js,asp,aspx -w {PRESET['dirsearch']}"
            cmd = prompt_command(default_cmd)
            run_tool("DIRSEARCH SCAN", cmd, "Brute-force direktori/file web advance (dirsearch).", timeout=90)
        elif choice == "7":
            target = input("Target (URL): ").strip()
            check_wordlist(PRESET['feroxbuster'])
            default_cmd = f"feroxbuster -u {target} -w {PRESET['feroxbuster']} -k -x php,html,js"
            cmd = prompt_command(default_cmd)
            run_tool("FEROXBUSTER SCAN", cmd, "Web fuzzing paralel (feroxbuster).", timeout=60)
        elif choice == "8":
            target = input("Target (URL): ").strip()
            default_cmd = f"nikto -h http://{target} -maxtime 60"
            cmd = prompt_command(default_cmd)
            run_tool("NIKTO SCAN", cmd, "Scan vulnerability web server (nikto, quick mode).", timeout=60)
        elif choice == "9":
            quick_scan_linux()
        elif choice == "10":
            target = input("Target (IP AD): ").strip()
            default_cmd = f"nmap -Pn -sS -p 53,88,135,139,389,445,464,636,3268,3269 {target} --host-timeout 60s"
            cmd = prompt_command(default_cmd)
            run_tool("NMAP AD QUICK SCAN", cmd, "Scan port AD/SMB/LDAP (quick mode).", timeout=60, clear=True)
        elif choice == "11":
            target = input("Target (IP): ").strip()
            default_cmd = f"enum4linux -a {target}"
            cmd = prompt_command(default_cmd)
            run_tool("ENUM4LINUX SCAN", cmd, "Enum user/group/share SMB (enum4linux).", timeout=60)
        elif choice == "12":
            target = input("Target (IP): ").strip()
            default_cmd = f"crackmapexec smb {target} -u '' -p '' --shares --users"
            cmd = prompt_command(default_cmd)
            run_tool("CRACKMAPEXEC SMB SCAN", cmd, "SMB enum + policy + share (crackmapexec).", timeout=60)
        elif choice == "13":
            target = input("Target (IP): ").strip()
            domain = input("Domain (misal: domain.local): ").strip()
            ldap_base = ",".join([f"DC={d}" for d in domain.split(".")])
            default_cmd = f"ldapsearch -x -H ldap://{target} -b '{ldap_base}' '(objectClass=person)' sAMAccountName"
            cmd = prompt_command(default_cmd)
            run_tool("LDAPSEARCH SCAN", cmd, "Dump user/group AD via LDAP.", timeout=60)
        elif choice == "14":
            dc = input("Domain Controller IP: ").strip()
            domain = input("Domain: ").strip()
            userlist = input("Wordlist username (default: /usr/share/seclists/Usernames/cirt-default-usernames.txt): ").strip()
            if not userlist:
                userlist = "/usr/share/seclists/Usernames/cirt-default-usernames.txt"
            check_wordlist(userlist)
            default_cmd = f"kerbrute userenum --dc {dc} -d {domain} {userlist}"
            cmd = prompt_command(default_cmd)
            run_tool("KERBRUTE USERENUM", cmd, "Enum user valid Kerberos (kerbrute).", timeout=60)
        elif choice == "15":
            dc = input("Domain Controller IP: ").strip()
            domain = input("Domain: ").strip()
            userfile = input("User wordlist (default: /usr/share/seclists/Usernames/cirt-default-usernames.txt): ").strip()
            if not userfile:
                userfile = "/usr/share/seclists/Usernames/cirt-default-usernames.txt"
            check_wordlist(userfile)
            default_cmd = f"python3 $(which GetNPUsers.py) {domain}/ -no-pass -dc-ip {target} -usersfile /usr/share/seclists/Usernames/cirt-default-usernames.txt"
            cmd = prompt_command(default_cmd)
            run_tool("GETNPUSERS SCAN", cmd, "Cari user AS-REP roasting vuln.", timeout=60)
        elif choice == "16":
            target = input("Target (IP/host): ").strip()
            default_cmd = f"smbclient -L \\\\{target} -N"
            cmd = prompt_command(default_cmd)
            run_tool("SMBCLIENT GUEST", cmd, "Test akses share SMB (guest/anon).", timeout=60)
        elif choice == "17":
            quick_scan_ad()
        # Active Directory & Internal (Lanjutan/Opsional)
        elif choice == "18":
            target = input("Target (IP): ").strip()
            default_cmd = f"smbmap -H {target}"
            cmd = prompt_command(default_cmd)
            run_tool("SMBMAP GUEST SCAN", cmd, "Enum share SMB (smbmap, guest/anon).", timeout=60)
        elif choice == "19":
            target = input("Target (IP): ").strip()
            user = input("Username: ").strip()
            password = input("Password: ").strip()
            default_cmd = f"smbmap -H {target} -u '{user}' -p '{password}'"
            cmd = prompt_command(default_cmd)
            run_tool("SMBMAP AUTH SCAN", cmd, "Enum share SMB (smbmap, authenticated).", timeout=60)
        elif choice == "20":
            target = input("Target (IP): ").strip()
            user = input("Username: ").strip()
            password = input("Password: ").strip()
            default_cmd = f"evil-winrm -i {target} -u '{user}' -p '{password}'"
            cmd = prompt_command(default_cmd)
            run_tool("EVIL-WINRM PASSWORD", cmd, "Remote shell ke Windows (evilwinrm).", timeout=120)
        elif choice == "21":
            target = input("Target (IP): ").strip()
            user = input("Username: ").strip()
            _hash = input("Hash (LM:NT): ").strip()
            default_cmd = f"evil-winrm -i {target} -u '{user}' -H '{_hash}'"
            cmd = prompt_command(default_cmd)
            run_tool("EVIL-WINRM HASH", cmd, "Remote shell ke Windows (evilwinrm, hash).", timeout=120)
        elif choice == "22":
            target = input("Target (IP): ").strip()
            user = input("Username: ").strip()
            password = input("Password: ").strip()
            default_cmd = f"crackmapexec smb {target} -u '{user}' -p '{password}' --shares --users"
            cmd = prompt_command(default_cmd)
            run_tool("CRACKMAPEXEC AUTH SMB SCAN", cmd, "SMB enum + auth (crackmapexec, password).", timeout=90)
        elif choice == "23":
            target = input("Target (IP): ").strip()
            user = input("Username: ").strip()
            _hash = input("Hash (LM:NT): ").strip()
            default_cmd = f"crackmapexec smb {target} -u '{user}' -H '{_hash}' --shares --users"
            cmd = prompt_command(default_cmd)
            run_tool("CRACKMAPEXEC HASH SMB SCAN", cmd, "SMB enum + auth (crackmapexec, hash).", timeout=90)
        elif choice == "24":
            target = input("Target (IP): ").strip()
            user = input("Username: ").strip()
            password = input("Password: ").strip()
            default_cmd = f"crackmapexec winrm {target} -u '{user}' -p '{password}' --groups --users"
            cmd = prompt_command(default_cmd)
            run_tool("CRACKMAPEXEC WINRM PASSWORD", cmd, "WinRM enum+exec (crackmapexec, password).", timeout=90)
        elif choice == "25":
            target = input("Target (IP): ").strip()
            user = input("Username: ").strip()
            _hash = input("Hash (LM:NT): ").strip()
            default_cmd = f"crackmapexec winrm {target} -u '{user}' -H '{_hash}' --groups --users"
            cmd = prompt_command(default_cmd)
            run_tool("CRACKMAPEXEC WINRM HASH", cmd, "WinRM enum+exec (crackmapexec, hash).", timeout=90)
        elif choice == "26":
            target = input("Target (IP): ").strip()
            default_cmd = f"rpcclient -U "" -N {target} -c 'enumdomusers'"
            cmd = prompt_command(default_cmd)
            run_tool("RPCCLIENT GUEST", cmd, "Enum info Windows (rpcclient, guest/anon).", timeout=60)
        elif choice == "27":
            target = input("Target (IP): ").strip()
            community = input("Community String (default: public): ").strip()
            if not community:
                community = "public"
            default_cmd = f"snmpwalk -v 2c -c {community} {target} 1.3.6.1.2.1.1"
            cmd = prompt_command(default_cmd)
            run_tool("SNMPWALK PUBLIC", cmd, "Enum SNMP v1 (public).", timeout=60)
        elif choice == "28":
            target = input("Target (IP): ").strip()
            community = input("Community String (default: public): ").strip()
            if not community:
                community = "public"
            default_cmd = f"snmpwalk -v 2c -c {community} {target} 1.3.6.1.4.1.77.1.2.2.1"
            cmd = prompt_command(default_cmd)
            run_tool("SNMPWALK EXTEND", cmd, "Enum SNMP extend (public).", timeout=60)
        elif choice == "29":
            target = input("Target (IP): ").strip()
            domain = input("Domain (default: WORKGROUP): ").strip()
            user = input("Username: ").strip()
            password = input("Password: ").strip()
            default_cmd = f"xfreerdp /v:{target} /d:{domain} /u:{user} /p:'{password}'"
            cmd = prompt_command(default_cmd)
            run_tool("XFREERDP", cmd, "Remote desktop RDP (xfreerdp).", timeout=120)
        elif choice == "30":
            target = input("Target (domain): ").strip()
            default_cmd = f"dnsenum {target}"
            cmd = prompt_command(default_cmd)
            run_tool("DNSENUM SCAN", cmd, "Enum DNS, subdomain, zone transfer.", timeout=120)
        elif choice == "31":
            target = input("Target (IP): ").strip()
            user = input("Username: ").strip()
            password = input("Password: ").strip()
            command = input("Command to run: ").strip()
            default_cmd = f"impacket-psexec {user}:{password}@{target} '{command}'"
            cmd = prompt_command(default_cmd)
            run_tool("IMPACKET-PSEXEC PASSWORD", cmd, "Remote command Windows (psexec, password).", timeout=120)
        elif choice == "32":
            target = input("Target (IP): ").strip()
            user = input("Username: ").strip()
            _hash = input("Hash (LM:NT): ").strip()
            command = input("Command to run: ").strip()
            default_cmd = f"impacket-psexec {user}@{target} -hashes '{_hash}' -exec 'cmd.exe /c \"{command}\"'"
            cmd = prompt_command(default_cmd)
            run_tool("IMPACKET-PSEXEC HASH", cmd, "Remote command Windows (psexec, hash).", timeout=120)
        elif choice == "33":
            target = input("Target (IP): ").strip()
            domain = input("Domain: ").strip()
            user = input("Username: ").strip()
            password = input("Password: ").strip()
            default_cmd = f"impacket-GetADUsers -all {domain}/{user}:{password}"
            cmd = prompt_command(default_cmd)
            run_tool("IMPACKET-GETADUSERS", cmd, "Dump user Active Directory (impacket-GetADUsers).", timeout=120)
        elif choice == "34":
            target = input("Target (IP): ").strip()
            user = input("Username: ").strip()
            password = input("Password: ").strip()
            default_cmd = f"impacket-secretsdump {user}:{password}@{target}"
            cmd = prompt_command(default_cmd)
            run_tool("IMPACKET-SECRETSDUMP", cmd, "Dump hash/password AD (impacket-secretsdump).", timeout=120)
        elif choice == "35":
            target = input("Target (IP): ").strip()
            user = input("Username: ").strip()
            password = input("Password: ").strip()
            default_cmd = f"impacket-mssqlclient {user}:{password}@{target}"
            cmd = prompt_command(default_cmd)
            run_tool("IMPACKET-MSSQLCLIENT", cmd, "Enum SQL Server (impacket-mssqlclient).", timeout=120)
        elif choice == "36":
            target = input("Target (IP): ").strip()
            domain = input("Domain: ").strip()
            user = input("Username: ").strip()
            password = input("Password: ").strip()
            default_cmd = f"impacket-GetUserSPNs {domain}/{user}:{password} -dc-ip {target} -request"
            cmd = prompt_command(default_cmd)
            run_tool("IMPACKET-GETUSERSPNS", cmd, "Cari SPN user (kerberoasting/ad privesc).", timeout=120)
        elif choice == "37":
            target = input("Target (IP): ").strip()
            domain = input("Domain: ").strip()
            userfile = input("User wordlist (default: /usr/share/seclists/Usernames/cirt-default-usernames.txt): ").strip()
            if not userfile:
                userfile = "/usr/share/seclists/Usernames/cirt-default-usernames.txt"
            check_wordlist(userfile)
            default_cmd = f"impacket-GetNPUsers.py {domain}/ -no-pass -dc-ip {target} -usersfile {userfile}"
            cmd = prompt_command(default_cmd)
            run_tool("GETNPUSERS BRUTE", cmd, "Brute-force user AS-REP roasting.", timeout=120)
        # ... (rest of menu unchanged, opsional dan lanjutan tetap bisa custom command/timeout)
        elif choice == "100":
            print_scanning_results()
        elif choice == "0":
            break

if __name__ == "__main__":
    main()
