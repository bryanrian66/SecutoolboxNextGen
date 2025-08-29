import subprocess
import os
import json
import webbrowser
from datetime import datetime
from command import PRESET
from format_to_html import format_to_html

JSON_RESULT_PATH = "combined_scan_results.json"
HTML_TEMPLATE_PATH = "combined_scan_results.html"

def get_now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def duration_seconds(start, end):
    fmt = "%Y-%m-%d %H:%M:%S"
    return (datetime.strptime(end, fmt) - datetime.strptime(start, fmt)).total_seconds()

def run_tool(tool_name, command, description, timeout=None, clear=False):
    print(f"[INFO] Menjalankan {tool_name}...")
    start_time = get_now()
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True, timeout=timeout)
        output = result.stdout + ("\n" + result.stderr if result.stderr else "")
        result.check_returncode()
        status = "success"
        error_message = ""
    except subprocess.TimeoutExpired:
        output = ""
        status = "timeout"
        error_message = f"Error: Command '{command}' timed out."
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
        "command": command,
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
        try:
            with open(JSON_RESULT_PATH, "r") as f:
                data = json.load(f)
        except:
            data = []
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
        try:
            with open(JSON_RESULT_PATH, "r") as f:
                data = json.load(f)
        except:
            data = []
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
    run_tool("NMAP FULL SCAN",
             f"nmap -sC -sV -O --open -p 1-1000 {target} -Pn",
             "Scan seluruh port & service dengan nmap.", timeout=180, clear=True)
    run_tool("WHATWEB SCAN",
             f"whatweb http://{target}",
             "Deteksi framework & teknologi web.", timeout=60)
    run_tool("FFUF DIRECTORY SCAN",
             f"ffuf -u http://{target}/FUZZ -w {PRESET['ffuf_dir']} -t 30",
             "Brute-force direktori/file web (ffuf).", timeout=90)
    run_tool("DIRSEARCH SCAN",
             f"dirsearch -u http://{target} -e php,html,js,asp,aspx -w {PRESET['dirsearch']}",
             "Brute-force direktori/file web advance (dirsearch).", timeout=90)
    run_tool("NIKTO SCAN",
             f"nikto -h http://{target} -Tuning x -Cgidirs all -nointeractive",
             "Scan vulnerability web server (nikto).", timeout=180)
    run_tool("FEROXBUSTER SCAN",
             f"feroxbuster -u http://{target} -w {PRESET['feroxbuster']} -k -x php,html,js",
             "Web fuzzing paralel (feroxbuster).", timeout=90)
    run_tool("FFUF SUBDOMAIN SCAN",
             f"ffuf -u http://{target}/ -H 'Host: FUZZ.{target}' -w {PRESET['ffuf_subdomain']} -c -t 50",
             "Cari subdomain pada domain target (ffuf).", timeout=120)
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
    run_tool("NMAP AD SCAN",
             f"nmap -Pn -sC -sV -p 53,88,135,139,389,445,464,636,3268,3269 --script=ldap-search,smb-enum-shares,smb-enum-users {target} --host-timeout 120s",
             "Scan port dan enum AD/SMB/LDAP dengan nmap.", timeout=180, clear=True)
    run_tool("ENUM4LINUX SCAN",
             f"enum4linux -a {target}",
             "Enum user/group/share SMB (enum4linux).", timeout=180)
    run_tool("CRACKMAPEXEC SMB SCAN",
             f"crackmapexec smb {target} -u '' -p '' --shares --users",
             "SMB enum + policy + share (crackmapexec).", timeout=90)
    ldap_base = ",".join([f"DC={d}" for d in domain.split(".")])
    run_tool("LDAPSEARCH SCAN",
             f"ldapsearch -x -H ldap://{target} -b '{ldap_base}' '(objectClass=person)' sAMAccountName",
             "Dump user/group AD via LDAP.", timeout=180)
    run_tool("KERBRUTE USERENUM",
             f"kerbrute userenum --dc {target} -d {domain} /usr/share/seclists/Usernames/cirt-default-usernames.txt",
             "Enum user valid Kerberos (kerbrute).", timeout=180)
    run_tool("GETNPUSERS SCAN",
             f"impacket-GetNPUsers {domain}/ -no-pass -dc-ip {target} -usersfile /usr/share/seclists/Usernames/cirt-default-usernames.txt",
             "Cari user AS-REP roasting vuln.", timeout=180)
    run_tool("SMBCLIENT GUEST",
             f"smbclient -L \\\\{target} -N",
             "Test akses share SMB (guest/anon).", timeout=90)
    scan_end = get_now()
    append_to_json_results(
        "SUMMARY", "-", "Total waktu eksekusi quick scan AD",
        f"{duration_seconds(scan_start, scan_end)} detik",
        scan_start, scan_end
    )
    print("[INFO] Quick Scan AD selesai. Gunakan menu 100 untuk lihat hasil.")

def main():
    while True:
        print("\nMenu SECUTOOLBOX V2:")
        print("1. Quick Scan Linux/Web")
        print("2. Quick Scan Active Directory")
        print("100. Print Hasil Scanning (HTML & Ekspor PDF)")
        print("0. Keluar")
        choice = input("Pilih menu: ").strip()
        if choice == "1":
            quick_scan_linux()
        elif choice == "2":
            quick_scan_ad()
        elif choice == "100":
            print_scanning_results()
        elif choice == "0":
            print("Keluar.")
            break
        else:
            print("Pilihan tidak valid.")

if __name__ == "__main__":
    main()

