# SecuToolboxNextGen

SecuToolboxNextgen is a comprehensive set of security tools designed to simplify and automate various penetration testing tasks. This tool features the ability to print scan results in HTML format, as well as quick scans for Linux and Active Directory.

## Features

- **FFUF**: Subdomain and directory fuzzing.
- **Nmap**: Full and UDP scans.
- **WhatWeb**: Website fingerprinting.
- **WFuzz**: Subdomain brute-forcing.
- **Gobuster**: Directory, DNS, and virtual host brute-forcing.
- **Dirsearch**: Directory search.
- **SMB Tools**: SMBClient, SMBMap.
- **Evil-WinRM**: Windows Remote Management.
- **CrackMapExec**: SMB and WinRM brute-forcing.
- **RPCClient**: RPC enumeration.
- **Enum4Linux**: Linux enumeration.
- **SNMPWalk**: SNMP enumeration.
- **xFreeRDP**: FreeRDP client.
- **Print Hasil Scanning**: HTML & PDF OUTPUT.
- **Quick Scan**: For Linux & Active Directory.

## Prerequisites

Ensure you have the following tools installed:
- Python 3.x
- FFUF
- Nmap
- WhatWeb
- WFuzz
- Gobuster
- Dirsearch
- SMBClient
- SMBMap
- Evil-WinRM
- CrackMapExec
- RPCClient
- Enum4Linux
- SNMPWalk
- xFreeRDP

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/bryanrian66/SecutoolboxNextGen.git
   cd SecuToolboxNextGen

2. Ensure all required tools are installed and available in your PATH.

## Usage

Run the main script to access the menu:
```bash
python3 secutoolbox.py
```

## Menu Options

- **Linux/Web & General:**
  - `1. Run nmap (full)                           - Scan seluruh port TCP, deteksi service & versi`
  - `2. Run whatweb                               - Deteksi framework & teknologi web target`                     
  - `3. Run ffuf (subdomain)                      - Cari subdomain pada domain target (web enumeration)` 
  - `4. Run ffuf (directory)                      - Bruteforce direktori/file tersembunyi di web`
  - `5. Run gobuster (directory)                  - Bruteforce direktori/file tersembunyi web (gobuster)`
  - `6. Run dirsearch                             - Cari direktori/file tersembunyi (dirsearch)`
  - `7. Run feroxbuster                           - Web fuzzing paralel, cepat (feroxbuster)`
  - `8. Run nikto                                 - Scan vulnerability web server (nikto)`
  - `9. Quick Scan for Linux                      - Otomatisasi scan web, enum, vuln (1-8)`
- **Active Directory & Internal (Utama)**
  - `10. Run nmap (AD script)                     - Scan port AD/SMB/LDAP dengan script enum`
  - `11. Run enum4linux                           - Enum user/group/share SMB (enum4linux, guest/anon)`
  - `12. Run crackmapexec smb                     - SMB enum + auth (crackmapexec, guest/anon)`
  - `13. Run ldapsearch                           - Enum user/group AD (ldapsearch)`
  - `14. Run kerbrute (userenum)                  - Enum user Kerberos (kerbrute)`
  - `15. Run GetNPUsers                           - Enum user AS-REP roasting (impacket-GetNPUsers)`
  - `16. Run smbclient (guest)                    - Enum share SMB tanpa login (guest/anon)`
  - `17. Quick Scan for Active Directory          - Otomatisasi enum AD, SMB, Kerberos, dll (10-16)`
- **Active Directory & Internal (Lanjutan/Opsional)**
  - `18. Run smbmap (guest)                       - Enum share SMB (smbmap, guest/anon)`
  - `19. Run smbmap (user & password)             - Enum share SMB (smbmap, authenticated)`            
  - `20. Run evilwinrm (password)                 - Remote shell ke Windows (evilwinrm, password)`                
  - `21. Run evilwinrm (hash)                     - Remote shell ke Windows (evilwinrm, hash)`
  - `22. Run crackmapexec smb (password)          - SMB enum + auth (crackmapexec, password)`
  - `23. Run crackmapexec smb (hash)              - SMB enum + auth (crackmapexec, hash)`
  - `24. Run crackmapexec winrm (password)        - WinRM enum+exec (crackmapexec, password)`
  - `25. Run crackmapexec winrm (hash)            - WinRM enum+exec (crackmapexec, hash)`
  - `26. Run rpcclient                            - Enum info Windows (rpcclient, guest/anon)`
  - `27. Run snmpwalk                             - Enum SNMP v1 (public)`
  - `28. Run snmpwalk extend                      - Enum SNMP extend (public)`
  - `29. Run xfreerdp                             - Remote dekstop RDP (xfreerdp)`
  - `30. Run dnsenum                              - Enum DNS, subdomain, zone transfer`
  - `31. Run Psexec (password)                    - Remote command Windows (psexec, password)`                  
  - `32. Run Psexec (hash)                        - Remote command Windows (psexec, hash)`                        
  - `33. Run GetADUsers                           - Dump user Active Directory (impacket-GetADUsers)`
  - `34. Run secretsdump                          - Dump hash/password AD (impacket-secretsdump)`
  - `35. Run mssqlclient                          - Enum SQL Server (impacket-mssqlclient)`
  - `36. Run getUserSPNs                          - Cari SPN user (kerbroasting/ad privesc)`
  - `37. GetNPUsers (BruteForce List)             - Brute-force user AS-REP roasting`
  - `100. Print Hasil Scanning                    - Lihat hasil scan dalam format HTML/PDF`
  - `0. Exit`

## Example Usage

To run an Nmap full scan:
1. Select option `1` from the menu.
2. Enter the target IP or domain.

To Print Output:
1. Select option `100` from the menu
   
## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue for any bugs or feature requests.

## Contact

For any inquiries or issues, please open an issue on GitHub.
