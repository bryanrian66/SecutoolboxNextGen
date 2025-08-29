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
python secutoolbox.py
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
  - `25. Run evilwinrm (password)`
  - `26. Run evilwinrm (hash)`
  - `27. Run crackmapexec smb (password)`
  - `28. Run crackmapexec smb (hash)`
  - `29. Run crackmapexec evilwinrm (password)`
  - `30. Run crackmapexec evilwinrm (hash)`
  - `31. Run rpcclient`
  - `32. Run enum4linux`
  - `33. Run snmpwalk`
  - `34. Run snmpwalk extend`
  - `35. Run xfreerdp`
  - `36. Run dnsenum`
  - `37. Run kerbrute (userenum)`
  - `38. Run GetNPUsers`
  - `39. Run Psexec (password)`
  - `40. Run Psexec (hash)`
  - `41. Run GetADUsers (optional User & Password)`
  - `42. Run ldapsearch`
  - `43. Run secretsdump (username & password)`
  - `44. Run mssqlclient (username, password & database)`
  - `45. Run getUserSPNs (username & password)`
  - `46. Run GetNPUsers (BruteForce Username.txt)`
  - `47. Quick Scan for Active Directory`
  - `99. Addhosts`
  - `100. Print Hasil Scanning`
  - `0. Exit`

## Example Usage

To run an Nmap full scan:
1. Select option `3` from the menu.
2. Enter the target IP or domain.

To add a host entry:
1. Select option `99` from the menu.
2. Enter the IP and host.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue for any bugs or feature requests.

## Contact

For any inquiries or issues, please open an issue on GitHub.
