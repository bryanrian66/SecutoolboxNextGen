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
- **Print Hasil Scanning**: HTML OUTPUT.
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
  - `1. Run ffuf (subdomain)`
  - `2. Run ffuf (directory)`
  - `3. Run nmap (full)`
  - `4. Run nmap (udp)`
  - `5. Run whatweb`
  - `6. Run wfuzz (subdomain)`
  - `7. Run gobuster (directory)`
  - `8. Run gobuster (dns)`
  - `9. Run gobuster (vhost)`
  - `10. Run dirsearch`
  - `11. Run dirsearch`
  - `12. Run feroxbuster`
  - `13. Quick Scan for Linux`
- **Active Directory**
  - `20. Run smbclient (guest)`
  - `21. Run smbclient (user & password)`
  - `22. Run smbclient (login)`
  - `23. Run smbmap (hash)`
  - `24. Run smbmap (user & password)`
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
