PRESET = {
    # Wordlist untuk directory/file brute-force. quickhits.txt sudah bagus untuk quick scan.
    # Namun, rockyou.txt tidak cocok untuk directory.
    # Untuk scan yang lebih mendalam, Anda bisa menggunakan dirb/common.txt atau dirbuster/directory-list-2.3-small.txt.
    "dir_fuzz": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "quick_dir_fuzz": "/usr/share/seclists/Discovery/Web-Content/quickhits.txt",

    # Wordlist untuk subdomain brute-force.
    # subdomains-top1million-5000.txt sudah bagus.
    "subdomain_fuzz": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",

    # Wordlist untuk usernames, sangat penting untuk Active Directory dan umum.
    # cirt-default-usernames.txt sudah bagus, namun ada yang lebih lengkap.
    "usernames": "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt",
    "quick_usernames": "/usr/share/seclists/Usernames/cirt-default-usernames.txt",

    # Wordlist untuk password, diperlukan untuk brute-force login.
    "passwords": "/usr/share/seclists/Passwords/rockyou.txt",

    # Wordlist untuk layanan khusus, seperti Kerberos.
    # Usernames yang sama bisa digunakan.
    "kerbrute_userenum": "/usr/share/seclists/Usernames/cirt-default-usernames.txt",
    
    # Wordlist untuk virtual hosts.
    "virtual_hosts": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",

    # ✅ Tambahan untuk tool lain yang dipanggil di menu / secutoolbox
    "ffuf_dir": "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "ffuf_subdomain": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "dirsearch": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
    "gobuster_dir": "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "feroxbuster": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
}
