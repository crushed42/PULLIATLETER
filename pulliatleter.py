import os
from scapy.all import *
from colorama import Fore, Style, init
from wifi import Cell

init(autoreset=True)

# Initialize a list to store unique networks
networks = []

def display_banner():
    os.system('clear')
    print(Fore.CYAN + Style.BRIGHT + """
  ____        _ _ _       _   _      _            
 |  _ \ _   _| | (_) __ _| |_| | ___| |_ ___ _ __ 
 | |_) | | | | | | |/ _` | __| |/ _ \ __/ _ \ '__|
 |  __/| |_| | | | | (_| | |_| |  __/ ||  __/ |   
 |_|    \__,_|_|_|_|\__,_|\__|_|\___|\__\___|_|   
                                                  
    """)
    print(Fore.GREEN + "Wi-Fi Network Analyzer - Fancy Terminal Edition\n")

def packet_handler(packet):
    if packet.haslayer(Dot11Beacon):
        ssid = packet[Dot11Elt].info.decode() if packet[Dot11Elt].info else "Hidden SSID"
        bssid = packet[Dot11].addr2
        channel = int(ord(packet[Dot11Elt:3].info))
        dbm_signal = packet.dBm_AntSignal
        
        # Check if the network is already listed
        if bssid not in [net['BSSID'] for net in networks]:
            networks.append({'SSID': ssid, 'BSSID': bssid, 'Channel': channel, 'Signal': dbm_signal})
            
            # Display the network information
            print(Fore.YELLOW + "[+] SSID: " + Fore.CYAN + ssid)
            print(Fore.YELLOW + "    BSSID: " + Fore.MAGENTA + bssid)
            print(Fore.YELLOW + "    Channel: " + Fore.RED + str(channel))
            print(Fore.YELLOW + "    Signal Strength: " + Fore.GREEN + str(dbm_signal) + " dBm")
            print(Style.RESET_ALL + "-"*50)

def scan_wifi():
    display_banner()
    print(Fore.GREEN + "[*] Scanning for nearby networks... Press Ctrl+C to stop.\n")
    sniff(prn=packet_handler, iface='wlan0', store=False)

if __name__ == "__main__":
    try:
        scan_wifi()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Scan interrupted by user.")
        print(Fore.GREEN + "[*] Exiting...")