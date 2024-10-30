
# Imports
import sys
import time
from scapy.all import ARP, sniff

# Variables
help_shown = False     # To track if help has been shown
detected_ip_mac_pairs = {} # To store all unique IP and MAC pairs

def help():
    #Help Feature - prints out instructions 

    usage_text = """
    Network Reconnaissance Tool

    How To Use:

    Options:
      -p or --passive:    Listen for traffic at the interface
      -h or --help:       Show a help message and exit
      -e or --exit:       Exit the program
    """
  
    print(usage_text)

# Seperate function for processing args for readability
# Individually goes through the valid inputs and determines what to do based on them
def process_argument(arg):
   
    if arg in ["-h", "--help", "help", "h"]:
        help()
        return False  # Makes the system continue to run
    
    elif arg in ["-p", "--passive", "passive", "p"]:
       interface = input("Enter the interface to listen on (e.g., eth0): ")
       passive_scan(interface)
       return False  
    
    elif arg in ["-e", "--exit", "exit", "e"]:
        print("Exiting the program")
        return True  # Exits the system
    
    else:
        print(f"Invalid option: {arg}. Please see options below") # F-String included to show variable arg. 
        help()
        return False  

# Listens for ARP traffic
def passive_scan(interface):
   
    # Handles the ARP packets & outputs reply info
    def process_packet(pkt):
        if ARP in pkt and pkt[ARP].op == 2:  # ARP reply operation code
            src_ip = pkt[ARP].psrc  # Source IP address
            src_mac = pkt[ARP].hwsrc  # Source MAC address
       
            detected_ip_mac_pairs[src_ip] = src_mac

            print(f"IP: {src_ip} - MAC: {src_mac}")                       
         
            
    print(f"Listening for ARP traffic on interface: {interface}. Press Ctrl+C to stop.")    

    # Sniff the user's interface for packets
    try:
        sniff(iface=interface, filter="arp", prn=process_packet) 

    except KeyboardInterrupt: # Stops program on Ctrl + C click
        print("Stopped listening for ARP traffic.")   
        time.sleep(3)
            
    finally:
        if detected_ip_mac_pairs:
            print("Summary of detected devices:")
            for src_ip, src_mac in detected_ip_mac_pairs.items():
                    print(f"IP: {src_ip}, MAC: {src_mac}")
            time.sleep(5)
        else:
             print("No ARP packets detected.")
             time.sleep(3)
                

        print("Exiting passive scan.")          

def main():
    # Initially call the help function only if its the first time the process is ran
    global help_shown

    if help_shown == False:
        help()
        help_shown = True

        
  # Checks command-line arguments
    if len(sys.argv) > 1:    
        for arg in sys.argv[1:]: # Iterate through all args (to end of list)
            if process_argument(arg):
                return  

    # Interactive prompt if no arguments are provided / continuous loop until exit
    while True:
        user_input = input("Please select an option:  ").strip()       
        if process_argument(user_input): # Processes the user input as if it were a command-line argument
            break  




main()
