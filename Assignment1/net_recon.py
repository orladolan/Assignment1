
# Imports
import sys
import time
from scapy.all import ARP, sniff, Ether, srp, get_if_addr, get_if_hwaddr
 
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
      -a or --active:     Send ARP requests to network  
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
    
    elif arg in ["-a", "--active", "active", "a"]:
       interface = input("Enter the interface to listen on (e.g., eth0): ")
       active_recon(interface)
       return False 

    elif arg in ["-e", "--exit", "exit", "e"]:
        print("Exiting the program")
        return True  # Exits the system
    
    else:
        print(f"Invalid option: {arg}. Please see options below") # F-String included to show variable arg. 
        help()
        return False  

# TASK 2: PASSIVE RECON
# Listens for ARP traffic
def passive_scan(interface):
   
    # Handles the ARP packets 
    def process_packet(pkt):
        if ARP in pkt and pkt[ARP].op == 2:  # ARP reply operation code
            src_ip = pkt[ARP].psrc           # Source IP address
            src_mac = pkt[ARP].hwsrc         # Source MAC address
       
            detected_ip_mac_pairs[src_ip] = src_mac

            print(f"IP: {src_ip} - MAC: {src_mac}")   # Outputs reply info                    
         
            
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

#TASK 3: ACTIVE RECON
def active_recon(interface):
     detected_active_pairs = {}  # To store all IP and MAC pairs

    # Handles the ARP request 
     def process_active_packet(pkt):
        if ARP in pkt and pkt[ARP].op == 2:  # ARP reply operation code 
            src_ip = pkt[ARP].psrc           # Source IP address
            src_mac = pkt[ARP].hwsrc         # Source MAC address
            detected_active_pairs[src_ip] = src_mac  
            print(f"ARP Reply Recieved - IP: {src_ip} - MAC: {src_mac}")  # Outputs reply info  


    # Get the IP address for interface
     ip_address = get_if_addr(interface)
     mac_address = get_if_hwaddr(interface)

    # Calculate the network address
     
     network_prefix = ip_address.rsplit('.', 1)[0]  # Splits for first 3 octets of IP
     print(f"Scanning network: {network_prefix}.0/24")  # Uses a /24 network

    # Construct ARP packet
     for i in range(1, 255):  # Scan entire network
        target_ip = f"{network_prefix}.{i}"
        
        ether_hdr = Ether(dst="FF:FF:FF:FF:FF:FF", type=0x0806)  # Create Ethernet header
        
        arp_hdr = ARP(op="who-has", psrc=ip_address, hwsrc=mac_address, pdst=target_ip)  # Create ARP header  

        packet = ether_hdr / arp_hdr # Combine into packet
        
        # Send the packet to network
        try:
            print(f"Sending ARP request to {target_ip}") 

            answers, _ = srp(packet, iface=interface, timeout=1, verbose=False)  # Sends the packet
            
            for _, received in answers:
                 process_active_packet(received)  # Pass each reply to be processed

        except Exception as e:
             print(f"An error occurred: {e}")

     if detected_active_pairs:
            print("\nActive hosts detected:") #\n to leave a line spacing
            for ip_address, mac_address in detected_active_pairs.items():
                    print(f"IP: {ip_address}, MAC: {mac_address}")
            time.sleep(5)
     else:
            print("No active hosts detected.")
            time.sleep(3)



# MAIN FUNCTION
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


if __name__ == '__main__':
    main()
