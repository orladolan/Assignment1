
# Imports
import sys
import os
import time
from scapy.all import ARP, sniff, Ether, srp, get_if_addr, get_if_hwaddr,  get_if_list
 
# Variables
help_shown = False     # To track if help has been shown
header_shown = False     # To track if header has been shown
detected_ip_mac_pairs = {} # To store all unique IP and MAC pairs, and packet count

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



# TASK 1
# Seperate function for processing args for readability
# Individually goes through the valid inputs and determines what to do based on them
def process_argument(arg):
   
    if arg in ["-h", "--help", "help", "h"]:
        help()
        return False  # Makes the system continue to run
    
    elif arg in ["-p", "--passive", "passive", "p"]:
       interface = input("Enter the interface to listen on (e.g., WiFi / eth0): ")
       try:
            passive_scan(interface)  # Attempt to start passive scan on the specified interface
       except Exception as e:
            print(f"Error: {e}")  # Catch and print any errors from invalid interfaces
            return False
       return False   

    elif arg in ["-a", "--active", "active", "a"]:
       interface = input("Enter the interface to listen on (e.g., WiFi / eth0): ")
       try:
            active_recon(interface)  # Attempt to start passive scan on the specified interface
       except Exception as e:
            print(f"Error: {e}")  # Catch and print any errors from invalid interfaces
            return False
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
        global header_shown

        if ARP in pkt and pkt[ARP].op == 2:  # ARP reply operation code
            src_ip = pkt[ARP].psrc           # Source IP address
            src_mac = pkt[ARP].hwsrc         # Source MAC address
            
            # Increment count or add new entry for IP
            if src_ip in detected_ip_mac_pairs:
                current_mac, current_count = detected_ip_mac_pairs[src_ip]
                detected_ip_mac_pairs[src_ip] = (current_mac, current_count + 1)
            else:
                detected_ip_mac_pairs[src_ip] = (src_mac, 1)
            
            # Display table header once when the first packet is detected
            if not header_shown:
                display_table_header(interface, "Passive", len(detected_ip_mac_pairs))   
                header_shown = True

            # Display each entry in real-time with the updated packet count
            display_host_entry(src_ip, detected_ip_mac_pairs[src_ip])

    print(f"\nListening for ARP traffic on interface: {interface}. Press Ctrl+C to stop.")  
    
    # Sniff for ARP packets
    try:
        sniff(iface=interface, filter="arp", prn=process_packet) 

    except KeyboardInterrupt:
        print("\nStopped listening for ARP traffic.")   
        time.sleep(3)
            
    finally:
        if detected_ip_mac_pairs:
            print("\nSummary of Hosts:")
            summary_display(interface, "Passive", detected_ip_mac_pairs)
        else:
             print("No ARP packets detected.")
      
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

            print(f"ARP Reply Received - IP: {src_ip} - MAC: {src_mac}")  # Outputs reply info  


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
            summary_display(interface, "Active", detected_active_pairs)
            time.sleep(5)
     else:
            print("No active hosts detected.")
            time.sleep(3)

# TASK 4: IMPROVED DISPLAY

# Display for when user ends the passive process

def summary_display(interface, mode, hosts):
    # Header with dynamic information
    print(f"Interface: {interface}    Mode: {mode}    Found {len(hosts)} host{'s' if len(hosts) != 1 else ''}") 
    print("-" * 70)

    # Column headers
    if mode == "Passive":
        print(f"{'MAC':<20} {'IP':<15} {'Host Activity':<10}")
        print("-" * 70)
        
        # Sort hosts by packet count in descending order
        sorted_hosts = sorted(hosts.items(), key=lambda item: item[1][1], reverse=True)
        for src_ip, (src_mac, packet_count) in sorted_hosts:
            print(f"{src_mac:<20} {src_ip:<15} {packet_count:<10}")
    else:  # for Active mode
        print(f"{'MAC':<20} {'IP':<15}")
        print("-" * 70)
        
        # Display each MAC-IP pair in table format
        for src_ip, src_mac in hosts.items():
            print(f"{src_mac:<20} {src_ip:<15}")
    
    print("-" * 70)
    

# Real-Time Display
def display_table_header(interface, mode, host_count):
    
  # Display the network scan table header
    
    print(f"Interface: {interface}    Mode: {mode}")
    print("-" * 70)
    print(f"{'MAC':<20} {'IP':<15}")
    print("-" * 70)


# Display each host entry
def display_host_entry(src_ip, data):
    src_mac, packet_count = data
    print(f"{src_mac:<20} {src_ip:<15}")


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
