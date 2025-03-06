import scapy.all as scapy  # library for network packet manipulation

#Function scans a network and returns a list of active devices.
#Returns: 
def scan_network(network_range):
    #Create an ARP (Address Resolution Protocol) request
    # ARP asks: "Who has this IP address? Tell me your MAC address."
    arp_request = scapy.ARP(pdst=network_range)

    #Create an Ethernet frame with a broadcast MAC address
    #This ensures all devices on the network receive the ARP request.
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    #Combine the ARP request and broadcast into a single packet
    arp_request_broadcast = broadcast / arp_request

    #Send the ARP request and capture responses
    #`srp()` sends the packet and waits for responses (timeout=2 seconds).
    #`verbose=False` disables unnecessary output.
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    #Parse responses to extract IP and MAC addresses
    devices = [] #List of devices that will be filled with IP and MAC Addresses
    for response in answered_list:
        devices.append({"IP": response[1].psrc, "MAC": response[1].hwsrc})

    return devices  #Return the list of active devices

#Function displays scanned devices in a table format.
def display_results(devices):
    print("\nActive Devices Found on the Network:\n")
    print("IP Address\t\tMAC Address")
    print("-" * 40)  #Prints a horizontal line for table formatting

    #Print each device's IP and MAC address
    for device in devices:
        print(f"{device['IP']}\t\t{device['MAC']}")
    
#Main script execution starts here
if __name__ == "__main__":

    #Prompt user to enter the network range (e.g., '192.168.1.1/24')
    network_range = input("\nEnter Network Range (e.g., 192.168.1.1/24): ").strip()

    print("\nScanning network, please wait...\n")

    #Scan the network for active devices
    devices = scan_network(network_range)

    #Display the results if devices are found, else print an error message
    if devices:
        display_results(devices)
    else:
        print("No active devices found. Try a different network range.")
