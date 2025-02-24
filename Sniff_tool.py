import sys
import argparse
from scapy.all import ARP, Ether, srp

parser = argparse.ArgumentParser(description="Network Scanner using ARP requests")
parser.add_argument("-ip", "--ipadd", help="IP Address/Subnet Mask", required=True)
args = parser.parse_args()

def scan_network(ip):
    # Create an ARP request packet
    arp_request = ARP(pdst=ip)
    # Create an Ethernet broadcast frame
    broadcast_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    # Combine them into a full request
    final_request = broadcast_frame / arp_request

    # Send the request and get the responses
    results_ans, _ = srp(final_request, timeout=2, verbose=False)

    # If no devices respond, print a message
    if not results_ans:
        print("No devices found on the network. Check your IP or try again.")
        return

    # Print the results in a formatted way
    print("\nIP Address\t\tMAC Address")
    print("-" * 40)
    for sent, received in results_ans:
        print(f"{received.psrc}\t\t{received.hwsrc}")

# Run the scanner
scan_network(args.ipadd)
