#!/usr/bin/python3

# INTRO: This is a network reconnaissance script/tool that can operate in two modes: Active or Passive.
# ACTIVE MODE: ARP requests are sent to all the 256 IPs within the subnet and the ARP responses are stored. The source MAC and IP addresses from these responses are displayed on the screen.
# PASSIVE MODE: The tool listens for traffic and filters all the ARP responses being sent on the network. The source MAC and IP addresses from these responses are displayed on the screen.
# DYNAMIC DISPLAY: The output in the terminal updates dynamically based on the user's input. In passive mode, the tool keeps on running until stopped by pressing Ctrl+C.
# HOST ACTIVITY: The passive mode also allows the user to listen for overall traffic on the recorded hosts and sort them based on their host activity.

import sys
import os
from scapy.all import *

def main():
  args = sys.argv # Store all the arguments passed by the user in args

  # Check if the correct number of arguments are provided:
  if len(args) == 0 or len(args) < 4 or len(args) > 4:
    help(args)
    exit()
  # Check if the network interface is specified using -i or --iface
  elif '-i' not in args and '--iface' not in args:
    help(args)
    exit()
  # Check if the options are correctly specified
  elif '-a' not in args and '--active' not in args and '-p' not in args and '--passive' not in args:
    help(args)
    exit()
  else:
    i = 0
    # If arguments are correct then iterate through arguments
    while i < len(args):
      # If the current argument has the specifier
      if args[i] == '-i' or args[i] == '--iface':
        # And the next argument exists
        if i + 1 < len(args):
          # nw_inter gets the network interface name
          nw_inter = args[i+1]
          i+=1 # And the next argument is skipped (the interface name)
      else:
        # The remaining argument gets the mode indicator
        indicate = args[i]
      i+=1

  if indicate == '-p' or indicate == '--passive':
    mode = "Passive"
    passive_scan(nw_inter, mode)
  elif indicate == '-a' or indicate == '--active':
    mode = "Active"
    active_recon(nw_inter, mode)

def passive_scan(nw_inter, mode):
  arp_records = []
  # Clears the terminal
  sys.stdout.write("\033c")
  # Prints the improved display
  sys.stdout.write("\rInterface: "+nw_inter+"\t\t"+"Mode: "+mode+"\t\t"+"Found "+str(len(arp_records))+" hosts\n")
  sys.stdout.flush()
  print("-----------------------------------------------------------------")
  print("MAC"+"\t\t\t"+"IP"+"\t\t\t"+"Host Activity")
  print("-----------------------------------------------------------------")
  def handler(pkt):
    flag = 0
    # Clears the terminal
    sys.stdout.write("\033c")
    # Checks if the packet is an ARP reply
    if ARP in pkt and pkt[ARP].op == 2:
      # Stores the discovered MAC and discovered IP
      disc_ip = pkt[ARP].psrc
      disc_mac = pkt[ARP].hwsrc
      # Checks for duplicates # Will be true if the IP is paired with an updated MAC address
      if (disc_mac, disc_ip) not in arp_records:
        for i in arp_records:
          # Checks if the discovered IP is already present in arp_records
          if i[1] == disc_ip:
            # If true then replace the corressponding MAC with the updated MAC
            i[0] = disc_mac
            # Increment the host activity of this IP by 1
            temp = int(i[2])
            temp+=1
            i[2] = str(temp)
            flag = 1 # Set the flag after updating the MAC address
            break
        if flag != 1: # Checks if a new IP is discovered with a new MAC address
          arp_records.append([disc_mac, disc_ip, str(1)]) # If so then store it and the host activity is initialised to 1
          flag = 0
      # Prints the improved display
      sys.stdout.write("\rInterface: "+nw_inter+"\t\t"+"Mode: "+mode+"\t\t"+"Found "+str(len(arp_records))+" hosts\n")
      sys.stdout.flush()
      print("-----------------------------------------------------------------")
      print("MAC"+"\t\t\t"+"IP"+"\t\t\t"+"Host Activity")
      print("-----------------------------------------------------------------")

      # Sorting the list based on host activity column in descending order using bubble sort
      # Iterates through the whole list for len(arp_records) x times
      for i in range(len(arp_records)):
        # Iterates up till the next element of the element i in arp_records
        for j in range(0, (len(arp_records))-i-1):
          # Compares both the values i and j in arp_records based on their host activity
          if arp_records[j][2] < arp_records[j+1][2]:
            # Swaps the hosts if the host activity of the current record is less than the next record
            arp_records[j], arp_records[j+1] = arp_records[j+1], arp_records[j]
      # Prints the full list
      for i in arp_records:
        print(i[0] + "\t" + i[1] + "\t\t" + i[2])
      # Allows the terminal to refresh. This is done to avoid a blinking terminal.
      os.system("sleep 1")

    # Calculates the total number of packets observed for the recorded hosts
    # Checks if the packet has an IP layer
    elif pkt.haslayer(IP):
      for i in arp_records:
        # Checks if the source IP of the packet matches any of the recorded hosts
        if i[1] == pkt[IP].src:
          # If this is true, then increment the host activity of that host by 1
          temp = int(i[2]) # Host activity needs to be parsed from string to integer before it can be incremented.
          temp+=1
          i[2] = str(temp)
          break
      # Prints the improved display
      sys.stdout.write("\rInterface: "+nw_inter+"\t\t"+"Mode: "+mode+"\t\t"+"Found "+str(len(arp_records))+" hosts\n")
      sys.stdout.flush()
      print("-----------------------------------------------------------------")
      print("MAC"+"\t\t\t"+"IP"+"\t\t\t"+"Host Activity")
      print("-----------------------------------------------------------------")

      # Sorting the list based on host activity column in descending order
      # Iterates through the whole list for len(arp_records) x times
      for i in range(len(arp_records)):
        # Iterates up till the next element of the element i in arp_records
        for j in range(0, (len(arp_records))-i-1):
          # Compares both the values i and j in arp_records based on their host activity
          if arp_records[j][2] < arp_records[j+1][2]:
            # Swaps the hosts if the host activity of the current record is less than the next record
            arp_records[j], arp_records[j+1] = arp_records[j+1], arp_records[j]

      # Prints the full list
      for i in arp_records:
        print(i[0] + "\t" + i[1] + "\t\t" + i[2])
      os.system("sleep 1")
  sniff(iface=nw_inter, prn=handler)

def active_recon(nw_inter, mode):
  # Clears the terminal
  sys.stdout.write("\033c")
  arp_records = []
  # Stores the network IP and MAC address
  nw_ip = get_if_addr(nw_inter)
  nw_mac = get_if_hwaddr(nw_inter)
  # Crafting an ARP request
  eth_hdr = Ether(dst="FF:FF:FF:FF:FF:FF", type=0x0806) # 0x0806 denotes ARP protocol
  arp_hdr = ARP(op="who-has", psrc=nw_ip, hwsrc=nw_mac, pdst=nw_ip+"/24") # This will send the request to all 256 IPs in the subnet
  arp_pkt = eth_hdr/arp_hdr
  # Sending ARP request to each IP and storing ARP responses
  resp, unans = srp(arp_pkt, iface = nw_inter, timeout = 2)
  # Iterating through ARP responses
  for sent,received in resp:
    sys.stdout.write("\033c")
    sys.stdout.write("\rInterface: "+nw_inter+"\t\t"+"Mode: "+mode+"\t\t"+"Found "+str(len(arp_records)+1)+" hosts\n")
    sys.stdout.flush()
    print("-----------------------------------------------------------------")
    print("MAC"+"\t\t\t"+"IP")
    print("-----------------------------------------------------------------")
    # Fetching the stored MAC and IP address pairings
    disc_mac = received.hwsrc
    disc_ip = received.psrc
    # Storing them in arp_records
    arp_records.append([disc_mac, disc_ip])
  # Printing the full list
  for i in arp_records:
    print(i[0] + "\t" + i[1])

def help(args):
  # This function informs the user exactly what is wrong with their command(s) instead of just printing a generalised usage.
  if len(args) == 0 or len(args) < 4:
    print("Error: Insufficient arguments")
  elif len(args) > 4:
    print("Error: Too many arguments")
  if '-i' not in args and '--iface' not in args:
    print("Error: Network interface should be specified using -i or --iface")
  if '-a' not in args and '--active' not in args and '-p' not in args and '--passive' not in args:
    print("Error: Incorrect options")
  print("Usage: sudo ./net_recon.py -i [interface] [options]")
  print("  -p  --passive  passive recon")
  print("  -a  --active   active recon")

main()
