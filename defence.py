from multiprocessing import Process

from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, RadioTap, Dot11Deauth

# a dictionary to store all the aps
# MacAddress -> [ssid, channel]
ap_list = {}

# Current interface
monitor_interface = ''

# BSSID of the chosen access point and client
ap_bssid = ''
ap_ssid = ''

# A dictionary that stores for each Access Point BSSID a list of clients
# { 'MAC address of ap' : ['client 1', ....]}
ap_clients = {}

evil_twin = ''  # fake ap MAC address


# Sniffing for aps in the area,
# That the user will choose the access point he is connected to
def sniff_ap(p):
    if p.haslayer(Dot11):
        if p.type == 0 and p.subtype == 8:
            if p.addr2 not in ap_list:
                stats = p[Dot11Beacon].network_stats()
                channel = stats.get("channel")
                ssid = p.info.decode()
                ap_list[p.addr2] = [ssid, channel]


# Sniffing for access points, and check if there is evil access point
def sniff_ap_inf(p):
    if p.haslayer(Dot11):
        if p.type == 0 and p.subtype == 8:
            stats = p[Dot11Beacon].network_stats()
            channel = stats.get("channel")
            ssid = p.info.decode()
            ap_list[p.addr2] = [ssid, channel]
            if equal_ap(ssid) and p.addr2 != ap_bssid:
                print(f'An evil twin attack is detected!')
                print(f'SSID: {ssid}')
                print(f'MAC: {p.addr2}')
                print(f'channel: {channel}')
                print('________________________________')
                deauth_attack(p.addr2)


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


# This function change the monitor interface channel each 0.5 seconds.
# reference: https://charlesreid1.com/wiki/Scapy/AP_Scanner
def channel_hopper_inf():
    ch = 1
    while (1):
        try:
            os.system(f'iwconfig {monitor_interface} channel {ch}')
            # Switching channels from 1 to 14 each 0.5 seconds
            ch = ch % 14 + 1
            time.sleep(0.5)
        except KeyboardInterrupt:
            break


# Broadcasting deauth packets from the evil twin
def deauth_attack(evil_bssid):
    os.system(f"iwconfig {monitor_interface} channel {ap_list[ap_bssid][1]}")

    deauth_client = Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2=evil_bssid, addr3=evil_bssid)

    packet_client = RadioTap() / deauth_client / Dot11Deauth()

    sendp(packet_client, iface=monitor_interface, inter=0.100, count=100)


# Check if the access point have the same name as our ap_ssid
def equal_ap(packet_ssid):
    if ap_ssid == packet_ssid:
        return True
    else:
        return False


def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')


# print the aps to the user
# index     MAC ADDRESS    channel         SSID
def print_aps():
    i = 0
    clear_console()
    print(f'Number of aps: {len(ap_list)}')
    for n in ap_list.keys():
        print(f'index: {i}  MacAddress: {n}  channel: {ap_list[n][1]} \t {ap_list[n][0]}')
        i += 1


# Let the user choose the access point he connected to
# We use this information to compare with other access points
def choose_ap():
    chosen_ap = input("Please choose an index of the ap you want: ")

    # creating a list full of address, then save the chosen bssid in chosen_ap
    list_aps_adr = list(ap_list.keys())

    global ap_bssid
    global ap_ssid
    ap_bssid = list_aps_adr[int(chosen_ap)]
    ap_ssid = ap_list[ap_bssid][0]
    clear_console()

    print(f'You chose the next access point {ap_bssid} - {ap_ssid}')


if __name__ == "__main__":
    os.system('iwconfig')
    monitor_interface = input("Please write the name of the Interface you want to change to monitor mode: ")
    print(f'Changing the mode of {monitor_interface} to monitor mode.')
    os.system('chmod +x sniff')
    os.system(f'./sniff {monitor_interface} 6')
    clear_console()
    print(f'The Interface {monitor_interface} changed its mode to monitor.\n\n\n')

    print("Wait while we search for a list of ap")

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

    print("Now the program is going to scan for two aps with the same ssid.")
    p = Process(target=channel_hopper_inf)
    p.start()
    # start sniffing for Evil Twin
    sniff(iface=monitor_interface, prn=sniff_ap_inf)
