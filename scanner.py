# By David Iosilevich
# Network Scanner using ARP

import argparse
import scapy.all as scp
from mac_vendor_lookup import MacLookup


def getArgs():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', dest='target', help='Target IP Address/Size of Prefix in Bits (e.g. -t xxx.xxx.x.x/24), find default gateway using "ifconfig" or "ipconfig".')
    options = parser.parse_args()

    if not options.target:
        parser.error('Please specify target and prefix correctly. Use --help for more info.')
    
    return options


def scan(ip_addr):
    # Generate ARP request and ethernet frame
    arp_req = scp.ARP(pdst=ip_addr)
    broadcast_frame = scp.Ether(dst='ff:ff:ff:ff:ff:ff')

    # Send combined frame and receieve responses
    broadcast_req = broadcast_frame / arp_req
    responses = scp.srp(broadcast_req, timeout=1, verbose=False)
    
    # Only accept answered responses
    answered = responses[0]

    # Traverse and parse responses
    dict_list = []
    for i in range(len(answered)):
        ip = answered[i][1].psrc
        mac = answered[i][1].hwsrc
        try:
            host = MacLookup().lookup(mac)
        except:
            host = '[Not Found]'

        client_dict = {'ip': ip, 'mac': mac, 'host': host}
        dict_list.append(client_dict)

    return dict_list


def display(dict_list):
    print('\nIP Address\t\tMAC Address\t\tManufacturer')
    print('---------------------------------------------------------------------------------------')

    for dict in dict_list:
        ret = '{}\t\t{}\t{}'.format(dict['ip'], dict['mac'], dict['host'])
        print(ret)

    print('---------------------------------------------------------------------------------------\n')


if __name__ == '__main__':
    options = getArgs()

    print('\n[*] Scanning network...', end='')
    output = scan(options.target)
    print('\tdone')

    display(output)
