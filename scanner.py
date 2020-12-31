# David Iosilevich
# Private Network Scanner

import argparse
import scapy.all as scapy
from mac_vendor_lookup import MacLookup


def getArgs():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', dest='target', help='Target IP Address/Address Frame')
    options = parser.parse_args()

    if not options.target:
        parser.error('Please specify target correctly. Use --help for more info.')
    
    return options


def scan(ip_addr):
    # Send ARP request and generate ethernet frame
    req = scapy.ARP(pdst=ip_addr)
    broadcast_frame = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    broadcast_req = broadcast_frame / req

    # Only accept hosts that answered
    answered = scapy.srp(broadcast_req, timeout=1, verbose=False)[0]
    dict_list = []

    # Traverse hosts
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

    print('[*] Scanning network...', end='')
    output = scan(options.target)
    print('\t\tdone')

    display(output)
