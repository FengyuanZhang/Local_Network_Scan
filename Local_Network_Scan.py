import os
import time
from scapy.all import *
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import *
from scapy.layers.inet import IP, TCP
import hashlib
import time
import multiprocessing
import requests
from pick import pick
import socket
import random


UNKNOWN_MAC = 'ff:ff:ff:ff:ff:ff'


def get_default_interface():
    interfaces = os.popen('route')
    data = interfaces.readlines()
    interfaces.close()
    return data[2].split()[-1]

def get_ip(interfaces = get_default_interface()):
    datas = os.popen('ifconfig ' + interfaces)
    data = datas.readlines()
    datas.close()
    return data[1].split()[1]

def get_submask(interfaces = get_default_interface()):
    datas = os.popen('ifconfig ' + interfaces)
    data = datas.readlines()
    datas.close()
    return data[1].split()[3]

def get_ip_list(ip = get_ip(), submask = get_submask()):
    the_first_ip = ''
    ip_list = []
    ip_nums = 0
    resrest_1sut_1s = 0
    ip = ip.split('.')
    submask = submask.split('.')
    for i in range(len(ip)):
        the_first_ip = the_first_ip + str(int(ip[i]) & int(submask[i])) + '.'
    the_first_ip = the_first_ip[:-1]
    for i in submask:
        if (int(i) ^ int(255)):
            rest_1s = bin(~int(i) & 0xff)[2:]
    
    ip_nums = pow(2, len(rest_1s))

    t = the_first_ip.split('.')

    
    for i in range(ip_nums):
        r = ''
        for j in range(0,3):
            r = r + str(t[j]) + '.'

        ip_list.append( (r + str(int(t[3])+i)) )
    
    return ip_list

def random_str_byte():
    temp = hashlib.md5()
    temp.update(bytes(str(time.time()),encoding='utf-8'))
    result = temp.hexdigest()
    return bytes(result,encoding='utf-8')

def ping(target_ip):
    pack = IP(dst=target_ip)/ICMP()/random_str_byte()
    result = sr1(pack, timeout=3, verbose=False)
    if result:
        return target_ip, True
    return target_ip, False

def check_living_ip(target_ip = get_ip_list(), thread_num = 64):
    living_ip = []
    pool = multiprocessing.Pool(processes = int(thread_num))
    result = pool.map(ping, target_ip)
    pool.close()
    pool.join()
    for ip, status in result:
        if status:
            living_ip.append(ip)
    return living_ip

def get_mac_from_ip(ip_list, default_ifaces = get_default_interface()):

    temp = srp(Ether(dst=UNKNOWN_MAC) / ARP(pdst=ip_list), timeout = 3, verbose=False, iface=default_ifaces)
    result = temp[0].res
    mac_list = []
    for item in result:
        target_mac = item[1].getlayer(ARP).fields['hwsrc']
        target_ip = item[1].getlayer(ARP).fields['psrc']
        mac_vendor = get_mac_vendor(target_mac)
        try:
            mac_list.append(tuple((target_ip, target_mac, mac_vendor)))
        except:
            pass
    return mac_list

def get_mac_vendor(mac_address):
    MAC_URL = 'http://macvendors.co/api/%s'
    r = requests.get(MAC_URL % mac_address)
    try:
        return (r.json()['result']['company'])
    except:
        return 'Unknow'


def tcp_port_scann(target_ip):
    print('target_ip: ', target_ip)
    a = input('Type the lower range of the port to scan: ')
    b = input('Type the upper range of the port to scan: ')

    lowerRange = int(a)
    upperRange = int(b)

    result = []
    ans, unans = sr( IP(dst=target_ip)/TCP(dport=(lowerRange, upperRange),flags="S"), verbose = False, timeout=3)
    print(ans)
    for i in range(len(ans.res)):
        if ans.res[i][1].getlayer(TCP).fields['flags'] == 'SA':
            result.append(ans.res[i][1].getlayer(TCP).fields['sport'])
    return result

if __name__ == '__main__':
    mac_ip_vendor_list = get_mac_from_ip(check_living_ip())

    title = 'Select the ip to scan:'
    selected_target, _ = pick(mac_ip_vendor_list, title)

    ip, *n = selected_target
    open_ports = tcp_port_scann(ip)

    ip, mac, vendor = selected_target
    print('IP ' + ip + ' has mac: ' + mac + ' from ' + vendor + ' company ' + 'with following ports open ')

    port = ''
    for i in open_ports:
        port = port + str(i) + ' '
    print(port)
