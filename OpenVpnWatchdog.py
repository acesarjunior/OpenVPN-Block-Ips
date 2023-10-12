import argparse
import re
import subprocess
import os

PATTERN = 'TLS Error: TLS key negotiation failed'
PATTERN2 = 'TLS Error: tls-crypt unwrapping failed from'

filename = '/var/log/openvpn/status.log'
file = open(filename, 'r')
Lines = file.readlines()
pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') 
ips = []
i = 0
for line in Lines:
        if PATTERN in line or PATTERN2 in line :
                ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', line)
                #print(ip[i])
                ips.append(ip)
                i = i+1
#print(ips)

for i in range(0, len(ips)):    
    #WRITE RULE -  sudo iptables -A INPUT -s <IP ADDRESS> -j DROP && sudo iptables-save > /etc/iptables/rules.v4 && echo -n "" > /var/log/openvpn/status.log
    ipsrule = str(ips[i]).replace("'","").replace("[","").replace("]","")  
    rule = 'sudo iptables -A INPUT -s ' +ipsrule+ ' -j DROP && sudo iptables-save > /etc/iptables/rules.v4 && echo -n "" > /var/log/openvpn/status.log'
    os.system(rule)
    
#print("complete")
