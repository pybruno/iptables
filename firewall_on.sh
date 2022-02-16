#!/bin/bash
# set some basic rules with iptables
echo "set firewall rules"

# create ipset
ipset -N blacklist hash:net
ipset flush blacklist

# drop all incoming
iptables -P INPUT DROP

# logging stuff
iptables -N IN_DROP
iptables -A IN_DROP -j LOG --log-prefix '[IN DROP] : '
iptables -A IN_DROP -j DROP

iptables -N OUT_DROP
iptables -A OUT_DROP -j LOG --log-prefix '[OUT DROP] : '
iptables -A OUT_DROP -j DROP
echo "loging stuff in, out"

# Allows all loopback (lo0) traffic and drop all traffic to 127/8 that doesn't use lo0
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT ! -i lo -d 127.0.0.0/8 -j REJECT

# Accepts all established inbound connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

for i in $(cat /somepath/blacklist.txt); do ipset -A blacklist $i; done
echo "build list ip blacklist: OK"

# Drop rule... must have ipset
iptables -A INPUT -m set --match-set blacklist src -j DROP
echo "DROP blacklist"

# Allows HTTP connections from anywhere
iptables -A INPUT -s X.X.X.X/32 -m multiport -p tcp --dports 80,443 -j ACCEPT

# allow nagios
iptables -A INPUT -s X.X.X.X/32 -p tcp -m state --state NEW --dport 5666 -j ACCEPT
echo "allow ip nagios"

# allows SSH
iptables -A INPUT -p tcp -m state --state NEW --dport ssh -j ACCEPT
echo "allow ssh"

# Allow ping
#  note that blocking other types of icmp packets is considered a bad idea by some
#  remove -m icmp --icmp-type 8 from this line to allow all kinds of icmp:
#  https://security.stackexchange.com/questions/22711
iptables -A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT

# allow all outbound trafic
iptables -A OUTPUT -j ACCEPT
echo "allow OUTPUT"

# in/out lo
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
echo "allow lo"

# log iptables denied calls (access via 'dmesg' command)
#iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "input denied: " --log-level 7

# Reject all other inbound - default deny unless explicitly allowed policy:
iptables -A INPUT -j REJECT
# iptables -A FORWARD -j REJECT

# logging
iptables -A INPUT -j IN_DROP
iptables -A OUTPUT -j OUT_DROP
echo "enable logging stuff"

echo "end of iptables rules"

exit 0
