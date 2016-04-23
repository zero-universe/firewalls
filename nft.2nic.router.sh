#!/usr/bin/nft -f

#
# last modified 2016.04.23
# zero.universe@gmail.com
#

# nics:
#
# ens3 = world
# esn4 = lan

table filter {
	
	chain input	{ 
		type filter hook input priority 0; policy drop; 

		# invalid connections
		ct state invalid drop

		# loopback interface
		iif lo accept
		
		# established/related connections
		ct state {established, related} accept

		# incoming inet trafic
		iif ens3 ip protocol tcp goto my_world_tcpv4
		iif ens3 ip protocol udp goto my_world_udpv4
		iif ens3 ip protocol icmp goto my_world_icmpv4
		
		iif ens4 ip protocol tcp goto my_lan_tcpv4
		iif ens4 ip protocol udp goto my_lan_udpv4
		iif ens4 ip protocol icmp goto my_lan_icmpv4

		}
		

	chain my_world_tcpv4 {
		
		# invalid connections
		ct state invalid drop
		
		# loopback interface
		iif lo accept
		
		# established/related connections
		ct state {established, related} accept
		
		# bad tcp -> avoid network scanning:
        tcp flags & (fin|syn) == (fin|syn) drop
        tcp flags & (syn|rst) == (syn|rst) drop
        tcp flags & (fin|syn|rst|psh|ack|urg) == 0 drop
        tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|psh|urg) drop
		
		# open tcp ports: ssh
		iif ens3 tcp dport 22 accept
		
        }
	
	
	chain my_world_udpv4 {

		# invalid connections
		ct state invalid drop

		# loopback interface
		iif lo accept
		
		# established/related connections
		ct state {established, related} accept

        }
         
            
	chain my_world_icmpv4 {

		# invalid connections
		ct state invalid drop

		# loopback interface
		iif lo accept
		
		# established/related connections
		ct state {established, related} accept
		
		iif ens3 icmp type { echo-request, echo-reply, destination-unreachable, parameter-problem } counter accept
		iif ens3 limit rate 10/second counter accept
    
        }
        
        
	chain my_lan_tcpv4 {
		
		# invalid connections
		ct state invalid drop

		# loopback interface
		iif lo accept
		
		# established/related connections
		ct state {established, related} accept
				
		# bad tcp -> avoid network scanning:
        tcp flags & (fin|syn) == (fin|syn) drop
        tcp flags & (syn|rst) == (syn|rst) drop
        tcp flags & (fin|syn|rst|psh|ack|urg) == 0 drop
        tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|psh|urg) drop

		# open tcp ports: ssh,dns,dhcp
		iif ens4 tcp dport { 22,53,67,68 } accept

        }
	
	
	chain my_lan_udpv4 {

		# invalid connections
		ct state invalid drop

		# loopback interface
		iif lo accept
		
		# established/related connections
		ct state {established, related} accept

		# open tcp ports: dns,dhcp
		iif ens4 tcp dport { 53,67,68 } accept
		
        }
         
            
	chain my_lan_icmpv4 {

		# invalid connections
		ct state invalid drop

		# loopback interface
		iif lo accept
		
		# established/related connections
		ct state {established, related} accept
		
		iif ens4 icmp type { echo-request, echo-reply, destination-unreachable, parameter-problem } counter accept
		iif ens4 limit rate 10/second counter accept
    
        }
	
	chain output { 
		type filter hook output priority 0; policy drop;
		
		# invalid connections
		ct state invalid drop

		# loopback interface
		oif lo accept
		
		}
		
		
	chain forward { 
		type filter hook forward priority 0; policy drop;

		# invalid connections
		ct state invalid drop

		# loopback interface
		iif lo accept
		
		# established/related connections
		ct state {established, related} accept

		iif ens4 oif ens3 tcp dport { 22,53,80,443 } counter accept
		iif ens4 oif ens3 udp dport { 53 } counter accept

		}
		
}


table nat {

	chain prerouting {
		type nat hook prerouting priority -150;
		
		}
	

	chain postrouting {
		type nat hook postrouting priority -150; policy accept;
		
		oif ens3 masquerade
		
		# snat
		#ip saddr 192.168.199.0/24 oif ens3 snat 192.168.199.108
		
		}


}
