#!/usr/bin/nft -f

#
# last modified 2016.04.23
# zero.universe@gmail.com
#

# nics:
#
# eth0 = world
# eth1 = lan
# eth2 = gwlan
# eth3 = kvms
# tun1 = ziont

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
		iif eth0 ip protocol tcp goto my_world_tcpv4
		iif eth0 ip protocol udp goto my_world_udpv4
		iif eth0 ip protocol icmp goto my_world_icmpv4
		
		iif eth1 ip protocol tcp goto my_lan_tcpv4
		iif eth1 ip protocol udp goto my_lan_udpv4
		iif eth1 ip protocol icmp goto my_lan_icmpv4
		
		iif eth2 ip protocol tcp goto my_gwlan_tcpv4
		iif eth2 ip protocol udp goto my_gwlan_udpv4
		iif eth2 ip protocol icmp goto my_gwlan_icmpv4
		
		iif eth3 ip protocol tcp goto my_kvms_tcpv4
		iif eth3 ip protocol udp goto my_kvms_udpv4
		iif eth3 ip protocol icmp goto my_kvms_icmpv4
		
		iif wlan0 ip protocol tcp goto my_wlan_tcpv4
		iif wlan0 ip protocol udp goto my_wlan_udpv4
		iif wlan0 ip protocol icmp goto my_wlan_icmpv4
		
		iif tun1 ip protocol tcp goto my_ziont_tcpv4
		iif tun1 ip protocol udp goto my_ziont_udpv4
		iif tun1 ip protocol icmp goto my_ziont_icmpv4

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

		# open tcp ports: openvpn, sshd
		iif eth0 tcp dport { 1195, 23235 } accept

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

		iif eth0 icmp type { echo-request, echo-reply, destination-unreachable, parameter-problem } counter accept
		iif eth0 limit rate 10/second counter accept
    
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

		# open tcp ports: dns,dhcp,ntp,squid,tor,sec
		iif eth1 tcp dport { 53,67,68,123,3128,9060,23235 } accept

        }
	
	
	chain my_lan_udpv4 {

		# invalid connections
		ct state invalid drop

		# loopback interface
		iif lo accept
		
		# established/related connections
		ct state {established, related} accept
		
		# open tcp ports: dns,dhcp,ntp
		iif eth1 tcp dport { 53,67,68,123 } accept
		
        }
         
            
	chain my_lan_icmpv4 {

		# invalid connections
		ct state invalid drop

		# loopback interface
		iif lo accept
		
		# established/related connections
		ct state {established, related} accept
		
		iif eth1 icmp type { echo-request, echo-reply, destination-unreachable, parameter-problem } counter accept
		iif eth1 limit rate 10/second counter accept
    
        }


	chain my_gwlan_tcpv4 {

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

		# open tcp ports: dns,dhcp,ntp,squid
		iif eth2 tcp dport { 53,67,68,123,3128 } accept

        }
	
	
	chain my_gwlan_udpv4 {

		# invalid connections
		ct state invalid drop

		# loopback interface
		iif lo accept
		
		# established/related connections
		ct state {established, related} accept
		
		# open tcp ports: dns,dhcp,ntp
		iif eth2 tcp dport { 53,67,68,123 } accept
		
        }
         
            
	chain my_gwlan_icmpv4 {

		# invalid connections
		ct state invalid drop

		# loopback interface
		iif lo accept
		
		# established/related connections
		ct state {established, related} accept
		
		iif eth2 icmp type { echo-request, echo-reply, destination-unreachable, parameter-problem } counter accept
		iif eth2 limit rate 3/second counter accept
    
        }
        
        
	chain my_kvms_tcpv4 {

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

		# open tcp ports: dns,dhcp,ntp,squid
		iif eth3 tcp dport { 53,67,68,123,3128 } accept

        }
	
	
	chain my_kvms_udpv4 {

		# invalid connections
		ct state invalid drop

		# loopback interface
		iif lo accept
		
		# established/related connections
		ct state {established, related} accept
		
		# open tcp ports: dns,dhcp,ntp
		iif eth3 tcp dport { 53,67,68,123 } accept
		
        }
         
            
	chain my_kvms_icmpv4 {

		iif eth3 icmp type { echo-request, echo-reply, destination-unreachable, parameter-problem } counter accept
		iif eth3 limit rate 3/second counter accept
    
        }
        
        
	chain my_wlan_tcpv4 {

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

		# open tcp ports: dns,dhcp,ntp,squid,tor,sec
		iif wlan0 tcp dport { 53,67,68,123,3128,9061,23235 } accept

        }
	
	
	chain my_wlan_udpv4 {

		# invalid connections
		ct state invalid drop

		# loopback interface
		iif lo accept
		
		# established/related connections
		ct state {established, related} accept
		
		# open tcp ports: dns,dhcp,ntp
		iif wlan0 tcp dport { 53,67,68,123 } accept
		
        }
         
            
	chain my_wlan_icmpv4 {

		# invalid connections
		ct state invalid drop

		# loopback interface
		iif lo accept
		
		# established/related connections
		ct state {established, related} accept
		
		iif wlan0 icmp type { echo-request, echo-reply, destination-unreachable, parameter-problem } counter accept
		iif wlan0 limit rate 3/second counter accept
    
        }
	
	
	chain output { 
		type filter hook output priority 0; policy accept;

		# invalid connections
		ct state invalid drop

		# loopback interface
		oif lo accept
		
		}
		
		
	chain forward { 
		type filter hook forward priority 0; policy drop;

		# invalid connections
		ct state invalid drop

		ct state {established, related} accept

		iif eth1 oif eth2 accept
		iif eth1 oif eth3 accept
		iif eth1 oif wlan0 accept
		iif eth1 oif tun1 accept
		
		iif wlan0 oif eth1 accept
		iif wlan0 oif eth3 accept
		iif wlan0 oif tun1 accept
		
		iif tun1 oif eth1 accept
		iif tun1 oif wlan0 accept
		
		}
		
}


table nat {

	chain prerouting {
		type nat hook prerouting priority -150;
		
		}
	

	chain postrouting {
		type nat hook postrouting priority -150; policy accept;
		
		oif eth0 masquerade
		
		# snat
		#ip saddr 192.168.77.0/24 oif eth0 snat 1.2.3.4
		#ip saddr 192.168.88.0/24 oif eth0 snat 1.2.3.4
		#ip saddr 192.168.99.0/24 oif eth0 snat 1.2.3.4
		
		}

}
