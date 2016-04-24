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

table ip6 filter {
	
	chain input	{ 
		type filter hook input priority 0; policy drop; 

		# invalid connections
		ct state invalid drop

		# loopback interface
		iif lo accept
		
		# established/related connections
		ct state {established, related} accept

		# incoming inet trafic
		iif eth0 ip protocol tcp goto my_world_tcpv6
		iif eth0 ip protocol udp goto my_world_udpv6
		iif eth0 ip protocol icmp goto my_world_icmpv6
		
		iif eth1 ip protocol tcp goto my_lan_tcpv6
		iif eth1 ip protocol udp goto my_lan_udpv6
		iif eth1 ip protocol icmp goto my_lan_icmpv6
		
		iif eth2 ip protocol tcp goto my_gwlan_tcpv6
		iif eth2 ip protocol udp goto my_gwlan_udpv6
		iif eth2 ip protocol icmp goto my_gwlan_icmpv6
		
		iif eth3 ip protocol tcp goto my_kvms_tcpv6
		iif eth3 ip protocol udp goto my_kvms_udpv6
		iif eth3 ip protocol icmp goto my_kvms_icmpv6
		
		iif wlan0 ip protocol tcp goto my_wlan_tcpv6
		iif wlan0 ip protocol udp goto my_wlan_udpv6
		iif wlan0 ip protocol icmp goto my_wlan_icmpv6
		
		iif tun1 ip protocol tcp goto my_ziont_tcpv6
		iif tun1 ip protocol udp goto my_ziont_udpv6
		iif tun1 ip protocol icmp goto my_ziont_icmpv6

		}
		
		
	chain my_world_tcpv6 {
		
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

		# open tcp ports: sec
		iif eth0 tcp dport { 23235 } accept

        }
	
	
	chain my_world_udpv6 {

		# invalid connections
		ct state invalid drop

		# loopback interface
		iif lo accept
		
		# established/related connections
		ct state {established, related} accept
		
        }
         
            
	chain my_world_icmpv6 {

		# invalid connections
		ct state invalid drop

		# loopback interface
		iif lo accept
		
		# established/related connections
		ct state {established, related} accept

		iif eth0 icmp type { echo-request, echo-reply, destination-unreachable, packet-too-big, time-exceeded, parameter-problem, router-solicitation, router-advertisement, neighbor-solicitation, neighbor-advertisement, 141, 142, 151, 152, 153  } counter accept
		iif eth0 limit rate 10/second counter accept
    
        }


	chain my_lan_tcpv6 {
	
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
	
	
	chain my_lan_udpv6 {

		# invalid connections
		ct state invalid drop

		# loopback interface
		iif lo accept
		
		# established/related connections
		ct state {established, related} accept
		
		# open tcp ports: dns,dhcp,ntp
		iif eth1 tcp dport { 53,67,68,123 } accept
		
        }
         
            
	chain my_lan_icmpv6 {

		# invalid connections
		ct state invalid drop

		# loopback interface
		iif lo accept
		
		# established/related connections
		ct state {established, related} accept
		
		iif eth1 icmp type { echo-request, echo-reply, destination-unreachable, packet-too-big, time-exceeded, parameter-problem, router-solicitation, router-advertisement, neighbor-solicitation, neighbor-advertisement, 141, 142, 151, 152, 153  } counter accept
		iif eth1 limit rate 10/second counter accept
    
        }


	chain my_gwlan_tcpv6 {

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
	
	
	chain my_gwlan_udpv6 {

		# invalid connections
		ct state invalid drop

		# loopback interface
		iif lo accept
		
		# established/related connections
		ct state {established, related} accept
		
		# open tcp ports: dns,dhcp,ntp
		iif eth2 tcp dport { 53,67,68,123 } accept
		
        }
         
            
	chain my_gwlan_icmpv6 {

		# invalid connections
		ct state invalid drop

		# loopback interface
		iif lo accept
		
		# established/related connections
		ct state {established, related} accept
		
		iif eth2 icmp type { echo-request, echo-reply, destination-unreachable, packet-too-big, time-exceeded, parameter-problem, router-solicitation, router-advertisement, neighbor-solicitation, neighbor-advertisement, 141, 142, 151, 152, 153  } counter accept
		iif eth2 limit rate 3/second counter accept
    
        }
        
        
	chain my_kvms_tcpv6 {

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
	
	
	chain my_kvms_udpv6 {

		# invalid connections
		ct state invalid drop

		# loopback interface
		iif lo accept
		
		# established/related connections
		ct state {established, related} accept
		
		# open tcp ports: dns,dhcp,ntp
		iif eth3 tcp dport { 53,67,68,123 } accept
		
        }
         
            
	chain my_kvms_icmpv6 {

		iif eth3 icmp type { echo-request, echo-reply, destination-unreachable, packet-too-big, time-exceeded, parameter-problem, router-solicitation, router-advertisement, neighbor-solicitation, neighbor-advertisement, 141, 142, 151, 152, 153  } counter accept
		iif eth3 limit rate 3/second counter accept
    
        }
        
        
	chain my_wlan_tcpv6 {

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
	
	
	chain my_wlan_udpv6 {

		# invalid connections
		ct state invalid drop

		# loopback interface
		iif lo accept
		
		# established/related connections
		ct state {established, related} accept
		
		# open tcp ports: dns,dhcp,ntp
		iif wlan0 tcp dport { 53,67,68,123 } accept
		
        }
         
            
	chain my_wlan_icmpv6 {

		# invalid connections
		ct state invalid drop

		# loopback interface
		iif lo accept
		
		# established/related connections
		ct state {established, related} accept
		
		iif wlan0 icmp type { echo-request, echo-reply, destination-unreachable, packet-too-big, time-exceeded, parameter-problem, router-solicitation, router-advertisement, neighbor-solicitation, neighbor-advertisement, 141, 142, 151, 152, 153  } counter accept
		iif wlan0 limit rate 3/second counter accept
    
        }
	
	
	chain output { 
		type filter hook output priority 0; policy accept;

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


table ip6 nat {

	chain prerouting {
		type nat hook prerouting priority -150;
		
		}
	

	chain postrouting {
		type nat hook postrouting priority -150; policy accept;
		
		oif eth0 masquerade

		}

}
