#!/usr/bin/nft -f

#
# last modified 2016.04.20
# zero.universe@gmail.com
#

table ip6 filter {
	
	chain input	{ 
		type filter hook input priority 0; policy drop; 
		
		# invalid connections
		ct state invalid drop

		# established/related connections
		ct state {established, related} accept
		
		ip6 protocol tcp goto my_tcpv6
		ip6 protocol udp goto my_udpv6
		ip6 protocol icmpv6 goto my_icmpv6

		}
		
		
	chain my_tcpv6 {
		
		# bad tcp -> avoid network scanning:
        iif wlp2s0 tcp flags & (fin|syn) == (fin|syn) drop
        iif wlp2s0 tcp flags & (syn|rst) == (syn|rst) drop
        iif wlp2s0 tcp flags & (fin|syn|rst|psh|ack|urg) == 0 drop 
        iif wlp2s0 tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|psh|urg) drop
		
		# loopback interface
		iif lo accept

		# open tcp ports: sec
		iif wlp2s0 tcp dport { 23235 } counter accept

		# everything else
		#drop	
    
        }
	
	
	chain my_udpv6 {
		ct state {established, related} accept
        
		# loopback interface
		iif lo accept
    
        }
         
            
	chain my_icmpv6 {
		iif wlp2s0 ct state {established, related} accept
        
        # invalid connections
		iif wlp2s0 ct state invalid drop

		# loopback interface
		iif lo accept

		iif wlp2s0 ipv6-icmp type { echo-request, echo-reply, destination-unreachable, packet-too-big, time-exceeded, parameter-problem, router-solicitation, router-advertisement, neighbor-solicitation, neighbor-advertisement, 141, 142, 151, 152, 153  } accept
    
        }
	
	
	chain forward { 
		type filter hook forward priority 0; policy drop;
		}
	
	
	chain output { 
		type filter hook output priority 0; policy accept;
		}
		
}
