#!/usr/bin/nft -f

#
# last modified 2014.04.05
# zero.universe@gmail.com
#

table ip6 filter {
	
	chain input	{ 
		type filter hook input priority 0; 
		
		# established/related connections
		ct state {established, related} accept
		
		ip6 protocol tcp jump my_tcpv6
		ip6 protocol udp jump my_udpv6
		ip6 protocol icmpv6 jump my_icmpv6

		}
		
		
	chain my_tcpv6 {
		
		# bad tcp -> avoid network scanning:
        meta iif wlp2s0 tcp flags & (fin|syn) == (fin|syn) drop
        meta iif wlp2s0 tcp flags & (syn|rst) == (syn|rst) drop
        meta iif wlp2s0 tcp flags & (fin|syn|rst|psh|ack|urg) < (fin) drop # == 0 would be better, not supported yet.
        meta iif wlp2s0 tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|psh|urg) drop
		
		meta iif wlp2s0 ct state {established, related} accept
        
        # invalid connections
		meta iif wlp2s0 ct state invalid drop

		# loopback interface
		meta iif lo accept

		# open tcp ports: sshd (22)
		meta iif wlp2s0 tcp dport { 22 } counter accept

		# everything else
		reject
    
        }
	
	
	chain my_udpv6 {
		ct state {established, related} accept
        
        # invalid connections
		meta iif wlp2s0 ct state invalid drop

		# loopback interface
		meta iif lo accept

		# everything else
		reject
    
        }
         
            
	chain my_icmpv6 {
		meta iif wlp2s0 ct state {established, related} accept
        
        # invalid connections
		meta iif wlp2s0 ct state invalid drop

		# loopback interface
		meta iif lo accept

		meta iif wlp2s0 ipv6-icmp type { echo-request, echo-reply, destination-unreachable, packet-too-big, time-exceeded, parameter-problem, router-solicitation, router-advertisement, neighbor-solicitation, neighbor-advertisement, 141, 142, 151, 152, 153  } accept
		#meta iif wlp2s0 icmpv6 type echo-request accept
		#meta iif wlp2s0 icmpv6 type echo-reply accept
		#meta iif wlp2s0 icmpv6 type destination-unreachable accept
		#meta iif wlp2s0 limit rate 5/second counter accept
		#meta iif wlp2s0 ip6 nexthdr icmpv6 accept

		# everything else
		reject
    
        }
	
	
	chain forward { 
		type filter hook forward priority 0; 
		}
	
	
	chain output { 
		type filter hook output priority 0; 
		accept
		}
		
}