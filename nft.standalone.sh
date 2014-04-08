#!/usr/bin/nft -f

#
# last modified 2014.04.05
# zero.universe@gmail.com
#

table filter {
	
	chain input	{ 
		type filter hook input priority 0; 
		
		# established/related connections
		ct state {established, related} accept
		
		ip protocol tcp jump my_tcpv4
		ip protocol udp jump my_udpv4
		ip protocol icmp jump my_icmpv4

		}
		
		
	chain my_tcpv4 {
		
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
		meta iif wlp2s0 tcp dport { 22 } accept

		# everything else
		reject
    
        }
	
	
	chain my_udpv4 {
		ct state {established, related} accept
        
        # invalid connections
		meta iif wlp2s0 ct state invalid drop

		# loopback interface
		meta iif lo accept

		# everything else
		reject
    
        }
         
            
	chain my_icmpv4 {
		meta iif wlp2s0 ct state {established, related} accept
        
        # invalid connections
		meta iif wlp2s0 ct state invalid drop

		# loopback interface
		meta iif lo accept

		meta iif wlp2s0 icmp type { echo-request, echo-reply, destination-unreachable } accept
		#meta iif wlp2s0 icmp type echo-request accept
		#meta iif wlp2s0 icmp type echo-reply accept
		#meta iif wlp2s0 icmp type destination-unreachable accept
		#meta iif wlp2s0 limit rate 5/second counter accept

		# everything else
		reject
    
        }
	
	
	chain forward { 
		type filter hook forward priority 0; 
		}
	
	
	chain output { 
		type filter hook output priority 0; 
		
		meta iif wlp2s0 ct state {new, established, related} accept
		
		meta iif wlp2s0 tcp dport { 22, 53 } counter accept
		meta iif wlp2s0 udp dport { 53 } counter accept
		#accept
		counter drop
		}
		
}
