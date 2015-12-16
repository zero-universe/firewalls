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
        tcp flags & (fin|syn) == (fin|syn) drop
        tcp flags & (syn|rst) == (syn|rst) drop
        tcp flags & (fin|syn|rst|psh|ack|urg) < (fin) drop # == 0 would be better, not supported yet.
        tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|psh|urg) drop
		
		ct state {established, related} accept
        
        # invalid connections
		ct state invalid drop

		# loopback interface
		meta iif lo accept

		# open tcp ports: sshd (23235)
		meta iif ens3 tcp dport { 23235 } counter accept

		# everything else
		reject
    
        }
	
	
	chain my_udpv4 {
		ct state {established, related} accept
        
        # invalid connections
		ct state invalid drop

		# loopback interface
		meta iif lo accept

		# everything else
		reject
    
        }
         
            
	chain my_icmpv4 {
		ct state {established, related} accept
        
        # invalid connections
		ct state invalid drop

		# loopback interface
		meta iif lo accept

		meta iif ens3 icmp type { echo-request, echo-reply, destination-unreachable } counter accept
		#meta iif ens3 icmp type echo-request accept
		#meta iif ens3 icmp type echo-reply accept
		#meta iif ens3 icmp type destination-unreachable accept
		meta iif ens3 limit rate 10/second counter accept

		# everything else
		reject
    
        }
	
	
	chain forward { 
		type filter hook forward priority 0; 
		}
	
	
	chain output { 
		type filter hook output priority 0; 
		
		#ct state {new, established, related} counter accept
		
		#meta iif ens3 tcp dport { 22, 53 } counter accept
		#meta iif ens3 udp dport { 53 } counter accept
		#accept
		accept
		}
		
}
