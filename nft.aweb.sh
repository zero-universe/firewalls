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
		
		meta iif ens3 ip protocol tcp jump my_tcpv4
		meta iif ens3 ip protocol udp jump my_udpv4
		meta iif ens3 ip protocol icmp jump my_icmpv4

		}
		
		
	chain my_tcpv4 {
		
		# bad tcp -> avoid network scanning:
        #meta iif ens3 tcp flags & (fin|syn) == (fin|syn) drop
        #meta iif ens3 tcp flags & (syn|rst) == (syn|rst) drop
        #meta iif ens3 tcp flags & (fin|syn|rst|psh|ack|urg) < (fin) drop # == 0 would be better, not supported yet.
        #meta iif ens3 tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|psh|urg) drop
		tcp flags & (fin|syn) == (fin|syn) drop
		tcp flags & (syn|rst) == (syn|rst) drop
		tcp flags & (fin|syn|rst|psh|ack|urg) < (fin) drop # == 0 would be better, not supported yet.
		tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|psh|urg) drop
		
		#meta iif ens3 ct state {established, related} accept
		ct state {established, related} accept
        
        # invalid connections
		#meta iif ens3 ct state invalid drop
		ct state invalid drop

		# loopback interface
		meta iif lo accept

		# open tcp ports: sshd, web, mysql, postgres
		meta iif ens3 tcp dport { 22, 80, 443, 3306, 5432 } counter accept

		# everything else
		reject
    
        }
	
	
	chain my_udpv4 {
		ct state {established, related} accept
        
        # invalid connections
		#meta iif ens3 ct state invalid drop
		ct state invalid drop

		# loopback interface
		meta iif lo accept

		# everything else
		reject
		}
         
            
	chain my_icmpv4 {
		#meta iif ens3 ct state {established, related} accept
		ct state {established, related} accept
        
        # invalid connections
		#meta iif ens3 ct state invalid drop
		ct state invalid drop

		# loopback interface
		meta iif lo accept

		#meta iif ens3 icmp type { echo-request, echo-reply, destination-unreachable } accept
		icmp type { echo-request, echo-reply, destination-unreachable } counter accept
		#meta iif ens3 icmp type echo-request accept
		#meta iif ens3 icmp type echo-reply accept
		#meta iif ens3 icmp type destination-unreachable accept
		#meta iif ens3 limit rate 5/second counter accept

		# everything else
		reject
    
        }
	
	
	chain forward { 
		type filter hook forward priority 0; 
		counter drop
		}
	
	
	chain output { 
		type filter hook output priority 0; 
		
		#meta oif ens3 ct state { established, related } accept
		
		#meta oif ens3 dport { 22, 53 } counter accept
		#meta oif ens3 udp dport { 53 } counter accept
		accept
		#counter drop
		}
		
}
