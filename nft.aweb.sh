#!/usr/bin/nft -f

#
# last modified 2016.04.20
# zero.universe@gmail.com
#

table filter {
	
	chain input	{
		
		type filter hook input priority 0; policy drop; 
		
		# established/related connections
		ct state {established, related} accept
		
		# invalid connections
		ct state invalid drop

		meta iif ens3 ip protocol tcp goto my_tcpv4
		meta iif ens3 ip protocol udp goto my_udpv4
		meta iif ens3 ip protocol icmp goto my_icmpv4

		}
		
		
	chain my_tcpv4 {

		# established/related connections
		ct state {established, related} accept
		
		# invalid connections
		ct state invalid drop
				
		# bad tcp -> avoid network scanning:
        tcp flags & (fin|syn) == (fin|syn) drop
        tcp flags & (syn|rst) == (syn|rst) drop
        tcp flags & (fin|syn|rst|psh|ack|urg)  == 0 drop
        tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|psh|urg) drop
		
		# loopback interface
		iif lo accept

		# open tcp ports: sshd, web
		iif ens3 tcp dport { 23235, 80, 443 } counter accept

        }
	
	
	chain my_udpv4 {

		# established/related connections
		ct state {established, related} accept
		
		# invalid connections
		ct state invalid drop
		
		# loopback interface
		iif lo accept

		}
         
            
	chain my_icmpv4 {

		# established/related connections
		ct state {established, related} accept
		
		# invalid connections
		ct state invalid drop
				
		#ct state {established, related} accept
        
		# loopback interface
		iif lo accept

		iif ens3 icmp type { echo-request, echo-reply, destination-unreachable } counter accept
		iif ens3 limit rate 10/second counter accept
    
        }
	
	
	chain forward {		
		type filter hook forward priority 0; policy drop;

		# established/related connections
		ct state {established, related} accept
		
		# invalid connections
		ct state invalid drop
		
		}
	
	
	chain output {
		
		type filter hook output priority 0; policy accept;
		
		counter

		}
		
}


table nat {
	
	chain prerouting {
		type nat hook prerouting priority -150;

		iif ens3 tcp dport 22 redirect to 2222
			
		}

	chain postrouting {
		type nat hook postrouting priority -150;
			
		}
}
