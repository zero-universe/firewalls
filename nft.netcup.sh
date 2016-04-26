#!/usr/bin/nft -f

#
# last modified 2016.04.21
# zero.universe@gmail.com
#

table filter {
	
	chain input	{ 
		type filter hook input priority 0; policy drop;

	    # invalid connections
		ct state invalid drop
	
		# established/related connections
		ct state {established, related} accept
		
		ip protocol tcp goto my_tcpv4
		ip protocol udp goto my_udpv4
		ip protocol icmp goto my_icmpv4

		}
		
		
	chain my_tcpv4 {
		
		# bad tcp -> avoid network scanning:
        tcp flags & (fin|syn) == (fin|syn) drop
        tcp flags & (syn|rst) == (syn|rst) drop
        tcp flags & (fin|syn|rst|psh|ack|urg)  == 0 drop
        tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|psh|urg) drop
		
       	# loopback interface
		iif lo accept

		# open tcp ports
		iif ens3 tcp dport { 22,25,80,143,443,587,993,5222,23235 } counter accept
    
        }
	
	
	chain my_udpv4 {
		
		ct state {established, related} accept

   		# loopback interface
		meta iif lo accept
    
        }
         
            
	chain my_icmpv4 {
		
		ct state {established, related} accept
        
		# loopback interface
		iif lo accept

		iif ens3 icmp type { echo-request, echo-reply, destination-unreachable } counter accept
		iif ens3 limit rate 10/second counter accept

        }
	
	
	chain forward { 
		type filter hook forward priority 0; policy drop;
		}
	
	
	chain output { 
		type filter hook output priority 0; policy accept;

		}
		
}




table nat {
	
        chain prerouting {
			
			type nat hook prerouting priority -150;

			counter
			iif ens3 tcp dport 22 redirect to 2222
			
			}

        chain postrouting {
			
			type nat hook postrouting priority -150;
			
			}
}