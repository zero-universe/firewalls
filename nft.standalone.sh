#!/usr/bin/nft -f

#
# last modified 2017.06.04
# zero.universe@gmail.com
#

set -o nounset
set -o errexit
#set -o noclobber
set -o noglob


#define int_if1 = eth0
#define int_if2 = eth1
#define int_ifs = { $int_if1, $int_if2 }
#filter input iif $int_ifs accept


table ip filter {
	
	chain input	{ 
		type filter hook input priority 0; policy drop;

	    # invalid connections
		ct state invalid drop
	
		# loopback interface
		iif lo accept
	
		# established/related connections
		ct state {established, related} accept
		
		iif eth0 ip protocol tcp goto my_tcpv4
		iif eth0 ip protocol udp goto my_udpv4
		iif eth0 ip protocol icmp goto my_icmpv4

		}
		
		
	chain my_tcpv4 {

		# invalid connections
		ct state invalid drop
	
		# established/related connections
		ct state {established, related} accept
		
		# bad tcp -> avoid network scanning:
        #tcp flags & (fin|syn) == (fin|syn) drop
        #tcp flags & (syn|rst) == (syn|rst) drop
        tcp flags & (fin|syn|rst|psh|ack|urg)  == 0 drop
        #tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|psh|urg) drop
		
       	# loopback interface
		iif lo accept

		# open tcp ports: http,https,sec
		tcp dport { 22,80,443,23235 } counter accept
    
        }
	
	
	chain my_udpv4 {
		
		# invalid connections
		ct state invalid drop
	
		# established/related connections
		ct state {established, related} accept

   		# loopback interface
		iif lo accept
    
        }
         
            
	chain my_icmpv4 {
		
		# invalid connections
		ct state invalid drop
	
		# established/related connections
		ct state {established, related} accept
        
		# loopback interface
		iifname lo accept

		iif eth0 icmp type { echo-request, echo-reply, destination-unreachable } counter accept
		iif eth0 limit rate 10/second counter accept

        }
	
	
	chain forward { 
		type filter hook forward priority 0; policy drop;
		
		# loopback interface
		iif lo accept
		oif lo accept
		
		}
	
	
	chain output { 
		type filter hook output priority 0; policy accept;
		
		# loopback interface
		oif lo accept

		}
		
}


#table ip nat {
#	
#	chain prerouting {
#		type nat hook prerouting priority -150;
#
#		#iifname eth0 tcp dport 22 redirect to 2222
#			
#		}
#
#	chain postrouting {
#		type nat hook postrouting priority -150;
#			
#		}
#}