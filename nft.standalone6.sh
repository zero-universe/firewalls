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


table ip6 filter {
	
	chain input	{ 
		type filter hook input priority 0; policy drop; 
		
		# invalid connections
		ct state invalid drop

		# established/related connections
		ct state {established, related} accept

		# loopback interface
		iif lo accept
		
		iif eth0 goto eth0_v6

		}
		
		
	chain eth0_v6 {
		
		# invalid connections
		ct state invalid drop
	
		# established/related connections
		ct state {established, related} accept
		
		# bad tcp -> avoid network scanning:
        #tcp flags & (fin|syn) == (fin|syn) drop
        #tcp flags & (syn|rst) == (syn|rst) drop
        #tcp flags & (fin|syn|rst|psh|ack|urg) == 0 drop 
        #tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|psh|urg) drop
		
		# loopback interface
		iif lo accept

		# open tcp ports: sec
		tcp dport { 22,23235 } counter accept

		# no ping floods:
        ip6 nexthdr icmpv6 limit rate 20/second accept

		# loopback interface
		iif lo accept

		icmpv6 type { echo-request, echo-reply, destination-unreachable, packet-too-big, time-exceeded, parameter-problem, 133, 134, 135, 136, 141, 142, 151, 152, 153  } accept
    
        }
	
	
	chain forward { 
		type filter hook forward priority 0; policy drop;
		}
	
	
	chain output { 
		type filter hook output priority 0; policy accept;
		
		# loopback interface
		#oif lo accept
		
		}
}
