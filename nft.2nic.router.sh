#!/usr/bin/nft -f

#
# last modified 2017.06.04
# zero.universe@gmail.com
#

set -o nounset
set -o errexit
#set -o noclobber
set -o noglob


define world = ens3
define lan = ens4

# nics:
#
# ens3 = world
# ens4 = lan

flush ruleset

table ip filter {
	
	chain input	{ 
		type filter hook input priority 0; policy drop; 

		# invalid connections
		ct state invalid drop

		# loopback interface
		iifname lo accept
		
		# established/related connections
		ct state {established, related} accept

		# incoming inet trafic
		iifname $world ip protocol tcp goto my_world_tcpv4
		iifname $world ip protocol udp goto my_world_udpv4
		iifname $world ip protocol icmp goto my_world_icmpv4
		
		iifname $lan ip protocol tcp goto my_lan_tcpv4
		iifname $lan ip protocol udp goto my_lan_udpv4
		iifname $lan ip protocol icmp goto my_lan_icmpv4

		}
		

	chain my_world_tcpv4 {
		
		# invalid connections
		#ct state invalid drop
		
		# loopback interface
		#iifname lo accept
		
		# established/related connections
		#ct state {established, related} accept
		
		# bad tcp -> avoid network scanning:
        #tcp flags & (fin|syn) == (fin|syn) drop
        #tcp flags & (syn|rst) == (syn|rst) drop
        #tcp flags & (fin|syn|rst|psh|ack|urg) == 0 drop
        #tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|psh|urg) drop
		
		# open tcp ports: ssh
		tcp dport ssh counter accept
		tcp dport ssh ct state new tcp flags & (syn | ack) == syn counter accept
		
        }
	
	
	chain my_world_udpv4 {

		# invalid connections
		#ct state invalid drop

		# loopback interface
		#iifname lo accept
		
		# established/related connections
		#ct state {established, related} accept

        }
         
            
	chain my_world_icmpv4 {

		# invalid connections
		#ct state invalid drop

		# loopback interface
		#iifname lo accept
		
		# established/related connections
		#ct state {established, related} accept
		
		icmp type { echo-request, echo-reply, destination-unreachable, parameter-problem } counter accept
		limit rate 10/second counter accept
    
        }
        
        
	chain my_lan_tcpv4 {
		
		# invalid connections
		#ct state invalid drop

		# loopback interface
		#iifname lo accept
		
		# established/related connections
		#ct state {established, related} accept
				
		# bad tcp -> avoid network scanning:
        #tcp flags & (fin|syn) == (fin|syn) drop
        #tcp flags & (syn|rst) == (syn|rst) drop
        #tcp flags & (fin|syn|rst|psh|ack|urg) == 0 drop
        #tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|psh|urg) drop

		# open tcp ports: ssh,dns,dhcp
		tcp dport { 22,53,67,68 } accept

        }
	
	
	chain my_lan_udpv4 {

		# invalid connections
		#ct state invalid drop

		# loopback interface
		#iif lo accept
		
		# established/related connections
		#ct state {established, related} accept

		# open tcp ports: dns,dhcp
		#iifname $lan tcp dport { 67,68 } accept
		tcp dport { 67,68 } accept
		
        }
         
            
	chain my_lan_icmpv4 {

		# invalid connections
		#ct state invalid drop

		# loopback interface
		#iif lo accept
		
		# established/related connections
		#ct state {established, related} accept
		
		iifname $lan icmp type { echo-request, echo-reply, destination-unreachable, parameter-problem } counter accept
		iifname $lan limit rate 10/second counter accept
		accept
    
        }
	
	
	chain output { 
		type filter hook output priority 0; policy drop;
		
		# invalid connections
		ct state invalid drop

		# loopback interface
		oif lo accept
		
		}
		
		
	chain forward { 
		type filter hook forward priority 0; policy drop;

		# invalid connections
		ct state invalid drop

		# loopback interface
		iifname lo accept
		
		# established/related connections
		ct state {established, related} accept
		
		iifname $world oifname $lan ct state {established, related} accept
		iifname $lan oifname $world ct state {established, related} accept

		#iifname $lan oifname $world tcp dport { 22,53,80,443 } counter accept
		#iifname $lan oifname $world udp dport { 53 } counter accept

		}
		
}



table nat {
	
	chain prerouting {
		type nat hook prerouting priority -150;
		
		}
	

	chain postrouting {
		type nat hook postrouting priority -150; policy accept;
		
		oifname $world masquerade
		
		# snat
		#ip saddr 192.168.199.0/24 oifname $world snat 192.168.199.108
		
		}

}
