#!/usr/bin/nft -f

#
# last modified 2017.06.04
# zero.universe@gmail.com
#

set -o nounset
set -o errexit
#set -o noclobber
set -o noglob


define world = enp5s0
define media = enp6s0
#define buero = enp10s0
define gwlan = enp11s0
define wlan = wlp13s0
#define int_ifs = { $int_if1, $int_if2 }
#filter input iifname $int_ifs accept

# nics:
#
# enp5s0 = internet
# enp6s0 = lan
# enp10s0 = buero
# enp11s0 = kvms
# wlp13s0 = wlan
# tun1 = ziont
# hipv6 =  TUNB6

table ip6 filter {
	
	chain input	{ 
		type filter hook input priority 0; policy drop; 

		# invalid connections
		ct state invalid drop

		# loopback interface
		iifname lo accept
		
		# established/related connections
		ct state {established, related} accept

		# incoming inet trafic
		iifname $world ip protocol tcp goto my_world_tcpv6
		iifname $world ip protocol udp goto my_world_udpv6
		iifname $world ip protocol icmpv6 goto my_world_icmpv6
		           
		iifname $lan ip protocol tcp goto my_lan_tcpv6
		iifname $lan ip protocol udp goto my_lan_udpv6
		iifname $lan ip protocol icmpv6 goto my_lan_icmpv6
		           
		iifname $buero ip protocol tcp goto my_gwlan_tcpv6
		iifname $buero ip protocol udp goto my_gwlan_udpv6
		iifname $buero ip protocol icmpv6 goto my_gwlan_icmpv6
		
		iifname $kvms ip protocol tcp goto my_kvms_tcpv6
		iifname $kvms ip protocol udp goto my_kvms_udpv6
		iifname $kvms ip protocol icmpv6 goto my_kvms_icmpv6
		
		iifname $wlan ip protocol tcp goto my_wlan_tcpv6
		iifname $wlan ip protocol udp goto my_wlan_udpv6
		iifname $wlan ip protocol icmpv6 goto my_wlan_icmpv6
		
		iifname tun1 ip protocol tcp goto my_ziont_tcpv6
		iifname tun1 ip protocol udp goto my_ziont_udpv6
		iifname tun1 ip protocol icmpv6 goto my_ziont_icmpv6
		
		iifname hipv6 ip protocol tcp goto my_hipv6_tcpv6
		iifname hipv6 ip protocol udp goto my_hipv6_udpv6
		iifname hipv6 ip protocol icmpv6 goto my_hipv6_icmpv6

		}
		
		
	chain my_world_tcpv6 {
		
		# invalid connections
		#ct state invalid drop

		# loopback interface
		#iifname lo accept
		
		# established/related connections
		#ct state {established, related} accept
		
		# bad tcp -> avoid network scanning:
		#tcp flags & (fin|syn) == (fin|syn) drop
		#tcp flags & (syn|rst) == (syn|rst) drop
		tcp flags & (fin|syn|rst|psh|ack|urg) == 0 drop 
		#tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|psh|urg) drop

		# open tcp ports: sec
		iifname $world tcp dport { 23235 } accept

        }
	
	
	chain my_world_udpv6 {

		# invalid connections
		#ct state invalid drop

		# loopback interface
		#iifname lo accept
		
		# established/related connections
		#ct state {established, related} accept
		
        }
         
            
	chain my_world_icmpv6 {

		# invalid connections
		#ct state invalid drop

		# loopback interface
		#iifname lo accept
		
		# established/related connections
		#ct state {established, related} accept

		iifname $world icmpv6 type { echo-request, echo-reply, destination-unreachable, packet-too-big, time-exceeded, parameter-problem, router-solicitation, router-advertisement, neighbor-solicitation, neighbor-advertisement, 141, 142, 151, 152, 153  } counter accept
		iifname $world limit rate 10/second counter accept
    
        }


	chain my_lan_tcpv6 {
	
		# invalid connections
		#ct state invalid drop

		# loopback interface
		#iifname lo accept
		
		# established/related connections
		#ct state {established, related} accept
		
		# bad tcp -> avoid network scanning:
		#tcp flags & (fin|syn) == (fin|syn) drop
		#tcp flags & (syn|rst) == (syn|rst) drop
		tcp flags & (fin|syn|rst|psh|ack|urg) == 0 drop 
		#tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|psh|urg) drop

		# open tcp ports: dns,dhcp,ntp,squid,tor,sec
		iifname $lan tcp dport { 53,67,68,123,3128,9060,23235 } accept

        }
	
	
	chain my_lan_udpv6 {

		# invalid connections
		#ct state invalid drop

		# loopback interface
		#iifname lo accept
		
		# established/related connections
		#ct state {established, related} accept
		
		# open tcp ports: dns,dhcp,ntp
		iifname $lan tcp dport { 53,67,68,123 } accept
		
        }
         
            
	chain my_lan_icmpv6 {

		# invalid connections
		#ct state invalid drop

		# loopback interface
		#iifname lo accept
		
		# established/related connections
		#ct state {established, related} accept
		
		iifname $lan icmpv6 type { echo-request, echo-reply, destination-unreachable, packet-too-big, time-exceeded, parameter-problem, router-solicitation, router-advertisement, neighbor-solicitation, neighbor-advertisement, 141, 142, 151, 152, 153  } counter accept
		iifname $lan limit rate 10/second counter accept
    
        }


	chain my_gwlan_tcpv6 {

		# invalid connections
		#ct state invalid drop

		# loopback interface
		#iifname lo accept
		
		# established/related connections
		#ct state {established, related} accept
				
		# bad tcp -> avoid network scanning:
		#tcp flags & (fin|syn) == (fin|syn) drop
		#tcp flags & (syn|rst) == (syn|rst) drop
		tcp flags & (fin|syn|rst|psh|ack|urg) == 0 drop 
		#tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|psh|urg) drop

		# open tcp ports: dns,dhcp,ntp,squid
		iifname $buero tcp dport { 53,67,68,123,3128 } accept

        }
	
	
	chain my_gwlan_udpv6 {

		# invalid connections
		#ct state invalid drop

		# loopback interface
		#iifname lo accept
		
		# established/related connections
		#ct state {established, related} accept
		
		# open tcp ports: dns,dhcp,ntp
		iifname $buero tcp dport { 53,67,68,123 } accept
		
        }
         
            
	chain my_gwlan_icmpv6 {

		# invalid connections
		#ct state invalid drop

		# loopback interface
		#iifname lo accept
		
		# established/related connections
		#ct state {established, related} accept
		
		iifname $buero icmpv6 type { echo-request, echo-reply, destination-unreachable, packet-too-big, time-exceeded, parameter-problem, router-solicitation, router-advertisement, neighbor-solicitation, neighbor-advertisement, 141, 142, 151, 152, 153  } counter accept
		iifname $buero limit rate 3/second counter accept
    
        }
        
        
	chain my_kvms_tcpv6 {

		# invalid connections
		#ct state invalid drop

		# loopback interface
		#iifname lo accept
		
		# established/related connections
		#ct state {established, related} accept
				
		# bad tcp -> avoid network scanning:
		#tcp flags & (fin|syn) == (fin|syn) drop
		#tcp flags & (syn|rst) == (syn|rst) drop
		tcp flags & (fin|syn|rst|psh|ack|urg) == 0 drop 
		#tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|psh|urg) drop

		# open tcp ports: dns,dhcp,ntp,squid
		iifname $kvms tcp dport { 53,67,68,123,3128 } accept

        }
	
	
	chain my_kvms_udpv6 {

		# invalid connections
		#ct state invalid drop

		# loopback interface
		#iifname lo accept
		
		# established/related connections
		#ct state {established, related} accept
		
		# open tcp ports: dns,dhcp,ntp
		iifname $kvms tcp dport { 53,67,68,123 } accept
		
        }
         
            
	chain my_kvms_icmpv6 {

		iifname $kvms icmpv6 type { echo-request, echo-reply, destination-unreachable, packet-too-big, time-exceeded, parameter-problem, router-solicitation, router-advertisement, neighbor-solicitation, neighbor-advertisement, 141, 142, 151, 152, 153  } counter accept
		iifname $kvms limit rate 3/second counter accept
    
        }
        
        
	chain my_wlan_tcpv6 {

		# invalid connections
		#ct state invalid drop

		# loopback interface
		#iifname lo accept
		
		# established/related connections
		#ct state {established, related} accept
				
		# bad tcp -> avoid network scanning:
		#tcp flags & (fin|syn) == (fin|syn) drop
		#tcp flags & (syn|rst) == (syn|rst) drop
		tcp flags & (fin|syn|rst|psh|ack|urg) == 0 drop 
		#tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|psh|urg) drop

		# open tcp ports: dns,dhcp,ntp,squid,tor,sec
		iifname $wlan tcp dport { 53,67,68,123,3128,9061,23235 } accept

        }
	
	
	chain my_wlan_udpv6 {

		# invalid connections
		#ct state invalid drop

		# loopback interface
		#iifname lo accept
		
		# established/related connections
		#ct state {established, related} accept
		
		# open tcp ports: dns,dhcp,ntp
		iifname $wlan tcp dport { 53,67,68,123 } accept
		
        }
         
            
	chain my_wlan_icmpv6 {

		# invalid connections
		#ct state invalid drop

		# loopback interface
		#iifname lo accept
		
		# established/related connections
		#ct state {established, related} accept
		
		iifname $wlan icmpv6 type { echo-request, echo-reply, destination-unreachable, packet-too-big, time-exceeded, parameter-problem, router-solicitation, router-advertisement, neighbor-solicitation, neighbor-advertisement, 141, 142, 151, 152, 153  } counter accept
		iifname $wlan limit rate 3/second counter accept
    
        }
	
	
	chain output { 
		type filter hook output priority 0; policy accept;

		}
		
		
	chain forward { 
		type filter hook forward priority 0; policy drop;

		# invalid connections
		ct state invalid drop

		#ct state {established, related} accept

		iifname $lan oifname $buero accept
		iifname $lan oifname $kvms accept
		iifname $lan oifname $wlan accept
		iifname $lan oifname tun1 accept
		
		iifname $wlan oifname $lan accept
		iifname $wlan oifname $kvms accept
		iifname $wlan oifname tun1 accept
		
		iifname tun1 oifname $lan accept
		iifname tun1 oifname $wlan accept
		
		}
		
}


table ip6 nat {

	chain prerouting {
		type nat hook prerouting priority -150;
		
		}
	

	chain postrouting {
		type nat hook postrouting priority -150; policy accept;
		
		oifname $world masquerade
		oifname hipv6 masquerade

		}

}
