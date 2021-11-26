#! /usr/bin/nft -f

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
#define gwlan = wlp14s0
#define int_ifs = { $world $media $buero $kvms $wlan $gwlan }
#filter input iif $int_ifs accept

# nics:
#
# enp5s0 = internet
# enp6s0 = media
# enp10s0 = buero
# enp11s0 = kvms
# wlp13s0 = wlan
# wlp14s0 = gwlan
# tun1 = ziont

flush ruleset

table ip filter {
	
	chain input	{ 
		type filter hook input priority 0; policy drop; 
		
		# invalid connections
		ct state invalid drop
		
		# loopback interface
		iif lo accept
		
		# established/related connections
		ct state {established, related} accept
		
		# incoming inet trafic
		iif $world ip protocol tcp goto my_world_tcpv4
		iif $world ip protocol udp goto my_world_udpv4
		iif $world ip protocol icmp goto my_world_icmpv4
		
		iif $media ip protocol tcp goto my_media_tcpv4
		iif $media ip protocol udp goto my_media_udpv4
		iif $media ip protocol icmp goto my_media_icmpv4
		
		iif $buero ip protocol tcp goto my_buero_tcpv4
		iif $buero ip protocol udp goto my_buero_udpv4
		iif $buero ip protocol icmp goto my_buero_icmpv4
		
		iif $kvms ip protocol tcp goto my_kvms_tcpv4
		iif $kvms ip protocol udp goto my_kvms_udpv4
		iif $kvms ip protocol icmp goto my_kvms_icmpv4
		
		iif $wlan ip protocol tcp goto my_wlan_tcpv4
		iif $wlan ip protocol udp goto my_wlan_udpv4
		iif $wlan ip protocol icmp goto my_wlan_icmpv4
			
		iif $gwlan ip protocol tcp goto my_gwlan_tcpv4
		iif $gwlan ip protocol udp goto my_gwlan_udpv4
		iif $gwlan ip protocol icmp goto my_gwlan_icmpv4
		
		iif tun1 ip protocol tcp goto my_ziont_tcpv4
		iif tun1 ip protocol udp goto my_ziont_udpv4
		iif tun1 ip protocol icmp goto my_ziont_icmpv4

		}
		
		
	chain my_world_tcpv4 {
		
		# invalid connections
		#ct state invalid drop

		# loopback interface
		#iif lo accept
		
		# established/related connections
		#ct state {established, related} accept
		
		# bad tcp -> avoid network scanning:
		#tcp flags & (fin|syn) == (fin|syn) drop
		#tcp flags & (syn|rst) == (syn|rst) drop
		tcp flags & (fin|syn|rst|psh|ack|urg) == 0 drop
		#tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|psh|urg) drop

		# open tcp ports: openvpn, sshd
		iif $world tcp dport { 1195, 23235 } accept

		}
	
	
	chain my_world_udpv4 {

		}
		 
			
	chain my_world_icmpv4 {

		# invalid connections
		#ct state invalid drop

		# loopback interface
		#iif lo accept
		
		# established/related connections
		#ct state {established, related} accept

		iif $world icmp type { echo-request, echo-reply, destination-unreachable, parameter-problem } counter accept
		iif $world limit rate 10/second counter accept
	
		}


	chain my_media_tcpv4 {
	
		# invalid connections
		#ct state invalid drop

		# loopback interface
		#iif lo accept
		
		# established/related connections
		#ct state {established, related} accept
		
		# bad tcp -> avoid network scanning:
		#tcp flags & (fin|syn) == (fin|syn) drop
		#tcp flags & (syn|rst) == (syn|rst) drop
		tcp flags & (fin|syn|rst|psh|ack|urg) == 0 drop
		#tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|psh|urg) drop

		# open tcp ports: dns,dhcp,ntp,squid,tor,sec
		iif $media tcp dport { 53,67,68,123,3128,9060,23235 } accept

		}
	
	
	chain my_media_udpv4 {

		# invalid connections
		#ct state invalid drop

		# loopback interface
		#iif lo accept
		
		# established/related connections
		#ct state {established, related} accept
		
		# open tcp ports: dns,dhcp,ntp
		iif $media tcp dport { 53,67,68,123 } accept
		
		}
		 
			
	chain my_media_icmpv4 {

		# invalid connections
		#ct state invalid drop

		# loopback interface
		#iif lo accept
		
		# established/related connections
		#ct state {established, related} accept
		
		iif $media icmp type { echo-request, echo-reply, destination-unreachable, parameter-problem } counter accept
		iif $media limit rate 10/second counter accept
	
		}


	chain my_buero_tcpv4 {

		# invalid connections
		#ct state invalid drop

		# loopback interface
		#iif lo accept
		
		# established/related connections
		#ct state {established, related} accept
				
		# bad tcp -> avoid network scanning:
		#tcp flags & (fin|syn) == (fin|syn) drop
		#tcp flags & (syn|rst) == (syn|rst) drop
		tcp flags & (fin|syn|rst|psh|ack|urg) == 0 drop
		#tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|psh|urg) drop

		# open tcp ports: dns,dhcp,ntp,squid
		iif $buero tcp dport { 53,67,68,123,3128,23235 } accept

		}
	
	
	chain my_buero_udpv4 {

		# invalid connections
		#ct state invalid drop

		# loopback interface
		#iif lo accept
		
		# established/related connections
		#ct state {established, related} accept
		
		# open tcp ports: dns,dhcp,ntp
		iif $buero tcp dport { 53,67,68,123 } accept
		
		}
		 
			
	chain my_buero_icmpv4 {

		# invalid connections
		#ct state invalid drop

		# loopback interface
		#iif lo accept
		
		# established/related connections
		#ct state {established, related} accept
		
		iif $buero icmp type { echo-request, echo-reply, destination-unreachable, parameter-problem } counter accept
		iif $buero limit rate 5/second counter accept
	
		}
		
		
	chain my_kvms_tcpv4 {

		# invalid connections
		#ct state invalid drop

		# loopback interface
		#iif lo accept
		
		# established/related connections
		#ct state {established, related} accept
				
		# bad tcp -> avoid network scanning:
		#tcp flags & (fin|syn) == (fin|syn) drop
		#tcp flags & (syn|rst) == (syn|rst) drop
		tcp flags & (fin|syn|rst|psh|ack|urg) == 0 drop
		#tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|psh|urg) drop

		# open tcp ports: dns,dhcp,ntp,squid
		iif $kvms tcp dport { 53,67,68,123,3128 } accept

		}
	
	
	chain my_kvms_udpv4 {

		# invalid connections
		#ct state invalid drop

		# loopback interface
		#iif lo accept
		
		# established/related connections
		#ct state {established, related} accept
		
		# open tcp ports: dns,dhcp,ntp
		iif $kvms tcp dport { 53,67,68,123 } accept
		
		}
		 
			
	chain my_kvms_icmpv4 {

		iif $kvms icmp type { echo-request, echo-reply, destination-unreachable, parameter-problem } counter accept
		iif $kvms limit rate 3/second counter accept
	
		}
		
		
	chain my_wlan_tcpv4 {

		# invalid connections
		#ct state invalid drop

		# loopback interface
		#iif lo accept
		
		# established/related connections
		#ct state {established, related} accept
				
		# bad tcp -> avoid network scanning:
		#tcp flags & (fin|syn) == (fin|syn) drop
		#tcp flags & (syn|rst) == (syn|rst) drop
		tcp flags & (fin|syn|rst|psh|ack|urg) == 0 drop
		#tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|psh|urg) drop

		# open tcp ports: dns,dhcp,ntp,squid,tor,sec
		iif $wlan tcp dport { 53,67,68,123,3128,9061,23235 } accept

		}
	
	
	chain my_wlan_udpv4 {

		# invalid connections
		#ct state invalid drop

		# loopback interface
		#iif lo accept
		
		# established/related connections
		#ct state {established, related} accept
		
		# open tcp ports: dns,dhcp,ntp
		iif $wlan tcp dport { 53,67,68,123 } accept
		
		}
		 
			
	chain my_wlan_icmpv4 {

		# invalid connections
		#ct state invalid drop

		# loopback interface
		#iif lo accept
		
		# established/related connections
		#ct state {established, related} accept
		
		iif $wlan icmp type { echo-request, echo-reply, destination-unreachable, parameter-problem } counter accept
		iif $wlan limit rate 3/second counter accept
	
		}
	
	
	chain my_gwlan_tcpv4 {

		# invalid connections
		#ct state invalid drop

		# loopback interface
		#iif lo accept
		
		# established/related connections
		#ct state {established, related} accept
				
		# bad tcp -> avoid network scanning:
		#tcp flags & (fin|syn) == (fin|syn) drop
		#tcp flags & (syn|rst) == (syn|rst) drop
		tcp flags & (fin|syn|rst|psh|ack|urg) == 0 drop
		#tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|psh|urg) drop

		# open tcp ports: dns,dhcp,ntp,squid,tor,sec
		iif $gwlan tcp dport { 53,67,68,123,3128,9061 } accept

		}
	
	
	chain my_gwlan_udpv4 {

		# invalid connections
		#ct state invalid drop

		# loopback interface
		#iif lo accept
		
		# established/related connections
		#ct state {established, related} accept
		
		# open tcp ports: dns,dhcp,ntp
		iif $gwlan tcp dport { 53,67,68,123 } accept
		
		}
		 
			
	chain my_gwlan_icmpv4 {

		# invalid connections
		#ct state invalid drop

		# loopback interface
		#iif lo accept
		
		# established/related connections
		#ct state {established, related} accept
		
		iif $gwlan icmp type { echo-request, echo-reply, destination-unreachable, parameter-problem } counter accept
		iif $gwlan limit rate 3/second counter accept
	
		}

			
	chain output { 
		type filter hook output priority 0; policy accept;

		# invalid connections
		#ct state invalid drop

		# loopback interface
		oif lo accept
		
		}
		
		
	chain forward { 
		type filter hook forward priority 0; policy drop;

		# invalid connections
		ct state invalid drop

		ct state {established, related} accept

		#iif $media oif $buero accept
		#iif $media oif $kvms accept
		#iif $media oif $wlan accept
		#iif $media oif tun1 accept
		
		#iif $media oif $world accept
		
		iif $buero oif $media accept
		iif $wlan oif $media accept
		iif tun1 oif $world accept
		iif $buero oif $world accept
		
		}
		
}



table ip nat {

	chain prerouting {
		type nat hook prerouting priority -150;
					
		}
				

	chain postrouting {
		type nat hook postrouting priority 100; policy accept;
		
		oif $world masquerade
		
		# snat
		#ip saddr 192.168.77.0/24 oif $world snat 1.2.3.4
		#ip saddr 192.168.88.0/24 oif $world snat 1.2.3.4
		#ip saddr 192.168.99.0/24 oif $world snat 1.2.3.4
					
		}

}
