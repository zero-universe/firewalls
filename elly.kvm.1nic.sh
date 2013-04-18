#!/bin/bash

# 2013.04.09
# zero.universe@gmail.com

########################### definitions ###########################

IPT=$(which iptables)
IPT6=$(which ip6tables)
WORLD="eth0"
VM0="virbr0"
VM1="virbr1"
VM2='virbr2'
MOD=$(which modprobe)
INTLAN="192.168.4.0/24"
VM0LAN="192.168.122.0/24"
#INTLAN6="fd54:fc9a:8b7a:765e::/64"



case "$1" in
  start)

  echo "Starte IP-Paketfilter"

########################### load modules ###########################

### iptables-Modul
    $MOD x_tables
    $MOD ip_tables
    $MOD ip6table_filter
    $MOD ip6_tables

### Connection-Tracking-Module
    $MOD nf_conntrack
    $MOD nf_conntrack_ipv6
    $MOD nf_conntrack_irc
    $MOD nf_conntrack_ftp

########################### proc-settings ###########################

### activate forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo 1 > /proc/sys/net/ipv6/conf/all/forwarding

### Max. 500/second (5/Jiffie)
    echo 10 > /proc/sys/net/ipv4/icmp_ratelimit
    echo 10 > /proc/sys/net/ipv6/icmp/ratelimit

### ram and ram-timing for IP-de/-fragmentation
    echo 262144 > /proc/sys/net/ipv4/ipfrag_high_thresh
    echo 196608 > /proc/sys/net/ipv4/ipfrag_low_thresh
    echo 30 > /proc/sys/net/ipv4/ipfrag_time
    
    echo 262144 > /proc/sys/net/ipv6/ip6frag_high_thresh
    echo 196608 > /proc/sys/net/ipv6/ip6frag_low_thresh
    echo 30 > /proc/sys/net/ipv6/ip6frag_time

### TCP-FIN-Timeout protection against DoS-attacks
    echo 30 > /proc/sys/net/ipv4/tcp_fin_timeout

### max 3 answers to a TCP-SYN
    echo 3 > /proc/sys/net/ipv4/tcp_retries1

### repeat TCP-packets max 15x
    echo 15 > /proc/sys/net/ipv4/tcp_retries2
    
### disable source routing
	echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route
	echo 0 > /proc/sys/net/ipv6/conf/all/accept_source_route
	
### ignore bogus icmp_errors
	echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses
	
### deactivate source redirects
	echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects
	echo 0 > /proc/sys/net/ipv6/conf/all/accept_redirects
	
### deactivate source route
	echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route
	echo 0 > /proc/sys/net/ipv6/conf/all/accept_source_route

########################### cleanup tables ###########################

    $IPT -F
    $IPT -t nat -F
    $IPT -t mangle -F
    $IPT -X
    $IPT -t nat -X
    $IPT -t mangle -X

    $IPT6 -F
    $IPT6 -t mangle -F
    $IPT6 -X
    $IPT6 -t mangle -X

########################### default policies ###########################

    $IPT -P INPUT DROP
    $IPT -P OUTPUT ACCEPT
    $IPT -P FORWARD DROP

    $IPT6 -P INPUT DROP
    $IPT6 -P OUTPUT ACCEPT
    $IPT6 -P FORWARD DROP

###################### allow loopback networking #######################

### MY_LOOPY Chain
    $IPT -N MY_LOOPYv4
    $IPT6 -N MY_LOOPYv6

### loopback traffic goes to MY_LOOPY
    $IPT -A INPUT -i lo -j MY_LOOPYv4
    $IPT6 -A INPUT -i lo -j MY_LOOPYv6
    
    $IPT -A MY_LOOPYv4 -i lo -j ACCEPT
    $IPT6 -A MY_LOOPYv6 -i lo -j ACCEPT
    
    # default policy of OUTPUT is ACCEPT
    #$IPT -A OUTPUT -o lo -j ACCEPT
    #$IPT6 -A OUTPUT -o lo -j ACCEPT

#----------------------------------------------------------------------#
    
########################### own tables ###########################

### MY_ICMP Chain
    $IPT -N MY_ICMP

### MY_ICMP fuellen
    $IPT -A INPUT -p icmp -j MY_ICMP

### MY_TCP
    $IPT -N MY_TCP

### MY_TCP fuellen
    $IPT -A INPUT -p tcp -j MY_TCP

### MY_UDP
    $IPT -N MY_UDP

### MY_UDP fuellen
    $IPT -A INPUT -p udp -j MY_UDP

### MY_ICMPv6 Chain
    $IPT6 -N MY_ICMPv6

### MY_ICMPv6 fuellen
    $IPT6 -A INPUT -p icmpv6 -j MY_ICMPv6

### MY_TCPv6
    $IPT6 -N MY_TCPv6

### MY_TCP fuellen
    $IPT6 -A INPUT -p tcp -j MY_TCPv6

### MY_UDP
    $IPT6 -N MY_UDPv6

### MY_UDP fuellen
    $IPT6 -A INPUT -p udp -j MY_UDPv6

### MY_DROP
#    $IPT -N MY_DROP

########################### drop invalid packets ###########################

	#$IPT -A INPUT -m conntrack --ctstate INVALID -j DROP
	$IPT -A MY_TCP -m conntrack --ctstate INVALID -j DROP

	#$IPT6 -A INPUT -m conntrack --ctstate INVALID -j DROP
	$IPT6 -A MY_TCPv6 -m conntrack --ctstate INVALID -j DROP

########################### log all invalid packets ###########################

### Alle verworfenen Pakete protokollieren
    #$IPT -A INPUT -m conntrack --ctstate INVALID -m limit --limit 7200/h -j LOG --log-prefix "INPUT INVALID "
    #$IPT -A OUTPUT -m conntrack --ctstate INVALID -m limit --limit 7200/h -j LOG --log-prefix "OUTPUT INVALID "
    #$IPT6 -A INPUT -m conntrack --ctstate INVALID -m limit --limit 7200/h -j LOG --log-prefix "INPUT INVALID "
    #$IPT6 -A OUTPUT -m conntrack --ctstate INVALID -m limit --limit 7200/h -j LOG --log-prefix "OUTPUT INVALID "

########################### allow vm-networking ###########################

    #$IPT -A INPUT -i $VM0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    #$IPT -A INPUT -i $VM1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    $IPT -A MY_TCP -i $VM0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    #$IPT -A MY_TCP -i $VM1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    #$IPT6 -A INPUT -i $VM0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    #$IPT6 -A INPUT -i $VM1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    $IPT6 -A MY_TCPv6 -i $VM0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    #$IPT6 -A MY_TCPv6 -i $VM1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

########################### own tables/rules ###########################


########################### ICMP Tables ###########################

### MY_ICMP
    $IPT -A MY_ICMP -p icmp --icmp-type destination-unreachable -m conntrack --ctstate RELATED -j ACCEPT
    $IPT -A MY_ICMP -p icmp --icmp-type fragmentation-needed -m conntrack --ctstate RELATED -j LOG --log-prefix "icmp-fragmentation-needed: "
    $IPT -A MY_ICMP -p icmp --icmp-type fragmentation-needed -m conntrack --ctstate RELATED -j ACCEPT
    $IPT -A MY_ICMP -p icmp --icmp-type echo-request -m limit --limit 80/minute -j ACCEPT
    $IPT -A MY_ICMP -p icmp --icmp-type echo-request -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
    $IPT -A MY_ICMP -p icmp --icmp-type echo-reply -m conntrack --ctstate ESTABLISHED,RELATED -j LOG --log-prefix "icmp-echo-reply: "
    $IPT -A MY_ICMP -p icmp --icmp-type echo-reply -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    
### connection tracking
    $IPT -A MY_ICMP -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

### standard policy    
    $IPT -A MY_ICMP -j DROP

### MY_ICMPv6
    $IPT6 -A MY_ICMPv6 -p icmpv6 --icmpv6-type destination-unreachable -m conntrack --ctstate RELATED -j ACCEPT
    $IPT6 -A MY_ICMPv6 -p icmpv6 --icmpv6-type packet-too-big -m conntrack --ctstate RELATED -j ACCEPT
    $IPT6 -A MY_ICMPv6 -p icmpv6 --icmpv6-type time-exceeded -m conntrack --ctstate RELATED -j ACCEPT
    $IPT6 -A MY_ICMPv6 -p icmpv6 --icmpv6-type parameter-problem -m conntrack --ctstate RELATED -j ACCEPT

    $IPT6 -A MY_ICMPv6 -p icmpv6 --icmpv6-type echo-request -m limit --limit 80/minute -j ACCEPT
    $IPT6 -A MY_ICMPv6 -p icmpv6 --icmpv6-type echo-reply -j ACCEPT

### router advertisements
    #$IPT6 -A MY_ICMPv6 -p icmpv6 --icmpv6-type router-solicitation -j ACCEPT
    #$IPT6 -A MY_ICMPv6 -p icmpv6 --icmpv6-type router-advertisement -j ACCEPT

### router neighbor advertisements
    #$IPT6 -A MY_ICMPv6 -p icmpv6 --icmpv6-type neighbor-solicitation -j ACCEPT
    #$IPT6 -A MY_ICMPv6 -p icmpv6 --icmpv6-type neighbor-advertisement -j ACCEPT

### mobile-ipv6
    #$IPT6 -A MY_ICMPv6 -p icmpv6 --icmpv6-type 144 -j ACCEPT
    #$IPT6 -A MY_ICMPv6 -p icmpv6 --icmpv6-type 146 -j ACCEPT

### Inverse Neighbor Discovery
    $IPT6 -A MY_ICMPv6 -p icmpv6 --icmpv6-type 141 -j ACCEPT
    $IPT6 -A MY_ICMPv6 -p icmpv6 --icmpv6-type 142 -j ACCEPT

### Multicast groups + multicast listener
    #$IPT6 -A MY_ICMPv6 -p icmpv6 --icmpv6-type 130 -j ACCEPT
    #$IPT6 -A MY_ICMPv6 -p icmpv6 --icmpv6-type 131 -j ACCEPT
    #$IPT6 -A MY_ICMPv6 -p icmpv6 --icmpv6-type 132 -j ACCEPT
    #$IPT6 -A MY_ICMPv6 -p icmpv6 --icmpv6-type 143 -j ACCEPT

### Send - Certification Path Soli./Advert.
    #$IPT6 -A MY_ICMPv6 -p icmpv6 --icmpv6-type 148 -j ACCEPT
    #$IPT6 -A MY_ICMPv6 -p icmpv6 --icmpv6-type 149 -j ACCEPT

### multicast router
    #$IPT6 -A MY_ICMPv6 -p icmpv6 --icmpv6-type 151 -j ACCEPT
    #$IPT6 -A MY_ICMPv6 -p icmpv6 --icmpv6-type 152 -j ACCEPT
    #$IPT6 -A MY_ICMPv6 -p icmpv6 --icmpv6-type 153 -j ACCEPT

### connection tracking
	$IPT6 -A MY_UDPv6 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
	
### standart policy	
    $IPT6 -A MY_ICMPv6 -j DROP

########################### forwarding + masquerading ##########################

### allow KVM forwarding
    $IPT -A FORWARD -i $VM0 -o $WORLD -j ACCEPT
    $IPT -A FORWARD -i $WORLD -o $VM0 -j ACCEPT
    $IPT6 -A FORWARD -i $VM0 -o $WORLD -j ACCEPT
    $IPT6 -A FORWARD -i $WORLD -o $VM0 -j ACCEPT

    $IPT -A FORWARD -i $VM0 -o $VM0 -j ACCEPT
    $IPT -A FORWARD -i $VM1 -o $VM1 -j ACCEPT
    $IPT -A FORWARD -i $VM0 -o $VM1 -j ACCEPT
    $IPT -A FORWARD -i $VM1 -o $VM0 -j ACCEPT

    $IPT6 -A FORWARD -i $VM0 -o $VM0 -j ACCEPT
    $IPT6 -A FORWARD -i $VM1 -o $VM1 -j ACCEPT
    $IPT6 -A FORWARD -i $VM0 -o $VM1 -j ACCEPT
    $IPT6 -A FORWARD -i $VM1 -o $VM0 -j ACCEPT

### forward the rest
    $IPT -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    $IPT6 -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

### masquerading
    $IPT -A FORWARD -o $WORLD -j ACCEPT
    $IPT -t nat -A PREROUTING -j ACCEPT
    $IPT -t nat -A POSTROUTING -o $WORLD -j MASQUERADE


########################### Connection-Tracking aktivieren ###########################

### all protocols!
	$IPT -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    $IPT -A MY_TCP -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    $IPT -A MY_UDP -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    
	$IPT6 -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    $IPT6 -A MY_TCPv6 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    $IPT6 -A MY_ICMPv6 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    #$IPT -A OUTPUT -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
    #$IPT6 -A OUTPUT -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT

#########################################################################
########################### start of services ###########################
#########################################################################




############################################################
########################### IPv4 ###########################


###
### MY_TCP
###

### Stealth Scans etc. DROPpen ###

### Keine Flags gesetzt
    $IPT -A MY_TCP -p tcp --tcp-flags ALL NONE -j DROP

### SYN und FIN gesetzt
    $IPT -A MY_TCP -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP

### SYN und RST gleichzeitig gesetzt
    $IPT -A MY_TCP -p tcp --tcp-flags SYN,RST SYN,RST -j DROP

### FIN und RST gleichzeitig gesetzt
    $IPT -A MY_TCP -p tcp --tcp-flags FIN,RST FIN,RST -j DROP

### FIN ohne ACK
    $IPT -A MY_TCP -p tcp --tcp-flags ACK,FIN FIN -j DROP

### PSH ohne ACK
    $IPT -A MY_TCP -p tcp --tcp-flags ACK,PSH PSH -j DROP

### URG ohne ACK
    $IPT -A MY_TCP -p tcp --tcp-flags ACK,URG URG -j DROP

### SSH
    #$IPT -A MY_TCP -i $WORLD -m conntrack --ctstate NEW -p tcp --dport 22 -j LOG --log-prefix "ssh-access: "
    $IPT -A MY_TCP -i $WORLD -m conntrack --ctstate NEW -p tcp --dport 22 -j ACCEPT

### HTTP+s
    $IPT -A MY_TCP -i $WORLD -m conntrack --ctstate NEW -p tcp --dport 443 -j LOG --log-prefix "web-access: "
    $IPT -A MY_TCP -i $WORLD -m conntrack --ctstate NEW -p tcp --dport 443 -j ACCEPT

### postgresql
    #$IPT -A MY_TCP -s $INTLAN -i $WORLD -m conntrack --ctstate NEW -p tcp --dport 5432 -j LOG --log-prefix "postgres-access: "
    #$IPT -A MY_TCP -s $INTLAN -i $WORLD -m conntrack --ctstate NEW -p tcp --dport 5432 -j ACCEPT

### mysql
    #$IPT -A MY_TCP -s $INTLAN -i $WORLD -m conntrack --ctstate NEW -p tcp --dport 3306 -j LOG --log-prefix "mysql-access: "
    $IPT -A MY_TCP -s $INTLAN -i $WORLD -m conntrack --ctstate NEW -p tcp --dport 3306 -j ACCEPT
    $IPT -A MY_TCP -s $VM0LAN -i $WORLD -m conntrack --ctstate NEW -p tcp --dport 3306 -j ACCEPT

### Transmission Torrent
	#$IPT -A MY_TCP -i $WORLD -m conntrack --ctstate NEW -p tcp --dport 9191 -j LOG --log-prefix "transmission-tcp: "
    #$IPT -A MY_TCP -i $WORLD -m conntrack --ctstate NEW -p tcp --dport 9191 -j ACCEPT

### IPSEC
    #$IPT -A MY_TCP -i $WORLD -p 50 -j ACCEPT
    #$IPT -A MY_TCP -i $WORLD -p 51 -j ACCEPT
    #$IPT -A MY_TCP -i $WORLD -m conntrack --ctstate NEW -p udp --dport 500 -j ACCEPT

### Skype
    #$IPT -A MY_TCP -i $WORLD -m conntrack --ctstate NEW -p tcp --dport 23103 -j ACCEPT

### drop rest
    $IPT -A MY_TCP -j DROP

#-------------------------------------------------------------------------------------------------------------------#

###
### MY_UDP
###

### Transmission Torrent
	#$IPT -A MY_UDP -i $WORLD -m conntrack --ctstate NEW -p udp --dport 6969 -j LOG --log-prefix "transmission-udp: "
    #$IPT -A MY_UDP -i $WORLD -m conntrack --ctstate NEW -p udp --dport 6969 -j ACCEPT

### OPENVPN_V2
    #$IPT -A MY_UDP -i $WORLD -m conntrack --ctstate NEW -p udp --dport 1194 -j LOG --log-prefix "openvpn-connection: "
    #$IPT -A MY_UDP -i $WORLD -m conntrack --ctstate NEW -p udp --dport 1194 -j ACCEPT

### Skype
	#$IPT -A MY_UDP -i $WORLD -m conntrack --ctstate NEW -p udp --dport 23103 -j ACCEPT

### drop rest
    $IPT -A MY_UDP -j DROP

############################################################
########################### IPv6 ###########################

###
### MY_TCPv6
###

### SSH
    #$IPT6 -A MY_TCPv6 -i $WORLD -m conntrack --ctstate NEW -p tcp --dport 22 -j LOG --log-prefix "ssh-access: "
    $IPT6 -A MY_TCPv6 -i $WORLD -m conntrack --ctstate NEW -p tcp --dport 22 -j ACCEPT

### postgresql
    #$IPT6 -A MY_TCPv6 -s $INTLAN6 -i $WORLD -m conntrack --ctstate NEW -p tcp --dport 5432 -j LOG --log-prefix "postgres-access: "
    #$IPT6 -A MY_TCPv6 -s $INTLAN6 -i $WORLD -m conntrack --ctstate NEW -p tcp --dport 5432 -j ACCEPT

### mysql
    #$IPT6 -A MY_TCPv6 -s $INTLAN6 -i $WORLD -m conntrack --ctstate NEW -p tcp --dport 3306 -j LOG --log-prefix "mysql-access: "
    #$IPT6 -A MY_TCPv6 -s $INTLAN6 -i $WORLD -m conntrack --ctstate NEW -p tcp --dport 3306 -j ACCEPT

### Transmission Torrent
	#$IPT6 -A MY_TCPv6 -i $WORLD -m conntrack --ctstate NEW -p tcp --dport 9191 -j LOG --log-prefix "transmission-tcp: "
    #$IPT6 -A MY_TCPv6 -i $WORLD -m conntrack --ctstate NEW -p tcp --dport 9191 -j ACCEPT

### IPSEC
    #$IPT6 -A MY_TCPv6 -i $WORLD -p 50 -j ACCEPT
    #$IPT6 -A MY_TCPv6 -i $WORLD -p 51 -j ACCEPT
    #$IPT6 -A MY_TCPv6 -i $WORLD -m conntrack --ctstate NEW -p udp --dport 500 -j ACCEPT

### Skype
    #$IPT6 -A MY_TCPv6 -i $WORLD -m conntrack --ctstate NEW -p tcp --dport 23103 -j ACCEPT

### drop rest
    $IPT6 -A MY_TCPv6 -j DROP

#-------------------------------------------------------------------------------------------------------------------#

###
### MY_UDPv6
###

### Transmission Torrent
	#$IPT6 -A MY_UDPv6 -i $WORLD -m conntrack --ctstate NEW -p udp --dport 6969 -j LOG --log-prefix "transmission-udp: "
    #$IPT6 -A MY_UDPv6 -i $WORLD -m conntrack --ctstate NEW -p udp --dport 6969 -j ACCEPT

### OPENVPN_V2
    #$IPT6 -A MY_UDPv6 -i $WORLD -m conntrack --ctstate NEW -p udp --dport 1194 -j LOG --log-prefix "openvpn-connection: "
    #$IPT6 -A MY_UDPv6 -i $WORLD -m conntrack --ctstate NEW -p udp --dport 1194 -j ACCEPT

### Skype
	#$IPT6 -A MY_UDPv6 -i $WORLD -m conntrack --ctstate NEW -p udp --dport 23103 -j ACCEPT

### drop rest
    $IPT6 -A MY_UDPv6 -j DROP
    
########################### IPv6 ###########################
############################################################


#######################################################################
########################### end of services ###########################
#######################################################################

	echo "firewall up and running ;-)"

  ;;


  stop)

  echo "Stoppe IP-Paketfilter"
### Tabelle flushen
    $IPT -F
    $IPT -t nat -F
    $IPT -t mangle -F
    $IPT -F MY_TCP
    $IPT -F MY_UDP
    $IPT -F MY_ICMP
    $IPT -X
    $IPT -t nat -X
    $IPT -t mangle -X

    $IPT6 -F
    $IPT6 -t mangle -F
    $IPT6 -F MY_TCPv6
    $IPT6 -F MY_UDPv6
    $IPT6 -F MY_ICMPv6
    $IPT6 -X
    $IPT6 -t mangle -X

### deactivate ip 4+6 forwarding
    echo 0 > /proc/sys/net/ipv4/ip_forward
    echo 0 > /proc/sys/net/ipv6/conf/all/forwarding

### IPv6 Default-Policies setzen
    $IPT -P INPUT ACCEPT
    $IPT -P OUTPUT ACCEPT
    $IPT -P FORWARD ACCEPT

    $IPT6 -P INPUT ACCEPT
    $IPT6 -P OUTPUT ACCEPT
    $IPT6 -P FORWARD ACCEPT

    echo "firewall stopped"

  ;;


   status)

    echo "Tabelle filter"
    $IPT -L -vn
    echo "Tabelle nat"
    $IPT -t nat -L -vn
    echo "Tabelle mangle"
    $IPT -t mangle -L -vn

    echo "Tabelle filter"
    $IPT6 -L -vn
    echo "Tabelle mangle"
    $IPT6 -t mangle -L -vn

   ;;

########################### usage of script ###########################

   *)
    echo "Fehlerhafter Aufruf"
    echo "Syntax: $0 {start|stop|status}"

    exit 1

    ;;

esac