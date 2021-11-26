#!/bin/bash

#
# last modified 2021.11.24
# zero.universe@gmail.com
#

set -o nounset
set -o errexit
#set -o noclobber
set -o noglob

#WORLD="enp5s0"
#MEDIALAN="br0"
#GUESTW="enp11s0"

NFT=$(which nft)
NFTRULES="/etc/firewall/nft.nelly.soekris"
NFTFLUSHED="/etc/firewall/nft_flushed"

############################ start ###################################

case "$1" in
  start)

############################ proc-settings ###########################

### activate forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo 1 > /proc/sys/net/ipv6/conf/all/forwarding

### Max. 500/second (5/Jiffie)
    echo 10 > /proc/sys/net/ipv4/icmp_ratelimit
    echo 10 > /proc/sys/net/ipv6/icmp/ratelimit

### ram and ram-timing for IP-de/-fragmentation
    #echo 262144 > /proc/sys/net/ipv4/ipfrag_high_thresh
    echo 196608 > /proc/sys/net/ipv4/ipfrag_low_thresh
    echo 30 > /proc/sys/net/ipv4/ipfrag_time
    
    #echo 262144 > /proc/sys/net/ipv6/ip6frag_high_thresh
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

### load ruleset
	${NFT} -f ${NFTRULES}
	
	;;

############################ stop ####################################

  stop)

  echo "stopping firewall"

### deactivate forwarding
    echo 0 > /proc/sys/net/ipv4/ip_forward
    echo 0 > /proc/sys/net/ipv6/conf/all/forwarding
    
### backup ruleset
	echo "flush ruleset" > ${NFTRULES}_bak_$(date -I)
	${NFT} list ruleset >> ${NFTRULES}_bak_$(date -I)
	
### flush ruleset
	${NFT} -f ${NFTFLUSHED}
	
	;;
	
############################ reload ##################################
	
  reload)

  echo "reloading firewall"

### backup ruleset
	echo "flush ruleset" > ${NFTRULES}_bak_$(date -I)
	${NFT} list ruleset >> ${NFTRULES}_bak_$(date -I)

### reload ruleset
	${NFT} -f ${NFTRULES}_bak_$(date -I)
	
	;;

############################ syntax ##################################

   *)
    echo "unknown argument"
    echo "syntax is: $0 {start|stop|reload}"

    exit 1

    ;;

esac

exit 0