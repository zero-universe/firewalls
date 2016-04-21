#!/bin/bash

#
# last modified 2014.09.25
# zero.universe@gmail.com
#

NFT=$(which nft)
MOD=$(which modprobe)

# load modules
MODS='nf_tables nf_tables_ipv4 nf_tables_ipv6 nf_tables_inet nft_compat nft_counter nft_ct nft_exthdr nft_hash nft_limit nft_log nft_meta nft_nat nft_queue nft_rbtree nft_reject nft_reject_inet nft_chain_route_ipv6 nft_chain_nat_ipv6'
for a in ${MODS}; do ${MOD} ${a};done



############################ proc-settings #############################

### activate forwarding
    echo 0 > /proc/sys/net/ipv4/ip_forward
    echo 0 > /proc/sys/net/ipv6/conf/all/forwarding

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


############################ proc-settings #############################



# flush all rules in filter
${NFT} flush table filter
${NFT} flush table ip6 filter
${NFT} flush table nat
${NFT} flush table ip6 nat



# delete everything in filter

# ipv4
${NFT} delete chain filter my_world_tcpv4
${NFT} delete chain filter my_world_udpv4
${NFT} delete chain filter my_world_icmpv4
${NFT} delete chain filter my_tcpv4
${NFT} delete chain filter my_udpv4
${NFT} delete chain filter my_icmpv4
${NFT} delete chain filter output
${NFT} delete chain filter forward
${NFT} delete chain filter input
${NFT} delete table filter

# ipv6
${NFT} delete chain ip6 filter my_world_tcpv6
${NFT} delete chain ip6 filter my_world_udpv6
${NFT} delete chain ip6 filter my_world_icmpv6
${NFT} delete chain ip6 filter my_tcpv6
${NFT} delete chain ip6 filter my_udpv6
${NFT} delete chain ip6 filter my_icmpv6
${NFT} delete chain ip6 filter output
${NFT} delete chain ip6 filter forward
${NFT} delete chain ip6 filter input
${NFT} delete table ip6 filter

# delete everything in nat
${NFT} delete chain nat prerouting
${NFT} delete chain nat postrouting
${NFT} delete table nat

exit 0
