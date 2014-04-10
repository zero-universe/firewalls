#!/bin/bash

#
# last modified 2014.04.05
# zero.universe@gmail.com
#

NFT=$(which nft)
MOD=$(which modprobe)

# load modules
#MODS='nf_tables nf_tables_ipv4 nf_tables_ipv6 nf_tables_inet nft_compat nft_counter nft_ct nft_exthdr nft_hash nft_limit nft_log nft_meta nft_nat nft_queue nft_rbtree nft_reject nft_reject_inet nft_chain_route_ipv6 nft_chain_nat_ipv6'
#for a in ${MODS}; do ${MOD} ${a};done

# flush all rules in filter
${NFT} flush table filter
#${NFT} flush table ip6 filter

# delete everything in filter
${NFT} delete chain filter my_tcpv4
${NFT} delete chain filter my_udpv4
${NFT} delete chain filter my_icmpv4
${NFT} delete chain filter output
${NFT} delete chain filter forward
${NFT} delete chain filter input
${NFT} delete table filter

#${NFT} delete chain ip6 filter my_tcpv6
#${NFT} delete chain ip6 filter my_udpv6
#${NFT} delete chain ip6 filter my_icmpv6
#${NFT} delete chain ip6 filter output
#${NFT} delete chain ip6 filter forward
#${NFT} delete chain ip6 filter input
#${NFT} delete table ip6 filter



exit 0
