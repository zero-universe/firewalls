#!/bin/bash

# source:
# https://wiki.nftables.org/wiki-nftables/index.php/Moving_from_iptables_to_nftables

set -o nounset
set -o errexit
#set -o noclobber
set -o noglob


IPTS4=$(which iptables-save)
IPTS6=$(which ip6tables-save)
IPTRANS=$(which iptables-restore-translate)
IPTRANS6=$(which ip6tables-restore-translate)

IPRULES="elly4_ipt"
IP6RULES="elly6_ipt"
NFTRULES="elly4_nft"
NFT6RULES="elly6_nft"

WORKING_DIR="/home/nft"

mkdir ${WORKING_DIR} 
cd ${WORKING_DIR}

###########  save iptables 4 and 6 rules ##########

echo "saving v4 rules to ${IPRULES}"
${IPTS4} > ${IPRULES}

echo "saving v6 rules to ${IP6RULES}"
${IPTS6} > ${IP6RULES}



###########  translate rules to nft ##########

echo "translating file ${IPRULES} to ${NFTRULES}"
${IPTRANS} -f ${IPRULES} > ${NFTRULES}

echo "translating file ${IP6RULES} to ${NFT6RULES}"
${IPTRANS} -f ${IP6RULES} > ${NFT6RULES}


echo "done"

ls -lah

exit 0