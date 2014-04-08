firewalls
=========

iptables/nftables for routers, kvm hosts and standalone machines


in my free time i play with virtualized linux systems.
a firewall should not be missing in any scenario, so i am putting
some ip(6)tables rules together.

- and since 3.13 is out - nftables ;-)

it is just a hobby ... feel free to add some rules ...
suggestions are always welcome.


i am using archlinux with the mainline kernel,
so the loaded modules could not be available in your distro - yet ;-)



elly.kvm.router
-> it is for a kvm-host with one physical nic and two virtual nics


elly.router
-> is for a system with two physical nics


elly.standalone
-> kind of a "template" for starting from scratch

elly.soekris.better
-> firewall for a soekris-router 

nft.load.standalone.sh
-> load all nft modules and flush/delete rules/chains

nft.standalone.sh
-> nft firewall for a standalone host (desktop)

nft.standalone6.sh
-> same as above with ipv6

nft.aweb.sh
-> nft firewall for a webserver
