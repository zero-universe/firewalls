#!/bin/bash

IPT=$(which iptables)
SCTL=$(which systemctl)
IP=$(which ip)
RFKILL=$(which rfkill)

WORLD=enp0s31f6
WLAN=wlp2s0


case "$1" in
  start)

### activate forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo 1 > /proc/sys/net/ipv6/conf/all/forwarding

	${RFKILL} unblock wlan

	${IP} a a 192.168.22.1/24 dev ${WLAN}
	${IP} link set dev ${WLAN} up
	${IP} a s ${WLAN}
  
	${SCTL} start dnsmasq hostapd
	${SCTL} status dnsmasq hostapd
	${IPT} -t nat -F
	${IPT} -t nat -vnL
	${IPT} -vnL
	${IPT} -vnL FORWARD
	
### masque
	${IPT} -t nat -A POSTROUTING -o ${WORLD} -j MASQUERADE

	;;

  stop)

	${IP} a d 192.168.22.1/24 dev ${WLAN}
	${IP} link set dev ${WLAN} down
	${IP} a s ${WLAN}

	${SCTL} stop dnsmasq hostapd
	${SCTL} status dnsmasq hostapd
	${IPT} -t nat -F
	${IPT} -t nat -vnL
	${IPT} -vnL
	${IPT} -vnL FORWARD

### deactivate fwd
	echo 0 > /proc/sys/net/ipv4/ip_forward
    echo 0 > /proc/sys/net/ipv6/conf/all/forwarding

    ${RFKILL} block wlan

	;;

  *)
    echo "Fehlerhafter Aufruf"
    echo "Syntax: $0 {start|stop}"

    exit 1

    ;;

esac

exit 0
