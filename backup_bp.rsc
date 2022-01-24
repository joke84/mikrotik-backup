# jan/24/2022 20:51:23 by RouterOS 7.1.1
# software id = UHQL-KJ35
#
# model = RouterBOARD 750G r3
# serial number = 6F380860464A
/interface pptp-server
add name=pptp-mobil user=joke
/interface sstp-client
add connect-to=officevpn.rackforest.com disabled=no name=sstp-rackforest \
    user=kohl.jozsef
/interface bridge
add admin-mac=CC:2D:E0:08:89:56 auto-mac=no name=bridge
/interface ethernet
set [ find default-name=ether1 ] name=ether1-pppoe speed=100Mbps
set [ find default-name=ether2 ] speed=100Mbps
set [ find default-name=ether3 ] speed=100Mbps
set [ find default-name=ether4 ] speed=100Mbps
set [ find default-name=ether5 ] speed=100Mbps
/interface l2tp-client
add connect-to=officevpn.rackforest.com dial-on-demand=yes name=\
    l2tp-rackforest use-ipsec=yes user=kohl.jozsef
/interface pppoe-client
add add-default-route=yes default-route-distance=2 dial-on-demand=yes \
    disabled=no interface=ether1-pppoe name=Digi user=kohljozsef-v4g
/interface list
add comment=defconf name=WAN
add comment=defconf name=LAN
/interface lte apn
set [ find default=yes ] ip-type=ipv4
/interface wireless security-profiles
set [ find default=yes ] supplicant-identity=MikroTik
/ip ipsec profile
set [ find default=yes ] enc-algorithm=aes-256,aes-128,3des
add dh-group=modp2048 enc-algorithm=aes-256 name=profile_1 nat-traversal=no
add dh-group=modp1024 name=profile_2
add dh-group=modp2048 enc-algorithm=aes-256 name=profile_3 nat-traversal=no
add dh-group=modp1024 enc-algorithm=3des name=ipsecvpn
add dh-group=modp1536 enc-algorithm=aes-256 hash-algorithm=sha256 name=\
    vpn.kohl.hu-ike
add dh-group=modp2048 enc-algorithm=aes-256 hash-algorithm=sha256 name=\
    bp-bikal
add dh-group=modp2048 enc-algorithm=aes-256 hash-algorithm=sha256 name=\
    bp-kozar
/ip ipsec peer
add address=bikal.kohl.hu comment=bp-bikal disabled=yes name=bp-bikal \
    profile=bp-bikal
add address=91.146.163.185/32 comment=bp-kozar disabled=yes name=bp-kozar \
    profile=bp-kozar
/ip ipsec proposal
set [ find default=yes ] auth-algorithms=sha256,sha1 pfs-group=none
add enc-algorithms=3des name=ipsecvpn_proposals
add auth-algorithms=sha256 enc-algorithms=aes-256-cbc,aes-256-ctr,aes-256-gcm \
    lifetime=1h name=vpn.kohl.hu-esp pfs-group=modp1536
add name=kozar
add auth-algorithms=sha256 enc-algorithms=aes-256-cbc,aes-256-ctr,aes-256-gcm \
    name=bp-bikal
add auth-algorithms=sha256 enc-algorithms=aes-256-cbc,aes-256-ctr,aes-256-gcm \
    name=bp-kozar
/ip pool
add name=dhcp ranges=192.168.102.201-192.168.102.250
add name=vpn ranges=192.168.87.30-192.168.87.254
/ip dhcp-server
add address-pool=dhcp interface=bridge name=defconf
/ipv6 dhcp-server
add address-pool=digi6 disabled=yes interface=bridge name=dhcp_ipv6
/port
set 0 name=serial0
/ppp profile
add dns-server=1.1.1.1 local-address=192.168.5.2 name=ipsec_vpn use-ipv6=no
add change-tcp-mss=yes dns-server=1.1.1.1,8.8.8.8 local-address=192.168.6.1 \
    name=PPTP-Profile only-one=yes remote-address=192.168.6.2 use-encryption=\
    yes
set *FFFFFFFE local-address=192.168.89.1 remote-address=vpn
/interface l2tp-client
add connect-to=185.43.204.45 dial-on-demand=yes disabled=no name=\
    l2tp-vpn.kohl.hu profile=ipsec_vpn use-ipsec=yes user=mikrotik.bp
/routing bgp template
set default as=65530 disabled=no name=default output.network=bgp-networks
/routing ospf instance
add name=default-v2
add name=default-v3 version=3
/routing ospf area
add disabled=yes instance=default-v2 name=backbone-v2
add disabled=yes instance=default-v3 name=backbone-v3
/routing table
add fib name=rackforestmark
add fib name=test-table
/snmp community
set [ find default=yes ] addresses=185.43.204.45/32
add addresses=185.43.204.45/32 name=mikrotik read-access=no
/system logging action
add bsd-syslog=yes name=remotelog remote=185.43.204.45 syslog-facility=local0 \
    target=remote
/user group
set full policy="local,telnet,ssh,ftp,reboot,read,write,policy,test,winbox,pas\
    sword,web,sniff,sensitive,api,romon,dude,tikapp,rest-api"
add name=backup policy="ssh,read,policy,test,sensitive,!local,!telnet,!ftp,!re\
    boot,!write,!winbox,!password,!web,!sniff,!api,!romon,!dude,!tikapp,!rest-\
    api"
/interface bridge port
add bridge=bridge comment=defconf ingress-filtering=no interface=ether2
add bridge=bridge comment=defconf ingress-filtering=no interface=ether3
add bridge=bridge comment=defconf ingress-filtering=no interface=ether4
add bridge=bridge comment=defconf ingress-filtering=no interface=ether5
/ip neighbor discovery-settings
set discover-interface-list=LAN
/ip settings
set rp-filter=strict tcp-syncookies=yes
/ipv6 settings
set max-neighbor-entries=8192
/interface detect-internet
set detect-interface-list=all
/interface l2tp-server server
set enabled=yes use-ipsec=yes
/interface list member
add interface=bridge list=LAN
add interface=Digi list=WAN
/interface ovpn-server server
set certificate=server cipher=blowfish128,aes128,aes192,aes256 enabled=yes \
    require-client-certificate=yes
/interface pptp-server server
set authentication=chap,mschap1,mschap2 default-profile=PPTP-Profile enabled=\
    yes
/interface sstp-server server
set default-profile=default-encryption enabled=yes
/ip address
add address=192.168.102.1/24 interface=ether2 network=192.168.102.0
/ip cloud
set ddns-enabled=yes
/ip dhcp-server lease
add address=192.168.102.20 client-id=\
    ff:56:50:4d:98:0:2:0:0:ab:11:33:a2:48:9a:ce:8:37:e0 comment=HOMESERVER \
    mac-address=70:85:C2:3C:19:BD server=defconf
add address=192.168.102.70 client-id=1:94:9a:a9:5b:3b:25 comment=XBOX \
    mac-address=94:9A:A9:5B:3B:25 server=defconf
add address=192.168.102.200 client-id=1:50:c7:bf:9a:1a:a4 comment=TPLINK-AP \
    mac-address=50:C7:BF:9A:1A:A4 server=defconf
add address=192.168.102.92 client-id=1:a0:cc:2b:33:18:c8 comment="Kl\EDma" \
    mac-address=A0:CC:2B:33:18:C8 server=defconf
add address=192.168.102.90 client-id=1:28:39:5e:c0:14:81 comment=TV-LAN \
    mac-address=28:39:5E:C0:14:81 server=defconf
add address=192.168.102.95 client-id=1:9c:93:4e:39:48:52 comment=\
    "Xerox nyomat\F3" mac-address=9C:93:4E:39:48:52 server=defconf
add address=192.168.102.91 client-id=1:28:39:5e:2f:8e:7 comment=TV-WIFI \
    mac-address=28:39:5E:2F:8E:07 server=defconf
add address=192.168.102.96 comment="Nappali l\E1mpa" mac-address=\
    5C:E5:0C:B3:0F:04 server=defconf
add address=192.168.102.97 client-id=1:60:ab:67:fc:9d:18 comment=\
    "Joke telefon" mac-address=60:AB:67:FC:9D:18 server=defconf
add address=192.168.102.94 comment="Air Purifier" mac-address=\
    04:CF:8C:AD:AA:75 server=defconf
/ip dhcp-server network
add address=192.168.87.0/24 comment=vpn dns-server=192.168.89.1 gateway=\
    192.168.89.1 netmask=24
add address=192.168.102.0/24 comment=defconf dns-server=192.168.102.1 domain=\
    home.lan gateway=192.168.102.1 netmask=24 ntp-server=148.6.0.1
/ip dns
set allow-remote-requests=yes servers="1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4,2606:47\
    00:4700::1111,2606:4700:4700::1001,2001:4860:4860::8888,2001:4860:4860::88\
    44"
/ip dns static
add address=192.168.102.1 name=router.lan
add address=192.168.102.20 name=hs.lan
add cname=hs.lan name=tr.kohl.hu type=CNAME
add cname=hs.lan name=ha.kohl.hu type=CNAME
add address=192.168.5.1 name=vpn.kohl.hu
add cname=router.lan name=bp.kohl.hu type=CNAME
add address=185.43.204.45 name=bw.kohl.hu
add address=192.168.3.20 name=amiko.kohl.hu
add address=192.168.102.20 name=vw.kohl.hu
/ip firewall address-list
add address=185.43.204.0/26 comment=RF list=vpn-bikal-kozar
add address=kozar.kohl.hu comment=kozar list=vpn-bikal-kozar
add address=185.80.49.215 list=rackforest
add address=172.18.0.0/24 list=rackforest
add address=bikal.kohl.hu comment=bikal list=vpn-bikal-kozar
add address=6f380860464a.sn.mynetname.net list=WAN
add address=192.168.102.0/24 list=LAN
add address=192.168.102.20 list=hs
add address=192.168.5.1 list=VPN_server
add address=192.168.5.0/24 list=VPN_network
add address=192.168.3.0/24 list=Bikal_LAN
/ip firewall filter
add action=fasttrack-connection chain=forward comment=FastTrack \
    connection-mark=!ipsec connection-state=established,related hw-offload=\
    yes
add action=accept chain=input comment="accept established,related,untracked" \
    connection-state=established,related,untracked
add action=accept chain=input comment="ZABBIX SNMP" dst-port=161 protocol=udp \
    src-address-list=vpn-bikal-kozar
add action=accept chain=input comment=winbox dst-port=8291 protocol=tcp \
    src-address-list=vpn-bikal-kozar
add action=accept chain=input comment=winbox dst-port=2200 protocol=tcp \
    src-address-list=vpn-bikal-kozar
add action=accept chain=input comment=VPN dst-address-list=LAN in-interface=\
    l2tp-vpn.kohl.hu src-address-list=VPN_network
add action=accept chain=input comment=BIKAL_IPSEC dst-address-list=LAN \
    ipsec-policy=in,ipsec src-address-list=Bikal_LAN
add action=accept chain=input comment="allow IPsec NAT" dst-port=4500 \
    protocol=udp src-address-list=vpn-bikal-kozar
add action=accept chain=input comment="allow IPsec NAT" protocol=gre \
    src-address-list=vpn-bikal-kozar
add action=accept chain=input protocol=ipsec-esp src-address-list=\
    vpn-bikal-kozar
add action=accept chain=input comment="allow IKE" dst-port=500 protocol=udp \
    src-address-list=vpn-bikal-kozar src-port=500
add action=accept chain=input comment="allow l2tp" dst-port=1701 protocol=udp \
    src-address-list=vpn-bikal-kozar
add action=accept chain=input comment="allow pptp" dst-port=1723 protocol=tcp
add action=drop chain=forward dst-port=53 protocol=udp
add action=drop chain=input comment="Drop Invalid Input" connection-state=\
    invalid
add action=drop chain=input comment="Drop all not coming from LAN" \
    in-interface-list=!LAN
add action=accept chain=forward comment="accept in ipsec policy" \
    ipsec-policy=in,ipsec
add action=accept chain=forward comment="accept out ipsec policy" \
    ipsec-policy=out,ipsec
add action=accept chain=forward comment=\
    "accept established,related, untracked" connection-state=\
    established,related,untracked
add action=drop chain=forward comment="Drop invalid Forward" \
    connection-state=invalid
add action=drop chain=forward comment="Drop all from WAN not DSTNATed" \
    connection-nat-state=!dstnat connection-state=new in-interface-list=WAN
/ip firewall mangle
add action=mark-connection chain=prerouting comment=\
    "Mark connections for hairpin NAT" dst-address-list=WAN \
    new-connection-mark="Hairpin NAT" passthrough=yes src-address-list=LAN
add action=mark-connection chain=forward comment="Mark IPsec" ipsec-policy=\
    out,ipsec new-connection-mark=ipsec passthrough=yes
add action=mark-connection chain=forward comment="Mark IPsec" ipsec-policy=\
    in,ipsec new-connection-mark=ipsec passthrough=yes
/ip firewall nat
add action=masquerade chain=srcnat comment="Hairpin NAT" connection-mark=\
    "Hairpin NAT"
add action=dst-nat chain=dstnat comment="Hairpin NAT" dst-address-list=WAN \
    dst-address-type=local dst-port=8443 protocol=tcp src-address-list=LAN \
    to-addresses=192.168.102.20 to-ports=443
add action=accept chain=srcnat dst-address-list=VPN_network out-interface=\
    l2tp-vpn.kohl.hu src-address-list=LAN
add action=accept chain=dstnat dst-address-list=LAN src-address=\
    192.168.3.0/24
add action=accept chain=srcnat dst-address-list=LAN src-address-list=\
    VPN_server
add action=masquerade chain=srcnat comment="SSTP masquerade" out-interface=\
    sstp-rackforest
add action=masquerade chain=srcnat comment="WAN masquerade" \
    out-interface-list=WAN
add action=dst-nat chain=dstnat dst-address=84.236.96.160 dst-port=8443 log=\
    yes log-prefix=test- protocol=tcp to-addresses=192.168.102.20 to-ports=\
    443
add action=dst-nat chain=dstnat comment=homeserver-ssh dst-port=22 \
    in-interface-list=WAN protocol=tcp src-address-list=vpn-bikal-kozar \
    to-addresses=192.168.102.20 to-ports=22
add action=dst-nat chain=dstnat comment=homeserver-influxdb dst-port=8086 \
    in-interface-list=WAN protocol=tcp src-address-list=vpn-bikal-kozar \
    to-addresses=192.168.102.20 to-ports=8086
add action=dst-nat chain=dstnat comment=homeserver-esphome dst-port=6052 \
    in-interface-list=WAN protocol=tcp src-address-list=vpn-bikal-kozar \
    to-addresses=192.168.102.20 to-ports=6052
add action=dst-nat chain=dstnat comment=homeserver-node-exporter dst-port=\
    9100 in-interface-list=WAN protocol=tcp src-address-list=vpn-bikal-kozar \
    to-addresses=192.168.102.20 to-ports=9100
add action=dst-nat chain=dstnat comment=homeserver-ftp dst-port=21 \
    in-interface-list=WAN protocol=tcp src-address-list=vpn-bikal-kozar \
    to-addresses=192.168.102.20 to-ports=21
add action=dst-nat chain=dstnat comment=homeserver-zabbix dst-port=10050 \
    in-interface-list=WAN protocol=tcp src-address-list=vpn-bikal-kozar \
    to-addresses=192.168.102.20 to-ports=10050
add action=dst-nat chain=dstnat comment=qbittorrent dst-port=8999 \
    in-interface-list=WAN protocol=tcp to-addresses=192.168.102.20 to-ports=\
    8999
add action=dst-nat chain=dstnat comment=homeserver-qbittorrent-web dst-port=\
    8080 protocol=tcp src-address-list=vpn-bikal-kozar to-addresses=\
    192.168.102.20 to-ports=8080
add action=dst-nat chain=dstnat comment=plex dst-port=32400 \
    in-interface-list=WAN protocol=tcp to-addresses=192.168.102.20 to-ports=\
    32400
add action=dst-nat chain=dstnat comment=tvheadend dst-port=9981 \
    in-interface-list=WAN protocol=tcp to-addresses=192.168.102.201 to-ports=\
    9981
add action=dst-nat chain=dstnat comment=letsencrypt dst-port=80 \
    in-interface-list=WAN protocol=tcp to-addresses=192.168.102.20 to-ports=\
    80
add action=dst-nat chain=dstnat comment=letsencrypt disabled=yes dst-port=443 \
    in-interface-list=WAN protocol=tcp to-addresses=192.168.102.20 to-ports=\
    443
add action=dst-nat chain=dstnat comment=homeassistant dst-port=8123 \
    in-interface-list=WAN protocol=tcp src-address-list=vpn-bikal-kozar \
    to-addresses=192.168.102.20 to-ports=8123
add action=dst-nat chain=dstnat comment="remote desktop" disabled=yes \
    dst-port=3389 in-interface-list=WAN protocol=tcp src-address-list=\
    vpn-bikal-kozar to-addresses=192.168.102.191 to-ports=3389
/ip firewall service-port
set sip disabled=yes
/ip ipsec identity
add comment=bp-bikal peer=bp-bikal
add comment=bp-kozar peer=bp-kozar
/ip ipsec policy
set 0 dst-address=0.0.0.0/0 src-address=0.0.0.0/0
add comment=bp-bikal dst-address=192.168.3.0/24 level=unique peer=bp-bikal \
    proposal=bp-bikal src-address=192.168.102.0/24 tunnel=yes
add comment=bp-kozar disabled=yes dst-address=192.168.0.0/24 level=unique \
    peer=bp-kozar proposal=bp-kozar src-address=192.168.2.0/24 tunnel=yes
/ip route
add disabled=no dst-address=172.24.24.1/32 gateway=bridge
add comment=Rackforest disabled=no dst-address=192.168.11.0/24 gateway=\
    sstp-rackforest
add disabled=no dst-address=185.170.85.116/32 gateway=l2tp-vpn.kohl.hu
add comment=Bikal disabled=no dst-address=46.249.129.168/32 gateway=\
    sstp-rackforest
add comment=Rackforest disabled=no dst-address=192.168.250.0/24 gateway=\
    sstp-rackforest
add comment=Rackforest disabled=no dst-address=172.18.0.0/24 gateway=\
    sstp-rackforest
add disabled=no dst-address=193.91.69.83/32 gateway=sstp-rackforest
add comment=Rackforest disabled=no dst-address=192.168.105.0/24 gateway=\
    sstp-rackforest
add comment=Rackforest disabled=no dst-address=185.187.72.0/23 gateway=\
    sstp-rackforest
add comment=kastely disabled=no dst-address=46.249.158.206/32 gateway=\
    sstp-rackforest
add comment=Bikal disabled=no dst-address=192.168.3.0/24 gateway=bridge
add comment=Rackforest disabled=no dst-address=185.80.48.0/22 gateway=\
    sstp-rackforest
add comment=Rackforest disabled=no dst-address=192.168.1.0/24 gateway=\
    sstp-rackforest
add comment=Rackforest disabled=no dst-address=192.168.115.0/24 gateway=\
    sstp-rackforest
add comment=Rackforest disabled=no dst-address=193.39.12.0/22 gateway=\
    sstp-rackforest
add disabled=no dst-address=192.168.0.0/24 gateway=bridge
add comment=Rackforest disabled=no dst-address=92.119.120.0/22 gateway=\
    sstp-rackforest
add comment=Rackforest disabled=no dst-address=79.139.56.0/21 gateway=\
    sstp-rackforest
add comment=Rackforest disabled=no dst-address=192.168.230.0/24 gateway=\
    sstp-rackforest
add comment=Rackforest disabled=no dst-address=185.87.60.0/24 gateway=\
    sstp-rackforest
add comment=Rackforest disabled=no dst-address=194.176.123.0/24 gateway=\
    sstp-rackforest
add comment=Rackforest disabled=no dst-address=194.180.12.0/24 gateway=\
    sstp-rackforest
add comment=Rackforest disabled=no dst-address=194.180.16.0/24 gateway=\
    sstp-rackforest
add comment=Rackforest disabled=no dst-address=194.180.19.0/24 gateway=\
    sstp-rackforest
add comment=Rackforest disabled=no dst-address=10.208.109.0/24 gateway=\
    sstp-rackforest
add comment=Rackforest disabled=no dst-address=185.187.75.0/24 gateway=\
    sstp-rackforest
add comment=Rackforest disabled=no dst-address=185.187.74.0/25 gateway=\
    sstp-rackforest
add comment=Rackforest disabled=no dst-address=185.187.74.128/26 gateway=\
    sstp-rackforest
add comment=Rackforest disabled=no dst-address=185.187.74.224/27 gateway=\
    sstp-rackforest
add comment=Rackforest disabled=no dst-address=185.43.206.3/32 gateway=\
    sstp-rackforest
add comment=Rackforest disabled=no dst-address=185.43.206.4/32 gateway=\
    sstp-rackforest
add comment=Rackforest disabled=no dst-address=185.43.207.0/24 gateway=\
    sstp-rackforest
add comment=Rackforest disabled=no dst-address=79.172.213.188/32 gateway=\
    sstp-rackforest
add comment="olaf munkahely" disabled=yes dst-address=86.101.237.173/32 \
    gateway=sstp-rackforest
add comment="Lovi mikro" disabled=no dst-address=82.141.135.10/32 gateway=\
    sstp-rackforest
add comment="Rackforest - nem \E9rem el \EDgy irod\E1b\F3l semmit" disabled=\
    yes dst-address=185.43.204.0/27 gateway=sstp-rackforest
add comment=Rackforest disabled=no dst-address=185.43.204.64/26 gateway=\
    sstp-rackforest
add comment=Rackforest disabled=yes dst-address=185.43.204.40/29 gateway=\
    sstp-rackforest
add comment=Rackforest disabled=no dst-address=185.43.204.48/29 gateway=\
    sstp-rackforest
add comment=Rackforest disabled=no dst-address=185.43.204.56/29 gateway=\
    sstp-rackforest
add comment=Rackforest disabled=no dst-address=185.43.204.128/25 gateway=\
    sstp-rackforest
add comment=Rackforest disabled=no dst-address=185.43.204.33/32 gateway=\
    sstp-rackforest
add comment=Rackforest disabled=no dst-address=185.43.206.128/25 gateway=\
    sstp-rackforest
add comment=Rackforest disabled=no dst-address=195.228.55.78/32 gateway=\
    sstp-rackforest
add comment=Rackforest disabled=no dst-address=79.172.194.41/32 gateway=\
    sstp-rackforest
add comment=Rackforest disabled=no dst-address=185.43.204.16/28 gateway=\
    sstp-rackforest
add comment=Rackforest disabled=no dst-address=192.168.140.0/24 gateway=\
    sstp-rackforest
add comment=Rackforest disabled=no dst-address=185.43.204.7/32 gateway=\
    sstp-rackforest
add comment=Rackforest disabled=no dst-address=185.43.204.3/32 gateway=\
    sstp-rackforest
/ip service
set telnet disabled=yes
set ftp disabled=yes
set www disabled=yes
set ssh port=2200
set api disabled=yes
set api-ssl disabled=yes
/ip ssh
set forwarding-enabled=remote
/ip upnp
set allow-disable-external-interface=yes enabled=yes
/ip upnp interfaces
add interface=Digi type=external
add interface=bridge type=internal
/ipv6 address
add from-pool=digi6 interface=bridge
/ipv6 dhcp-client
add add-default-route=yes interface=Digi pool-name=digi6 request=\
    address,prefix use-peer-dns=no
/ipv6 firewall address-list
add address=::/128 comment="defconf: unspecified address" list=bad_ipv6
add address=::1/128 comment="defconf: lo" list=bad_ipv6
add address=fec0::/10 comment="defconf: site-local" list=bad_ipv6
add address=::ffff:0.0.0.0/96 comment="defconf: ipv4-mapped" list=bad_ipv6
add address=::/96 comment="defconf: ipv4 compat" list=bad_ipv6
add address=100::/64 comment="defconf: discard only " list=bad_ipv6
add address=2001:db8::/32 comment="defconf: documentation" list=bad_ipv6
add address=2001:10::/28 comment="defconf: ORCHID" list=bad_ipv6
add address=3ffe::/16 comment="defconf: 6bone" list=bad_ipv6
add address=::224.0.0.0/100 comment="defconf: other" list=bad_ipv6
add address=::127.0.0.0/104 comment="defconf: other" list=bad_ipv6
add address=::/104 comment="defconf: other" list=bad_ipv6
add address=::255.0.0.0/104 comment="defconf: other" list=bad_ipv6
/ipv6 firewall filter
add action=drop chain=input connection-state=invalid
add action=add-src-to-address-list address-list=blacklist \
    address-list-timeout=1d chain=input dst-port=22 in-interface-list=WAN \
    protocol=tcp
add action=add-src-to-address-list address-list=blacklist \
    address-list-timeout=1d chain=input dst-port=23 in-interface-list=WAN \
    protocol=tcp
add action=accept chain=input connection-state=established,related
add action=accept chain=input dst-port=546 protocol=udp
add action=accept chain=input protocol=icmpv6
add action=accept chain=input in-interface-list=LAN
add action=accept chain=drop
add action=drop chain=forward connection-state=invalid
add action=drop chain=forward in-interface-list=WAN src-address-list=\
    blacklist
add action=add-src-to-address-list address-list=blacklist \
    address-list-timeout=0s chain=forward dst-port=22 in-interface-list=WAN \
    protocol=tcp
add action=add-src-to-address-list address-list=blacklist \
    address-list-timeout=0s chain=forward dst-port=23 in-interface-list=WAN \
    protocol=tcp
add action=accept chain=forward connection-state=established,related
add action=accept chain=forward out-interface-list=WAN
add action=drop chain=forward
add action=accept chain=input comment="defconf: accept UDP traceroute" \
    disabled=yes port=33434-33534 protocol=udp
/ipv6 nd
set [ find default=yes ] managed-address-configuration=yes \
    other-configuration=yes
/ppp secret
add name=kohl.jozsef profile=PPTP-Profile service=pptp
/routing rule
add action=lookup-only-in-table disabled=no dst-address=0.0.0.0/0 \
    routing-mark=rackforestmark table=test-table
/snmp
set enabled=yes trap-generators="" trap-interfaces=all trap-version=2
/system clock
set time-zone-name=Europe/Budapest
/system logging
add disabled=yes prefix=ssh
add disabled=yes prefix=ipsec- topics=ipsec
add disabled=yes topics=ssh,!debug
add disabled=yes topics=debug,!dhcp,!snmp
add disabled=yes topics=ovpn,debug
add disabled=yes topics=ipsec,!packet
add disabled=yes prefix=sstp- topics=sstp
add disabled=yes topics=dhcp,debug
/system ntp client
set enabled=yes
/system ntp client servers
add address=148.6.0.1
add address=193.227.197.2
/system resource irq rps
set ether1-pppoe disabled=no
set ether2 disabled=no
set ether3 disabled=no
set ether4 disabled=no
set ether5 disabled=no
/system scheduler
add comment="PPPoE reconnect script schelduler" interval=1w name=\
    PPPoE_ujracsatlakozas on-event="/system script run pppoe_reconnect" \
    policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive \
    start-date=mar/30/2020 start-time=03:01:01
add comment="L2TP reconnect script schelduler" interval=1d name=\
    "L2TP reconnect" on-event="/system script run l2tp_reconnect" policy=\
    ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon \
    start-date=jul/29/2020 start-time=04:00:00
/system script
add dont-require-permissions=no name=ipsec-peer-update-bp-bikal owner=joke \
    policy=read,write source=":local peerid    \"bp-bikal\"\
    \n:local peerhost  \"66160619378d.sn.mynetname.net\"\
    \n:local peerip    [:resolve \$peerhost]\
    \n:local peeruid\
    \n:set peeruid     [/ip ipsec peer   find comment=\"\$peerid\" and address\
    !=\"\$peerip/32\"]\
    \n:local policyuid\
    \n:set policyuid   [/ip ipsec policy find comment=\"\$peerid\" and sa-dst-\
    address!=\"\$peerip\"]\
    \n:if (\$peeruid != \"\") do={\
    \n  /ip ipsec peer set \$peeruid address=\"\$peerip/32\"\
    \n  :log info \"Script ipsec-peer-update updated peer '\$peerid' with addr\
    ess '\$peerip'\"\
    \n}\
    \n:if (\$policyuid != \"\") do={\
    \n  /ip ipsec policy set \$policyuid sa-dst-address=\"\$peerip\"\
    \n  :log info \"Script ipsec-peer-update updated policy '\$peerid' with ad\
    dress '\$peerip'\"\
    \n}"
add dont-require-permissions=no name=pppoe_reconnect owner=admin policy=\
    ftp,reboot,read,write,policy,test,password,sniff,sensitive source=":log in\
    fo \"Digi off\"; \r\
    \n/interface pppoe-client disable Digi;\r\
    \n:delay 10 ; \r\
    \n:log info \"Digi on\"; \r\
    \n/interface pppoe-client enable Digi;\r\
    \n"
add dont-require-permissions=no name=l2tp_reconnect owner=joke policy=\
    ftp,reboot,read,write,policy,test,password,sniff,sensitive source=":log in\
    fo \"VPN off\"; \r\
    \n/interface l2tp-client disable l2tp-vpn.kohl.hu;\r\
    \n:delay 5 ; \r\
    \n:log info \"VPN on\"; \r\
    \n/interface l2tp-client enable l2tp-vpn.kohl.hu;\r\
    \n"
/tool bandwidth-server
set authenticate=no enabled=no
/tool mac-server
set allowed-interface-list=LAN
/tool mac-server mac-winbox
set allowed-interface-list=LAN
/tool sniffer
set filter-interface=*1B filter-ip-protocol=icmp
