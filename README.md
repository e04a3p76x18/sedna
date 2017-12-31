# sedna
Linux c gtk packet filtering firewall 

currently support filtering ip4 level tcp and udp packets 

## Features ##

application level firewall for blocking packets at network level includes support for filtering packets by protocol, process, domain, ip, port. 

control all outgoing and incoming connections when a process attempts to open a network connection the application will display a connection alert allowing the user to allow or block the request.

uses netfilter to get queued packets from Linux kernel  

<p>
<img src="/screenshot.png" />
</p>
example rule - firefox process always block all tcp outgoing connections to api.googleapi.com on all port numbers

## Build ##
requirements

libnetfilter_queue

libnetfilter_conntrack

gtk3

download all files

compile code
```
make
```
For the application to receive queued tcp or udp packets from the kernel iptables rules need to be added for example to control incoming and outgoing udp packets from userspace application add the following iptables rules

```
iptables -I OUTPUT -p udp  -j NFQUEUE -v
```
```
iptables -I INPUT -p udp  -j NFQUEUE -v
```

run application - requires admin permissions to run

```
./sedna
```
