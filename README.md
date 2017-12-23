# sedna
Linux c gtk tcp udp packet filtering firewall 


For the application to receive queued tcp or udp packets from the kernel iptables rules need to be added, for example to control incoming and outgoing udp packets from userspace application add the following iptables rules 

```
iptables -I OUTPUT -p udp  -j NFQUEUE -v
```
```
iptables -I INPUT -p udp  -j NFQUEUE -v
```

## Features ##

Application level firewall for blocking packets at network level includes support for filtering packets by protocol, process, domain, ip, port. 

When a process attempts to open a incoming or outgoing connection on the network, the application will display a connection alert, allowing the user to allow or block the connection.

<p>
<img src="/screenshot.png" />
</p>

## Build ##
lib requirements 
+ libnetfilter_queue
+ libnetfilter_conntrack

to compile
```
make
```
run application - requires admin permissions to run

```
./sedna
```
