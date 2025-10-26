# General information

This code was not written by me. It has been updated to support newer kernel version than the ones mentioned.

Current version: tgk-log-2.5
Based on: tgk-log-2.4

# Original README from the developer.

*NOTICE*

If you are planning to run tgk-log on a masquerading(NAT) gateway, then
make sure you are running a kernel from the 2.2.x series, otherwise the
source ip of the packets will be wrong.

tgk-log has been compiled and somewhat tested under:
-libc5.4.4x (to compile under libc5 edit the makefile and remove the # 
in front of -DLIBC5 under CFLAGS)
-glibc2.1.x
-glibc2.0.7x

Compilers have ranged from gcc 2.7.2.3 to pgcc 2.91.60.

*EOF NOTICE*

Simple explanation of the config file(/etc/tgk-log):

###### resolve on/off			
Toggles if tgk-log should resolve the ip's it logs into hostnames 
default is off

###### log-udp/tcp/icmp on/off
You should be able to figure out what this is on your own.

###### udp/icmp/tcplogfile /var/log/tgk.log
*required* Pretty obvious what this is isn't it? 

###### promisc on/off
Toggles if tgk-log should put the NIC into promiscous mode. If you want
to be able to log traffic going over the internal network only you have to
set this to on.
  
###### device ethX
The device tgk-log should bind to. for example eth0, eth1 etc etc.

###### log_all yes/no
Wheter to log everything that passes by the "device" interface, if set to no
the following options will apply. Else no check's will be done on
source&destination, this is probably what you want if not using a ip-masq
firewall 
    
**THE FOLLOWING OPTION ONLY APPLIES IF log_all IS no**

###### log_intranet on/off
Toggles if trafic that has a source and destination inside the internal
network should be logged, default is off

###### log_outside_to_intranet on/off
Whetver tgk-log should log connections made from hosts outside the intranet
to the internal net. If you'r using ip-masquerading this serves no purpose
as you probably understand, but if activated on a masquerading gateway it
will give you double logs of the connection. internal:port->external:port 
and external:port->internal:port.

###### net_class 8/16/24
What netmask the internal network has, 16 or 24, i.e class A,B or C.
default is 24

###### intranet <internal network adress>
Internal network adress, *required* if log_all is NO. for example 192.168.0.0
or 172.16.0.0

<fire@c5.hakker.com>
http://c5.hakker.com  
