#!/bin/sh
CONF="/etc/tgk-log.conf"
clear
echo "TGK-log configuration shellscript."
echo
echo "If you want some more detailed explanations about"
echo "what these options do, read the README file."
echo
until [ "$RESOLVE" = "y" ] || [ "$RESOLVE" = "Y" ] || 
      [ "$RESOLVE" = "n" ] || [ "$RESOLVE" = "N" ]; do
 echo -n "Do you want to resolve the ips being logged?(y/N): "
 read RESOLVE
 if [ "$RESOLVE" = "" ]; then
  RESOLVE=N
 fi;
done

until [ "$LOG_TCP" = "y" ] || [ "$LOG_TCP" = "Y" ] || 
      [ "$LOG_TCP" = "n" ] || [ "$LOG_TCP" = "N" ]; do
 echo -n "Do you want to log TCP traffic?(Y/n): "
 read LOG_TCP
 if [ "$LOG_TCP" = "" ]; then
  LOG_TCP=Y
 fi;
done

if [ "$LOG_TCP" = "y" ] || [ "$LOG_TCP" = "Y" ]; then
 until [ "$TCP_LOGFILE" != "" ]; do
  echo -n "Which logfile should be used for TCP traffic?: "
  read TCP_LOGFILE
 done
else 
 TCP_LOGFILE="/dev/null"
fi

until [ "$LOG_UDP" = "y" ] || [ "$LOG_UDP" = "Y" ] || 
      [ "$LOG_UDP" = "n" ] || [ "$LOG_UDP" = "N" ]; do
 echo -n "Do you want to log UDP traffic?(Y/n): "
 read LOG_UDP
 if [ "$LOG_UDP" = "" ]; then
  LOG_UDP=Y
 fi;
done

if [ "$LOG_UDP" = "y" ] || [ "$LOG_UDP" = "Y" ]; then
 until [ "$UDP_LOGFILE" != "" ]; do
  echo -n "Which logfile should be used for UDP traffic?: "
  read UDP_LOGFILE
 done
else 
 UDP_LOGFILE="/dev/null"
fi

until [ "$LOG_ICMP" = "y" ] || [ "$LOG_ICMP" = "Y" ] || 
      [ "$LOG_ICMP" = "n" ] || [ "$LOG_ICMP" = "N" ]; do
 echo -n "Do you want to log ICMP traffic?(Y/n): "
 read LOG_ICMP
 if [ "$LOG_ICMP" = "" ]; then
  LOG_ICMP=Y
 fi;
done

if [ "$LOG_ICMP" = "y" ] || [ "$LOG_ICMP" = "Y" ]; then
 until [ "$ICMP_LOGFILE" != "" ]; do
  echo -n "Which logfile should be used for ICMP traffic?: "
  read ICMP_LOGFILE
 done
else 
 ICMP_LOGFILE="/dev/null"
fi 

until [ "$DEVICE" != "" ]; do
 echo -n "Which device should be used by tgk-log?: "
 read DEVICE
done

until [ "$PROMISC" = "y" ] || [ "$PROMISC" = "Y" ] || 
      [ "$PROMISC" = "n" ] || [ "$PROMISC" = "N" ]; do
 echo -n "Do you want the device to be put in promiscous mode?(y/N): "
 read PROMISC
 if [ "$PROMISC" = "" ]; then
  PROMISC=N
 fi;
done

until [ "$LOG_ALL" = "y" ] || [ "$LOG_ALL" = "Y" ] || 
      [ "$LOG_ALL" = "n" ] || [ "$LOG_ALL" = "N" ]; do
 echo
 echo "*** ATTENTION ***"
 echo "If you choose no here you will be asked some more detailed questions"
 echo "about just what you want to log"
 echo
 echo -n "Do you want to log all traffic?(Y/n): "
 read LOG_ALL
 if [ "$LOG_ALL" = "" ]; then
  LOG_ALL=Y
 fi;
done

if [ "$LOG_ALL" = "n" ] || [ "$LOG_ALL" = "N" ]; then
 
 until [ "$LOG_INTRANET" = "y" ] || [ "$LOG_INTRANET" = "Y" ] || 
       [ "$LOG_INTRANET" = "n" ] || [ "$LOG_INTRANET" = "N" ]; do
  echo -n "Log traffic going on the internal network only?(y/N): "
  read LOG_INTRANET
  if [ "$LOG_INTRANET" = "" ]; then
   LOG_INTRANET=N
  fi;
 done
 
 until [ "$LOG_OUT2IN" = "y" ] || [ "$LOG_OUT2IN" = "Y" ] || 
       [ "$LOG_OUT2IN" = "n" ] || [ "$LOG_OUT2IN" = "N" ]; do
  echo -n "Log traffic going from internet to internal network?(y/N): "
  read LOG_OUT2IN
  if [ "$LOG_OUT2IN" = "" ]; then
   LOG_OUT2IN=N
  fi;
 done
 
 until [ "$NC" = "16" ] || [ "$NC" = "24" ]; do
  echo
  echo "**8 is a class A network. 16 is a class B network. 24 is a class C network.**"
  echo -n "Networkclass?(8/16/24): "
  read NC
 done
 
 until [ "$INTRANET" != "" ]; do
  echo -n "Internal network(for example 192.168.0.0)?: "
  read INTRANET
 done
fi

echo
echo "Entered values: "
echo "Resolve ips: $RESOLVE"
echo "Log TCP: $LOG_TCP"
echo "TCP logfile: $TCP_LOGFILE"
echo "Log UDP: $LOG_UDP"
echo "UDP logfile: $UDP_LOGFILE"
echo "Log ICMP: $LOG_ICMP"
echo "ICMP logfile: $ICMP_LOGFILE"
echo "Ethernet device: $DEVICE"
echo "Promiscous mode: $PROMISC"
echo "Log everything: $LOG_ALL"
if [ "$LOG_ALL" = "n" ] || [ "$LOG_ALL" = "N" ]; then
 echo "Log intranet: $LOG_INTRANET"
 echo "Log outside->inside traffic: $LOG_OUT2IN"
 echo "Network class: $NC"
 echo "Network: $INTRANET"
fi
echo
until [ "$WRITE" = "n" ] || [ "$WRITE" = "N" ] ||
      [ "$WRITE" = "y" ] || [ "$WRITE" = "Y" ]; do
 echo -n "Write $CONF?(y/n): "
 read WRITE
 if [ "$WRITE" = "y" ] || [ "$WRITE" = "Y" ]; then

  cat /dev/null > $CONF
  if [ "$RESOLVE" = "y" ] || [ "$RESOLVE" = "Y" ]; then 
   echo "resolve on" >> $CONF
  else
   echo "resolve off" >> $CONF
  fi;
  if [ "$LOG_TCP" = "y" ] || [ "$LOG_TCP" = "Y" ]; then 
   echo "log-tcp on" >> $CONF
  else
   echo "log-tcp off" >> $CONF
  fi;
  echo "tcplogfile $TCP_LOGFILE" >> $CONF
  if [ "$LOG_UDP" = "y" ] || [ "$LOG_UDP" = "Y" ]; then 
   echo "log-udp on" >> $CONF
  else
   echo "log-udp off" >> $CONF
  fi;
  echo "udplogfile $UDP_LOGFILE" >> $CONF
  if [ "$LOG_ICMP" = "y" ] || [ "$LOG_ICMP" = "Y" ]; then 
   echo "log-icmp on" >> $CONF
  else
   echo "log-icmp off" >> $CONF
  fi;
  echo "icmplogfile $ICMP_LOGFILE" >> $CONF
  echo "device $DEVICE" >> $CONF
  if [ "$PROMISC" = "y" ] || [ "$PROMISC" = "Y" ]; then 
   echo "promisc on" >> $CONF
  else
   echo "promisc off" >> $CONF
  fi;
  if [ "$LOG_ALL" = "y" ] || [ "$LOG_ALL" = "Y" ]; then 
   echo "log_all yes" >> $CONF
  else
   echo "log_all off" >> $CONF
  fi;
  echo "#" >> $CONF
  echo "# **THE FOLLOWING OPTIONS ONLY MATTER IF \"log_all\" IS \"no\"**" >> $CONF
  echo "#" >> $CONF
  if [ "$LOG_INTRANET" = "y" ] || [ "$LOG_INTRANET" = "Y" ]; then 
   echo "log_intranet on" >> $CONF
  else
   echo "log_intranet off" >> $CONF
  fi;
  if [ "$LOG_OUT2IN" = "y" ] || [ "$LOG_OUT2IN" = "Y" ]; then 
   echo "log_outside_to_intranet on" >> $CONF
  else
   echo "log_outside_to_intranet off" >> $CONF
  fi;
  if [ "$NC" != "" ]; then
   echo "net_class $NC" >> $CONF
  fi
  if [ "$INTRANET" != "" ]; then
   echo "intranet $INTRANET" >> $CONF
  fi
 fi
done
