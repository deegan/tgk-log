//Written by EvilFire <fire@c5.hakker.com http://c5.hakker.com>
//inspired from linsniff
//Modified for modern Linux kernels (AF_PACKET API)

#include "defines.h"
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#ifdef LIBC5
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#else
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#endif
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

int logudp=1;
int logicmp=1;
int logtcp=1;
int promisc=0;
int log_all=1;
int resolve=0;
int log_intranet=0;
int net_class=24;
int sock;
int log_intraffic=0;
int intranet_length=0;
char nic_ip[IP_SIZE];
char nic_hw[HW_SIZE];
char intranet[IP_SIZE];
char device[DEVICE_SIZE];
char icmplogfile[PATH_SIZE];
char tcplogfile[PATH_SIZE];
char udplogfile[PATH_SIZE]; 
struct iphdr *ip;
struct tcphdr *tcp;
struct udphdr *udp;
struct icmphdr *icmp;

struct etherpacket{ 
 struct ethhdr eth;
 struct iphdr  ip;
 char buffert[BUFFER_SIZE];
} ep;

static struct interface {
    struct in_addr ipaddr;
} iface;

FILE *tcpfile,*udpfile,*icmpfile;

char *icmptype[]={
  "ECHOREPLY", "undef", "undef", "DEST_UNREACH", "SOURCE_QUENCH",
  "REDIRECT", "undef", "undef", "ECHO", "undef",
  "undef", "TIME_EXCEED", "PARAMETERPROB", "TIMESTAMP", "TIMESTAMPREPLY",
  "INFO_REQUEST", "INFO_REPLY", "ADDRESS", "ADDRESSREPLY"
};

char *icmpunreach[]={
"NET_UNREACH", "HOST_UNREACH", "PROT_UNREACH", "PORT_UNREACH", "FRAG_NEEDED",
  "SR_FAILED", "NET_UNKNOWN", "HOST_UNKNOWN", "HOST_ISOLATED", "NET_ANO",
"HOST_ANO", "NET_UNR_TOS", "HOST_UNR_TOS", "PKT_FILTERED", "PREC_VIOLATION",
  "PREC_CUTOFF"
};

char *icmpredirect[]={
  "REDIR_NET", "REDIR_HOST", "REDIR_NETTOS", "REDIR_HOSTTOS"
};

char *icmptime[]={
  "EXC_TTL", "EXC_FRAGTIME"
};

void write_node(unsigned long sa, unsigned long da,unsigned short sp,
		unsigned short dp,unsigned int pt,char hw[HW_SIZE]);
char *givetime(time_t *t);
char *resolve_host(unsigned long ip, int force);
void setup_interface(char *device, struct interface *intf);
void read_config(void);
void check_rules(unsigned long sa, unsigned long da,unsigned short sp,
		 unsigned short dp,unsigned int pt);
void cleanup(int sig);
void reread(int sig);
void check_paket(void);

char *givetime(time_t *t){
 char *gtime;
 time(t);
 gtime=ctime(t);
 gtime[strlen(gtime)-6]=0;
 return gtime;
}

char *resolve_host(unsigned long ip,int force){
 static char hostname[256];
 struct in_addr i;
 struct hostent *he;

 i.s_addr=ip;
 if((force)&&(resolve)){
  he=gethostbyaddr((char *)&i, sizeof(struct in_addr),AF_INET);
  if(he==NULL)
   strncpy(hostname, inet_ntoa(i),HOST_SIZE-1);
  else 
   strncpy(hostname, he->h_name,HOST_SIZE-1);
  } else {
   strncpy(hostname, inet_ntoa(i),HOST_SIZE-1);
  }
 return hostname;
}

void setup_interface(char *device,struct interface *intf){
 struct ifreq ifr;
 struct sockaddr_ll sll;
 int s;

 sock=socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
 if(sock<0){
  perror("socket");
  exit(1);
 }
 strncpy(ifr.ifr_name, device,sizeof(ifr.ifr_name)-1);
 if((s=ioctl(sock, SIOCGIFFLAGS, &ifr))==-1){
  close(sock);
  perror("ioctl");
  exit(1);
 }
 if(promisc==1){
  ifr.ifr_flags |= IFF_PROMISC;
  if((s=ioctl(sock, SIOCSIFFLAGS, &ifr))==-1){
   perror("ioctl");
   exit(1);
  }
 }

 if(ioctl(sock,SIOCGIFINDEX,&ifr)<0){
  printf("Couldn't get interface index for device %s\n",device);
  exit(1);
 }

 memset(&sll, 0, sizeof(sll));
 sll.sll_family = AF_PACKET;
 sll.sll_ifindex = ifr.ifr_ifindex;
 sll.sll_protocol = htons(ETH_P_ALL);

 if(bind(sock, (struct sockaddr *)&sll, sizeof(sll))<0){
  perror("bind");
  exit(1);
 }

 if(ioctl(sock,SIOCGIFHWADDR,&ifr)<0){
  printf("Couldn't get HW adress of device %s\n",device);
  exit(1);
 } else {
  memset(nic_hw,0,HW_SIZE);
  snprintf(nic_hw,HW_SIZE,"%02X:%02X:%02X:%02X:%02X:%02X",
           (ifr.ifr_hwaddr.sa_data[0] & 0377),
	   (ifr.ifr_hwaddr.sa_data[1] & 0377),
           (ifr.ifr_hwaddr.sa_data[2] & 0377),
	   (ifr.ifr_hwaddr.sa_data[3] & 0377),
	   (ifr.ifr_hwaddr.sa_data[4] & 0377),
	   (ifr.ifr_hwaddr.sa_data[5] & 0377));
  nic_hw[HW_SIZE-1]=0;
 }
 if(ioctl(sock,SIOCGIFADDR, &ifr)<0){
  printf("Couldn't get IP adress of device %s\n",device);
  exit(1);
 } else {
  memset(nic_ip,0,IP_SIZE);
  memcpy(&intf->ipaddr,(void *)&ifr.ifr_netmask.sa_data+2,sizeof(intf->ipaddr));
  snprintf(nic_ip,IP_SIZE-1,"%s",inet_ntoa(intf->ipaddr));
 }
}

void read_config(void){
char dump[DUMP_SIZE];
int type,i=0;
FILE *config;

 if((config=fopen("/etc/tgk-log.conf","r"))==NULL){
  printf("Couldnt open /etc/tgk-log.conf\n");
  exit(1);
 }

 memset(device,0,DEVICE_SIZE);
 memset(intranet,0,IP_SIZE);
 memset(tcplogfile,0,PATH_SIZE);
 memset(udplogfile,0,PATH_SIZE);
 memset(icmplogfile,0,PATH_SIZE);
 
 while(!feof(config)){
  memset(dump,0,DUMP_SIZE);
  fgets(dump,DUMP_SIZE-1,config);
  if((dump[0]!='#')&&(dump[0]!=0)){

   type=strlen(dump)-strlen(index(dump,' '));   
   dump[strlen(dump)-1]='\0';
   
   if(strncasecmp(dump,"resolve",type)==0){
    if(strncasecmp(index(dump,' ')+1,"on",strlen("on"))==0)
     resolve=1;
   } 
   
   else if(strncasecmp(dump,"log-tcp",type)==0){
    if(strncasecmp(index(dump,' ')+1,"on",strlen("on"))==0)
     logtcp=1;
    else if(strncasecmp(index(dump,' ')+1,"off",strlen("off"))==0)
     logtcp=0;
    else {
     printf("log-tcp has invalid value\n");
     fclose(config);
     exit(1);
    }
   } 
   
   else if(strncasecmp(dump,"log-udp",type)==0){
    if(strncasecmp(index(dump,' ')+1,"on",strlen("on"))==0)
     logudp=1;
    else if(strncasecmp(index(dump,' ')+1,"off",strlen("off"))==0)
     logudp=0;
    else {
     printf("log-udp has invalid value\n");
     fclose(config);
     exit(1);
    }
   } 
   
   else if(strncasecmp(dump,"log-icmp",type)==0){
    if(strncasecmp(index(dump,' ')+1,"on",strlen("on"))==0)
     logicmp=1;
    else if(strncasecmp(index(dump,' ')+1,"off",strlen("off"))==0)
     logicmp=0;
    else {
     printf("log-icmp has invalid value\n");
     fclose(config);
     exit(1);
    }
   } 
   else if(strncasecmp(dump,"tcplogfile",type)==0)
    strncpy(tcplogfile,index(dump,' ')+1,PATH_SIZE-1);
   else if(strncasecmp(dump,"udplogfile",type)==0)
    strncpy(udplogfile,index(dump,' ')+1,PATH_SIZE-1);
   else if(strncasecmp(dump,"icmplogfile",type)==0)
    strncpy(icmplogfile,index(dump,' ')+1,PATH_SIZE-1);

   else if(strncasecmp(dump,"log_all",type)==0){
    if(strncasecmp(index(dump,' ')+1,"yes",strlen("yes"))==0)
     log_all=1;
    else if(strncasecmp(index(dump,' ')+1,"no",strlen("no"))==0)
     log_all=0;
    else {
     printf("log_all has invalid value\n");
     fclose(config);
     exit(1);
    }
   }

   else if(strncasecmp(dump,"log_intranet",type)==0){
    if(strncasecmp(index(dump,' ')+1,"on",strlen("on"))==0)
     log_intranet=1; 
    else if(strncasecmp(index(dump,' ')+1,"off",strlen("off"))==0)
     log_intranet=0;
    else {
     printf("log_intranet has invalid value\n");
     fclose(config);
     exit(1);
    }
   }

   else if(strncasecmp(dump,"log_intraffic",type)==0){
    if(strncasecmp(index(dump,' ')+1,"on",strlen("on"))==0)
     log_intraffic=1;
    else if(strncasecmp(index(dump,' ')+1,"off",strlen("off"))==0)
     log_intraffic=0;
    else {
     printf("log_intraffic has invalid value\n");
     fclose(config);
     exit(1);
    }
   }

   else if(strncasecmp(dump,"net_class",type)==0){
    if(strncasecmp(index(dump,' ')+1,"8",strlen("8"))==0)
     net_class=8;
    else if(strncasecmp(index(dump,' ')+1,"16",strlen("16"))==0)
     net_class=16;
    else if(strncasecmp(index(dump,' ')+1,"24",strlen("24"))==0)
     net_class=24;
    else {
     printf("net_class has invalid value\n");
     fclose(config);
     exit(1);
    }
   }

   else if(strncasecmp(dump,"intranet",type)==0){
    strncpy(intranet,index(dump,' ')+1,IP_SIZE-1);
    if(inet_addr(intranet)==-1){
     printf("Invalid intranet IP in config file\n");
     fclose(config);
     exit(1);
    } 
   }

   else if(strncasecmp(dump,"promisc",type)==0){
    if(strncasecmp(index(dump,' ')+1,"on",strlen("on"))==0)
     promisc=1;
    else if(strncasecmp(index(dump,' ')+1,"off",strlen("off"))==0)
     promisc=0;
    else {
     printf("promisc has invalid value\n");
     fclose(config);
     exit(1);
    }
   }

   else if(strncasecmp(dump,"device",type)==0){
    strncpy(device,index(dump,' ')+1,DEVICE_SIZE-1);
   }
  }
 }
 fclose(config);

 setup_interface(device,&iface);
 if((logtcp)&&(tcplogfile[0]==0)){
  printf("log-tcp has value ON but no tcplogfile was entered\n");
  exit(1);
 }
 else if((logtcp)&&(tcplogfile[0]!=0)){
  if((tcpfile=fopen(tcplogfile,"a"))==NULL){
   printf("Couldn't open tcp logfile %s\n",tcplogfile);
   exit(1);
  }
 }

 if((logudp)&&(udplogfile[0]==0)){
  printf("log-udp has value ON but no udplogfile was entered\n");
  exit(1);
 }
 else if((logudp)&&(udplogfile[0]!=0)){
  if((udpfile=fopen(udplogfile,"a"))==NULL){
   printf("Couldn't open udp logfile %s\n",udplogfile);
   exit(1);
  }
 }

 if((logicmp)&&(icmplogfile[0]==0)){
  printf("log-icmp has value ON but no udplogfile was entered\n");
  exit(1);
 }
 else if((logicmp)&&(icmplogfile[0]!=0)){
  if((icmpfile=fopen(icmplogfile,"a"))==NULL){
   printf("Couldn't open icmp logfile %s\n",icmplogfile);
   exit(1);
  }
 }

 if(device[0]==0){
  printf("You havent entered a network device in the config file\n");
  exit(1);
 }

 if(log_all==0){
  if(intranet[0]==0){
   printf("log_all is no but intranet is empty.\n");
   exit(1);
  }
  switch(net_class){
   case 24:
    for(intranet_length=0;i!=3;intranet_length++){
     if(intranet[intranet_length]=='.')
      i++;
    }
   break;
   case 16:
    for(intranet_length=0;i!=2;intranet_length++){
     if(intranet[intranet_length]=='.')
      i++;
    }
   break;   
   case 8:
    for(intranet_length=0;i!=1;intranet_length++){
     if(intranet[intranet_length]=='.')
      i++;
    }
   break;   
  }
 }
}

void check_rules(unsigned long sa, unsigned long da,unsigned short sp,unsigned short dp,unsigned int pt){
char source_ip[IP_SIZE], dest_ip[IP_SIZE],hw[HW_SIZE];
 char *resolved_src, *resolved_dst;
 size_t len;

 memset(source_ip,0,IP_SIZE);
 memset(dest_ip,0,IP_SIZE);
 resolved_src = resolve_host(sa,NO_RESOLVE);
 resolved_dst = resolve_host(da,NO_RESOLVE);

 /* Copy with explicit truncation handling */
 len = strlen(resolved_src);
 if(len >= IP_SIZE) len = IP_SIZE - 1;
 memcpy(source_ip, resolved_src, len);
 source_ip[len] = 0;

 len = strlen(resolved_dst);
 if(len >= IP_SIZE) len = IP_SIZE - 1;
 memcpy(dest_ip, resolved_dst, len);
 dest_ip[len] = 0;

 snprintf(hw,HW_SIZE,"%02X:%02X:%02X:%02X:%02X:%02X",
           ep.eth.h_source[0],ep.eth.h_source[1],
           ep.eth.h_source[2],ep.eth.h_source[3],
           ep.eth.h_source[4],ep.eth.h_source[5]);
 hw[HW_SIZE-1]=0;

 if(((strcmp(source_ip,nic_ip))!=0)&&((strcmp(hw,nic_hw))!=0)){
  if(!log_all){
   if(strncmp(source_ip,intranet,intranet_length)==0){
    if(strncmp(dest_ip,intranet,intranet_length)!=0)
     write_node(sa,da,sp,dp,pt,hw);
    else if(log_intranet)
     write_node(sa,da,sp,dp,pt,hw);
   } else if(log_intraffic)
    write_node(sa,da,sp,dp,pt,hw);
  } else {
   write_node(sa,da,sp,dp,pt,hw);
  }
 } 
}

void write_node(unsigned long sa, unsigned long da,unsigned short sp,
		unsigned short dp,unsigned int pt,char hw[HW_SIZE]){
 time_t t;
 
 switch(pt){
  case IPPROTO_TCP:
   fprintf(tcpfile,"%s [%d] (%s)",resolve_host(sa,RESOLVE),ntohs(sp),hw);
   fprintf(tcpfile," => %s [%d] - ",resolve_host(da,RESOLVE),ntohs(dp));
   fprintf(tcpfile,"%s\n",givetime(&t));
   fflush(tcpfile);
  break; 
  case IPPROTO_UDP:
   fprintf(udpfile,"%s [%d] (%s)",resolve_host(sa,NO_RESOLVE),ntohs(sp),hw);
   fprintf(udpfile," => %s [%d] - ",resolve_host(da,NO_RESOLVE),ntohs(dp));
   fprintf(udpfile,"%s\n",givetime(&t));
   fflush(udpfile);
  break;
  case IPPROTO_ICMP:
   fprintf(icmpfile,"%s (%s)",resolve_host(sa,RESOLVE),hw);
   if((sp!=ICMP_DEST_UNREACH)&&(sp!=ICMP_REDIRECT)&&(sp!=ICMP_TIME_EXCEEDED))
    fprintf(icmpfile," => %s [%s] - ",resolve_host(da,RESOLVE),icmptype[sp]);
   else if(sp==ICMP_DEST_UNREACH)
    fprintf(icmpfile," => %s [%s] [%s] - ",resolve_host(da,RESOLVE),icmptype[sp],
				            icmpunreach[dp]); 
   else if(sp==ICMP_REDIRECT)
    fprintf(icmpfile," => %s [%s] [%s] - ",resolve_host(da,RESOLVE),icmptype[sp],
                                            icmpredirect[dp]);
   else if(sp==ICMP_TIME_EXCEEDED)
    fprintf(icmpfile," => %s [%s] [%s] - ",resolve_host(da,RESOLVE),icmptype[sp],
                                            icmptime[dp]);
   fprintf(icmpfile,"%s\n",givetime(&t));
   fflush(icmpfile);
  break;
 }
}

void cleanup(int sig){
struct ifreq ifr;
int s,sokka;

 if(sock)
  close(sock);
 if(logtcp)
  fclose(tcpfile);
 if(logudp)
  fclose(udpfile);
 if(logicmp)
  fclose(icmpfile);

 sokka=socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
 if(sokka<0){
  perror("socket");
  exit(1);
 }
 strncpy(ifr.ifr_name, device,sizeof(ifr.ifr_name));
 if((s=ioctl(sokka, SIOCGIFFLAGS, &ifr))==-1){
  close(sokka);
  perror("ioctl");
  exit(1);
 }
 if(promisc==1){
  ifr.ifr_flags -= IFF_PROMISC ;
  if((s=ioctl(sokka, SIOCSIFFLAGS, &ifr))==-1){
   perror("ioctl");
   exit(1);
  }
 }
 close(sokka);
 exit(1);
}

void reread(int sig){
struct ifreq ifr;
int s,sokka;

 if(sock)
  close(sock);
 if(logtcp)
  fclose(tcpfile);
 if(logudp)
  fclose(udpfile);
 if(logicmp)
  fclose(icmpfile);

 sokka=socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
 if(sokka<0){
  perror("socket");
  exit(1);
 }
 strncpy(ifr.ifr_name, device,sizeof(ifr.ifr_name));
 if((s=ioctl(sokka, SIOCGIFFLAGS, &ifr))==-1){
  close(sokka);
  perror("ioctl");
  exit(1);
 }
 if(promisc==1){
  ifr.ifr_flags -= IFF_PROMISC ;
  if((s=ioctl(sokka, SIOCSIFFLAGS, &ifr))==-1){
   perror("ioctl");
   exit(1);
  }
 }
 close(sokka);
 read_config();
}

void check_paket(void){
 switch(ip->protocol){
  case IPPROTO_TCP:
   if((tcp->syn)&&(logtcp))
    check_rules(ip->saddr,ip->daddr,tcp->source,tcp->dest,ip->protocol);
  break;
  case IPPROTO_UDP:
   if(logudp)
    check_rules(ip->saddr,ip->daddr,udp->source,udp->dest,ip->protocol);
  break;
  case IPPROTO_ICMP:
   if(logicmp)
    check_rules(ip->saddr,ip->daddr,icmp->type,icmp->code,ip->protocol);
  break;
 }
}

int main(int argc, char *argv[]){
 int x,dn;	
 ip=(struct iphdr *)(((unsigned long)&ep.ip)-2);
 tcp=(struct tcphdr *)(((unsigned long)&ep.buffert)-2);
 udp=(struct udphdr *)(((unsigned long)&ep.buffert)-2);
 icmp=(struct icmphdr *)(((unsigned long)&ep.buffert)-2);
 read_config();

 switch(fork()){
 case -1:
  perror("fork");
  exit(1);
 break;
 case 0:
  close(0);close(1);close(2);
  setsid();
  chdir("/");
  umask(0);
  dn=open("/dev/null",O_RDWR);
  dup2(0,dn); dup2(1,dn); dup2(2,dn);
  close(dn);

  signal(SIGINT, cleanup);
  signal(SIGTERM, cleanup);
  signal(SIGKILL, cleanup);
  signal(SIGQUIT, cleanup);
  signal(SIGHUP, reread);
	
  while(1){
   x=read(sock, (struct etherpacket *)&ep, sizeof(struct etherpacket));
   if(x>1)
    check_paket();
  }
  break;
 }
return(0);
}
