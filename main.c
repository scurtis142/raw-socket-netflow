#include <stdbool.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <string.h>
#include <signal.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pcap/pcap.h>
#include <math.h>
#include <sys/time.h>

#include "netflow-table.h"

#define FTWO 0x0000FF00
#define FONE 0x000000FF
#define FTH 0x000F0000

int rawSocket();
int setPromisc(char *,int *);
bool loop;

/* control-C handler */
static void
sigint_h(int sig)
{
   int i;

   (void)sig;	/* UNUSED */
   printf ("received control-C\n");
   loop = false;
}


int main(int argc,char **argv)
{
   if(argc!=2)
   {
      perror("please echo like this:   ./mypack eth0\n");
      exit(1);
   }

   struct netflow_table *table = netflow_table_init ();

   int sock;
   struct sockaddr_ll rcvaddr;
   char buf[6666];
   struct ifreq ifr;
   int len;
   struct sigaction sa;

   sock=rawSocket();
   setPromisc(argv[1],&sock);
   len=sizeof(struct sockaddr);
   memset(buf,0,sizeof(buf));
   loop = true;


   /* Install the handler and re-enable SIGINT for the main thread */
   memset(&sa, 0, sizeof(sa));
   sa.sa_handler = sigint_h;
   if (sigaction(SIGINT, &sa, NULL) < 0) {
      printf ("failed to install ^C handler: %s", strerror(errno));
   }


   int count = 0;
   while(loop)
   {
      int rval;      //the unit is byte!!!  so multiple 256
      netflow_key_t key;
      netflow_value_t value;
      rval=recvfrom(sock,buf,sizeof(buf),0,(struct sockaddr*)&rcvaddr,&len);
      if(rval>0)
      {
         /* printf("Packet received: %d\n", count++); */
         if (get_netflow_k_v (buf, len, &key, &value))
            netflow_table_insert(table, &key, &value);
      }

      else
         printf("recvfrom failed!!!\n");	
   }
   netflow_table_print_stats (table);
   return 0;
}


int rawSocket()//
{
   int sock;
   //sock=socket(PF_INET,SOCK_RAW,IPPROTO_TCP);//frome IP
   sock=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));//frome Ethernet
   if(sock<0)
   {
      printf("create raw socket failed:%s\n",strerror(errno));
      exit(1);
   }

   printf("raw socket :%d created successful!\n",sock);
   return sock;
}


int setPromisc(char *enterface,int *sock)
{
   struct ifreq ifr;
   strcpy(ifr.ifr_name, enterface);
   ifr.ifr_flags=IFF_UP|IFF_PROMISC|IFF_BROADCAST|IFF_RUNNING;
   if(ioctl(*sock,SIOCSIFFLAGS,&ifr)==-1)
   {
      perror("set 'eth' to promisc model failed\n"); //cant write  '%s',enterface  why?
      exit(1);
   }
   printf("set '%s' to promisc successed!\n",enterface);
   return 1;
}
