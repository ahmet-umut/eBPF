#define _POSIX_C_SOURCE 199309L	//for use of TAI clock

//general user-space C program needs
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

//network send/receive...
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>

#include <time.h>
#define tai(var) clock_gettime(CLOCK_TAI, &var)
#define ts timespec

#include "c.h"

#define ra (rand()%256)
#define p printf

u char *fa;
int rbsfn(void*c, void*d, size_t s)
{
	fa[*(u char *)d]=1;
	return 0;
}

int main(int arc, char** ars)
{
	p("\n");

	char fs,pds,pcif,re,acc;
	if (arc>=4)	fs = atoi(ars[1]), pds = atoi(ars[2]), acc = atoi(ars[3]);
	pcif = fs/pds, re=2;
	u char _fa[pcif];	fa=_fa;

	srand(time(0));

	int sockfd;
	struct ifreq ifr;
	struct sockaddr_ll sa;
	unsigned char reb[15+acc], seb[14+pds+1];

	// Create a raw socket
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		perror("socket");
		exit(1);
	}

	// Specify the interface to use
	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, "ven1", IFNAMSIZ - 1); // Change "ven1" to your interface name
	if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {
		perror("ioctl");
		close(sockfd);
		exit(1);
	}

	// Prepare the sockaddr_ll structure
	memset(&sa, 0, sizeof(struct sockaddr_ll));
	sa.sll_ifindex = ifr.ifr_ifindex;
	sa.sll_halen = ETH_ALEN;
	sa.sll_protocol = htons(ETH_P_IP);

	// Destination MAC address (example)
	sa.sll_addr[0] = 0xFF;
	sa.sll_addr[1] = 0xFF;
	sa.sll_addr[2] = 0xFF;
	sa.sll_addr[3] = 0xFF;
	sa.sll_addr[4] = 0xFF;
	sa.sll_addr[5] = 0xFF;

	// Construct Ethernet frame (14 bytes: 6 bytes dest MAC, 6 bytes src MAC, 2 bytes ethertype)
	memset(seb, 0, sizeof(seb));
	// Destination MAC
	seb[0] = 0xFF;
	seb[1] = 0xFF;
	seb[2] = 0xFF;
	seb[3] = 0xFF;
	seb[4] = 0xFF;
	seb[5] = 0xFF;
	// Source MAC (example)
	seb[6] = 0xFF;
	seb[7] = 0xFF;
	seb[8] = 0xFF;
	seb[9] = 0xFF;
	seb[10] =0xFF;
	seb[11] =0xFF;
	// Ethertype (example: 0x0800 for IPv4)
	seb[12] = 0;
	seb[13] = 0x00;

	u char f[pcif][pds];
		
	#define cf for (u char pti=0; pti<pcif; pti++)	for (u char pdi=0; pdi<pds; pdi++)	f[pti][pdi]=ra, fa[pti]=0;

	struct ts t0,t1, t;

	cf;
	p("file info:	");
	for (u char pti=0; pti<pcif; pti++)	for (u char pdi=0; pdi<pds; pdi++)	p("%d ", f[pti][pdi]);
	p("\n");

	tai(t0);
	p("starting to send %hhu files at\t\t\t%ld%ld\n", re, t0.tv_sec, t0.tv_nsec);
	for (u char en=0; en<re; en++)
	{
		for (u char pti=0; pti<pcif; pti++)
		{
			fa[pti]=0;
			seb[14]=pti;
			u char pdi=0;
			for (; pdi<pds; pdi++)	seb[15+pdi]=f[pti][pdi];
			sendto(sockfd, seb, sizeof(seb), 0, (struct sockaddr*)&sa, sizeof(struct sockaddr_ll));
		}

		c:
		ssize_t num_bytes = recvfrom(sockfd, reb, ETH_FRAME_LEN, 0, NULL, NULL);
		if (num_bytes)	for (u char aci=0; aci<reb[14]; aci++)	fa[reb[15+aci]] = 1, p("received");

		for (u char pti=0; pti<pcif; pti++)	if (!fa[pti])
		{
			seb[14]=pti;
			u char pdi=0;
			for (; pdi<pds; pdi++)	seb[15+pdi]=f[pti][pdi];
			sendto(sockfd, seb, sizeof(seb), 0, (struct sockaddr*)&sa, sizeof(struct sockaddr_ll));
			goto c;
		}
	}
	tai(t1);
	p("experiment done at\t\t\t\t%ld%ld\n", t1.tv_sec, t1.tv_nsec);

	e:
	close(sockfd);
	return 0;
}
/*
sudo ip netns exec n1 ip link set dev ven1 xdpgeneric off
clang _S.c -o _S -lbpf -fno-builtin
e n1 ./_S 
*/