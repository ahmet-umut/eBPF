#define _POSIX_C_SOURCE 199309L	//for use of TAI clock

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <linux/if.h>

#include <time.h>
#define tai(var) clock_gettime(CLOCK_TAI, &var)
#define ts timespec

#include "c.h"

#define p printf

int main(int arc, char** ars)
{
	p("\n");

	char fs,pds,pcif,re,acc;
	if (arc>=4)	fs = atoi(ars[1]), pds = atoi(ars[2]), acc = atoi(ars[3]);
	pcif = fs/pds, re=2;

	u char f[pcif][pds];
	u char fr[pcif];

	int sockfd;
	struct ifreq ifr;
	struct sockaddr_ll sa;
	unsigned char reb[14+pds+1], seb[14+acc+1];

	// Create a raw socket
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		perror("socket");
		exit(1);
	}

	// Specify the interface to listen on
	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, "ven2", IFNAMSIZ - 1); // Change "eth0" to your interface name
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

	printf("Listening on interface %s\n", ifr.ifr_name);
	
	for (u char en=0; en<re; en++)
	{
		for (u char pti=0; pti<pcif; pti++)	fr[pti]=0;
		u char ptc=0;
		c:
		ssize_t num_bytes = recvfrom(sockfd, reb, ETH_FRAME_LEN, 0, NULL, NULL);
		if (num_bytes)
		{
			struct ts t;
			tai(t);
			p("%d. packet came at \t\t\t\t%ld%ld\n", reb[14], t.tv_sec, t.tv_nsec);
			seb[15+seb[14]] = reb[14];
			ptc++, seb[14]++;
			if (seb[14] >= acc || ptc==pcif)	//sending cumulative ack with dynamic size
			{
				p(" cumulative ack ssent\n");
				sendto(sockfd, seb, sizeof(seb), 0, (struct sockaddr*)&sa, sizeof(struct sockaddr_ll));
				seb[14]=0;
			}
			for (u char pdi=0; pdi<pds; pdi++)	f[reb[14]][pdi]=reb[15+pdi];
			fr[reb[14]] = 1;
		}
		for (u char pti=0; pti<pcif; pti++)	if (!fr[pti])	goto c;
		
		p("file info:	");
		for (u char pti=0; pti<pcif; pti++)	for (u char pdi=0; pdi<pds; pdi++)	p("%d ", f[pti][pdi]);
		p("\n");
	}

	struct ts t;
	tai(t);
	p("experiment finished at \t\t\t\t%ld%ld\n", t.tv_sec, t.tv_nsec);

	p("\n");
	close(sockfd);
	return 0;
}
/*
sudo ip netns exec n2 ip link set dev ven2 xdpgeneric off
clang _R.c -o _R -lbpf
e n2 ./_R 
*/