#define _POSIX_C_SOURCE 199309L	//for use of TAI clock

//userspace eBPF program includes
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

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
#define so sizeof
#define a14(na, si) na[(si<14) ? 14 : (si)]

static int gfd(char *name, int **fds)
{
	unsigned int id = 0;
	int fd, nb_fds = 0;
	void *tmp;
	int err;

	while (true) {
		struct bpf_map_info info = {};
		__u32 len = sizeof(info);

		err = bpf_map_get_next_id(id, &id);
		if (err) {
			return nb_fds;
		}

		fd = bpf_map_get_fd_by_id(id);
		if (fd < 0) {
			goto err_close_fds;
		}

		err = bpf_map_get_info_by_fd(fd, &info, &len);
		if (err) {
			goto err_close_fd;
		}

		if (strncmp(name, info.name, BPF_OBJ_NAME_LEN)) {
			close(fd);
			continue;
		}

		if (nb_fds > 0) {
			tmp = realloc(*fds, (nb_fds + 1) * sizeof(int));
			if (!tmp) {
				goto err_close_fd;
			}
			*fds = tmp;
		}
		(*fds)[nb_fds++] = fd;
	}

err_close_fd:
	close(fd);
err_close_fds:
	while (--nb_fds >= 0)
		close((*fds)[nb_fds]);
	return -1;
}

u char *fa;
int rbsfn(void*c, void*d, size_t s)
{
	switch (((u char *)d)[0])
	{
		case 0:	fa[*(u char *)d]=1;	break;
		case 1:	fa[*(u char *)d]=0;	//nack
	}
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

	struct ring_buffer *rb;
	int fd=0, *fdp=&fd;
	gfd("rbsik",&fdp);
	rb = ring_buffer__new(fd, rbsfn, 0,0);

	int sockfd;
	struct ifreq ifr;
	struct sockaddr_ll sa;
	unsigned char buffer[14+pds+1];//
	u char a14(b,pds+1);

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

	// Destination MAC address (broadcast? I am not sure if this meand broadcasr.)
	sa.sll_addr[0] = 0xFF;
	sa.sll_addr[1] = 0xFF;
	sa.sll_addr[2] = 0xFF;
	sa.sll_addr[3] = 0xFF;
	sa.sll_addr[4] = 0xFF;
	sa.sll_addr[5] = 0xFF;

	// Construct Ethernet frame (14 bytes: 6 bytes dest MAC, 6 bytes src MAC, 2 bytes ethertype)
	memset(b, 0, so(b));

	u char f[pcif][pds];
		
	#define cf for (u char pti=0; pti<pcif; pti++)	for (u char pdi=0; pdi<pds; pdi++)	f[pti][pdi]=ra;

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
			b[0]=pti;
			u char pdi=0;
			for (; pdi<pds; pdi++)	b[1+pdi]=f[pti][pdi];
			p("sent %d\n", b[1]);
			sendto(sockfd, b, sizeof(b), 0, (struct sockaddr*)&sa, sizeof(struct sockaddr_ll));
		}

		u char cb;
		c:
		ring_buffer__poll(rb, 0);	//you can optimize the program by setting if not received poll again- like logic, since timeout -last parameter- is 0.
		for (u char pti=0; pti<pcif; pti++)	if (!fa[pti])
		{
			b[0]=pti;
			u char pdi=0;
			for (; pdi<pds; pdi++)	b[1+pdi]=f[pti][pdi];
			sendto(sockfd, b, sizeof(b), 0, (struct sockaddr*)&sa, sizeof(struct sockaddr_ll));
		}
	}
	tai(t1);
	p("transfer done at\t\t\t\t%ld%ld\n", t1.tv_sec, t1.tv_nsec);

	e:
	close(sockfd);
	return 0;
}
/*
clang SU.c -o SU -lbpf -fno-builtin
e n1 ./SU 
*/