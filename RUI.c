#define _POSIX_C_SOURCE 199309L	//for use of TAI clock

//userspace eBPF program includes
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include <time.h>
#define tai(var) clock_gettime(CLOCK_TAI, &var)
#define ts timespec

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

#include "c.h"

#define p printf

u char *f;
u char *fr;
char fs,pds,pcif,re,acc;

#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>

u char en=0;
int rbsfn(void*c, void*d, size_t s)
{
	for (u char pti=0; pti<pcif; pti++)	if (!fr[pti])	goto c;
	for (u char pti=0; pti<pcif; pti++)	fr[pti]=0; en++;
	c:
	struct ts t;	tai(t);
	p("dereferencing d\n");
	p("%hhu. packet (%hhu) came at \t\t\t%ld%ld\n", *(u char *)d, ((u char *)d)[1], t.tv_sec, t.tv_nsec);

	if (s < pds+1)	//packet info is partial, lost in the . Just do not receive packet. This functionality can be imroved by receiving partial packets etc. Future weork.
	{
		int sockfd;
		struct ifreq ifr;
		struct sockaddr_ll sa;
		unsigned char buffer[14];

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
		memset(buffer, 0, sizeof(buffer));

		//sending nack
		buffer[0] = 1;
		buffer[1] = *(u char *)d;
		sendto(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&sa, sizeof(struct sockaddr_ll));
	}
	for (u char pdi=0; pdi<pds; pdi++)	f[((u char *)d)[0]*pcif + pdi] = ((u char *)d)[pdi+1];
	p("read packet fully\n");

	fr[((u char *)d)[0]] = 1;
	return 0;
}

int main(int arc, char** ars)
{
	p("\n");

	if (arc>=4)	fs = atoi(ars[1]), pds = atoi(ars[2]), acc = atoi(ars[3]);
	pcif = fs/pds, re=2;
	u char _fr[pcif];	fr=_fr;
	for (u char pti=0; pti<pcif; pti++)	fr[pti]=0;
	u char _f[fs];	f=_f;

	u char cb;
	struct ring_buffer *rb;
	int fd=0, *fdp=&fd;
	gfd("rbrk",&fdp);
	rb = ring_buffer__new(fd, rbsfn, 0,0);

	for (en=0; en<re; en++)
	{
		for (u char pti=0; pti<pcif; pti++)	fr[pti]=0;
		c:
		cb = ring_buffer__poll(rb, 0);
		for (u char pti=0; pti<pcif; pti++)	if (!fr[pti])	goto c;
		// p("done\n");
	}

	struct ts t;
	tai(t);
	p("finished at \t\t\t%ld%ld\n", t.tv_sec, t.tv_nsec);
	
	p("file info:	");
	for (u char pti=0; pti<fs; pti++) p("%hhu ", f[pti]);
	p("\n");
	
	return 0;
}
/*
clang RUI.c -o RUI -lbpf -fno-builtin
e n2 ./RUI 
*/