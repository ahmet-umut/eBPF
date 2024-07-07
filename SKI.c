/* SPDX-License-Identifier: GPL-2.0 */

#include <string.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <sys/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "k.h"
#include "c.h"

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1);
} rbsik SEC(".maps");

u l int t, t0,t1;
u char ptc;

#define ptac(pti) if ((void*)c->d + pti+1 > (void*)c->de)	goto e

SEC("xdp")
int pm(struct xdp_md *c)
{
	t = bpfktgtains();

	ptac(acc+2);

	u char ptt = ((u char *)(c->d))[0];
	switch(ptt)
	{
		case 0:	//ack
			u char acco = ((u char *)(c->d))[1];
			for (u char aci=0; aci < acco; aci++)
			{
				u char ptt=0;
				bpf_ringbuf_output(&rbsik, &ptt, 1, 0);
				ptac(aci);
				u char ac = ((u char *)(c->d))[aci];
				bpf_ringbuf_output(&rbsik, &ac, 1, 0);
			}
			break;
		case 1:	//nack
			u char ptt=1;
			bpf_ringbuf_output(&rbsik, &ptt, 1, 0);
			
			ptac(1);
			u char pti = ((u char *)(c->d))[1];
			bpf_ringbuf_output(&rbsik, &pti, 1, 0);
	}
	
	t1 = bpfktgtains();
	ptc++;
	t0=t;
	return XDP_DROP;
	e:	return XDP_PASS;
}
/*
sudo ip netns exec n1 ip link set dev ven1 xdpgeneric off
clang -c SKI.c -o SKI.o -target bpf -g -O1 -fno-builtin
e n1 ip link set dev ven1 xdpgeneric obj SKI.o sec xdp

sudo bpftool map dump name SKI.bss
*/
char _license[] SEC("license") = "GPL";