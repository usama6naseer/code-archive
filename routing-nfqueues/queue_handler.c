#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
/* returns packet id */

struct ret_rule {
	u_int32_t id;
	int ip_found;
};

struct ret_rule read_pkt_insert_rule (struct nfq_data *tb) {
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
		printf("payload_len=%d ", ret);

	fputc('\n', stdout);

	struct iphdr *iph = ((struct iphdr *) data);

    // Computing IP address translation from 32 bits words to 4*8bits decimal
    /* NOTE ON THE LENGTHS
    all lengths used in headers are specified in 32bits words
    thus, to print the size in bytes, we need to multiply this value by 4
    */

    // display IP HEADERS : ip.h line 45
    // ntohs convert short unsigned int, ntohl do the same for long unsigned int
    fprintf(stdout, "IP{v=%u; ihl=%u; tos=%u; tot_len=%u; id=%u; ttl=%u; protocol=%u; "
        ,iph->version, iph->ihl*4, iph->tos, ntohs(iph->tot_len), ntohs(iph->id), iph->ttl, iph->protocol);

    char *saddr = inet_ntoa(*(struct in_addr *)&iph->saddr);
    fprintf(stdout,"saddr=%s; ",saddr);

    char *daddr = inet_ntoa(*(struct in_addr *)&iph->daddr);
    fprintf(stdout,"daddr=%s}\n",daddr);

    // sudo iptables -t nat -I PREROUTING -p tcp --source 192.168.230.1 --dport 80 -j DNAT --to-destination 152.3.144.155 
    // 24.250.21.244 24.250.21.244
    printf("saddr: %s | daddr: %s | %s %u\n", saddr, daddr, "24.250.21.244", strcmp("24.250.21.244", saddr));
    if (strcmp("24.250.21.244", saddr) == 0) {
    	system("sudo iptables -t nat -I PREROUTING -p tcp --source 24.250.21.244 --dport 80 -j DNAT --to-destination 152.3.144.154");	
    	printf("%s\n", "concerned IP found.");
    	struct ret_rule ret = {id,1};
    	return ret;
    }
	else {
		printf("%s\n", "concerned IP NOT found.");
		struct ret_rule ret = {id,0};
		return ret;
	}
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	// u_int32_t id = print_pkt(nfa);
	struct ret_rule ret = read_pkt_insert_rule(nfa);
	printf("entering callback\n");
	// return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	printf("ip_found ret: %u\n", ret.ip_found);
	if (ret.ip_found == 0) {
		return nfq_set_verdict(qh, ret.id, NF_ACCEPT, 0, NULL);	
	}
	else {
		return nfq_set_verdict(qh, ret.id, NF_REPEAT, 0, NULL);
	}
	
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '1'\n");
	qh = nfq_create_queue(h,  1, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}

