#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>        /* for NF_ACCEPT */
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <regex.h>
#include <string.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

struct ip *ip_hdr;
struct tcphdr *tcp_hdr;
char host_url[100];

void get_in_data_url(u_char *data) {
	regex_t state;
	regmatch_t host_name[1];
	int status, url_len;
	const char *url_pattern = "(Host: ?)(([a-zA-Z0-9\\-_])+\\.)+([a-zA-Z]{2,11})";

	regcomp(&state, url_pattern, REG_EXTENDED);
	status = regexec(&state, data, 1, host_name, 0);
	if(status == 0) {
		url_len = (int)host_name[0].rm_eo - host_name[0].rm_so;
		strncpy(host_url, data+host_name[0].rm_so+6, url_len-6);
		printf("You are in %s\n", host_url);
	}
	regfree(&state);
	return ;
}	

int check_harmful() {
	char *harm = "sex.com";
	if(!strncmp(host_url, harm, strlen(harm))) return 1;
	else return 0;

}

void get_host_name(u_char *data) {
	u_char *start_data;
	ip_hdr = (struct ip *)data;
	printf("IP PROTO : %d\n", ip_hdr->ip_p);
	if(ip_hdr->ip_p == IPPROTO_TCP) {
		tcp_hdr = (struct tcphdr *)(data+ip_hdr->ip_hl*4);
		printf("Port Num : %d\n", ntohs(tcp_hdr->th_dport));
		if(ntohs(tcp_hdr->th_dport) == 80 || ntohs(tcp_hdr->th_dport) == 8080) {
			start_data = (u_char *)data+(ip_hdr->ip_hl*4)+(tcp_hdr->th_off*4);
			get_in_data_url(start_data);
		}

	}
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb, int *result)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	u_char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		//printf("hw_protocol=0x%04x hook=%u id=%u ",
		//ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0) {
		get_host_name(data);
		if(check_harmful()) *result = 1;
		else *result = 0;
	}
	fputc('\n', stdout);
	return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
		struct nfq_data *nfa, void *data)
{
	int result = -1;
	u_int32_t id = print_pkt(nfa, &result);
	//printf("entering callback\n");
	if(result == 1) {
		puts("Warning Site!!!!!!");
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}
	else if(result == 0) {
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
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

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
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
			//printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
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

