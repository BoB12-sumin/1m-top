#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <libnetfilter_queue/libnetfilter_queue.h>


struct ip_header {
    uint8_t ihl:4;
    uint8_t version:4;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

struct tcp_header {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint16_t res1:4;
    uint16_t doff:4;
    uint16_t fin:1;
    uint16_t syn:1;
    uint16_t rst:1;
    uint16_t psh:1;
    uint16_t ack:1;
    uint16_t urg:1;
    uint16_t res2:2;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};


void dump(unsigned char *buf, int size);


#define MAX_URLS 1000001
#define B_FIELD_INDEX 1

char *blocked_urls[MAX_URLS];
int blocked_urls_count = 0;

char *remove_newline(char *str) {
    if (str == NULL)
        return NULL;

    size_t len = strlen(str);
    if (len > 0 && str[len - 1] == '\n') {
        str[len - 1] = '\0';
    }

    return str;
}


void parse_csv_file(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Failed to open file");
        exit(EXIT_FAILURE);
    }

    char line[1024];
    int line_count = 0;
	while (fgets(line, sizeof(line), file)) {
		char *token;
		int field_index = 0;

		token = strtok(line, ",");
		while (token != NULL) {
			if (field_index == B_FIELD_INDEX) {
				remove_newline(token);
				
				blocked_urls[blocked_urls_count] = strdup(token);
				blocked_urls_count++;
					
					if (blocked_urls_count >= MAX_URLS) {
						fprintf(stderr, "Too many URLs in CSV file\n");
						exit(EXIT_FAILURE);
					}
				}
				token = strtok(NULL, ",");
				field_index++;
			}
		}

    fclose(file);
}

bool is_url_blocked(const char *url) {
    printf("Checking URL: %s", url);
	printf("checking unban_url: %s", blocked_urls[2]);
    for (int i = 0; i < blocked_urls_count; i++) {
        if (strcmp(url, blocked_urls[i]) == 0)
            return true;
    }
    
    return false;
}


static u_int32_t print_pkt (struct nfq_q_handle *qh, struct nfq_data *tb)
{
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
	if (ret >= 0){
		printf("payload_len=%d\n", ret);
		dump(data, ret);
		printf("\n");
	}
	
	fputc('\n', stdout);

	return id;
}

void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02X ", buf[i]);
	}
	printf("\n");
}

static int cb(struct nfq_q_handle *qh,
              struct nfgenmsg *nfmsg,
              struct nfq_data *nfa,
              void* data)
{
    u_int32_t id = print_pkt(qh,nfa);

    unsigned char *payload;
    int payload_len = nfq_get_payload(nfa, &payload);

    struct ip_header *ip = (struct ip_header *)payload;
    unsigned char *tcp_data = payload + ip->ihl * 4;
    struct tcp_header *tcp = (struct tcp_header *)tcp_data;
    unsigned char *http_data = tcp_data + tcp->doff*4;

	char http_string[payload_len+1];
	strncpy(http_string, (char*)http_data, payload_len);
	http_string[payload_len] = '\0';

 	char* host=strstr(http_string,"Host: ");
	if(host!=NULL){
		host+=strlen("Host: ");
		char *host_end = strstr(host, "\r\n");
		if(host_end!=NULL){
		while(host_end > host && isspace((unsigned char) *(host_end - 1))) {
			--host_end;
		}
		*host_end='\0';
		if(is_url_blocked(host)){  
			*host_end='\r';
			return nfq_set_verdict(qh,id,NF_DROP,0,NULL);
		}
		*host_end='\r';
		}
	}

     printf("entering callback");

     return nfq_set_verdict(qh,id,NF_ACCEPT,payload_len,payload);
}


int main(int argc,char **argv){

	if(argc!=2){
        	printf("Usage: %s csv_file\n", argv[0]);
        	return -1;
     }

	parse_csv_file(argv[1]);

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
	qh = nfq_create_queue(h, 0, &cb, NULL);
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
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}


