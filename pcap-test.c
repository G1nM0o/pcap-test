#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <libnet.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr *header;
		const u_char *packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		struct libnet_ethernet_hdr *ether = (struct libnet_ethernet_hdr *)packet;
		if (ntohs(ether->ether_type) != ETHERTYPE_IP) continue;

		struct libnet_ipv4_hdr *ip = (struct libnet_ipv4_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));
		if (ip->ip_p != IPPROTO_TCP) continue;

		int ip_hdr_len = ip->ip_hl * 4;
		struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr *)((unsigned char *)ip + ip_hdr_len);
		int tcp_hdr_len = tcp->th_off * 4;
		int total_len = ntohs(ip->ip_len);
		int payload_len = total_len - ip_hdr_len - tcp_hdr_len;
		unsigned char *payload = (unsigned char *)tcp + tcp_hdr_len;

		printf("%02x:%02x:%02x:%02x:%02x:%02x -> ", ether->ether_shost[0], ether->ether_shost[1], ether->ether_shost[2], ether->ether_shost[3], ether->ether_shost[4], ether->ether_shost[5]);
		printf("%02x:%02x:%02x:%02x:%02x:%02x, ", ether->ether_dhost[0], ether->ether_dhost[1], ether->ether_dhost[2], ether->ether_dhost[3], ether->ether_dhost[4], ether->ether_dhost[5]);

		printf("%s:%u -> %s:%u\n", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport), inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));

		printf("payload: ");
		for (int i = 0; i < payload_len && i < 20; i++) {
			printf("%02x ", payload[i]);
		}
		printf("\n\n");
	}

	pcap_close(pcap);
}

