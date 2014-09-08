#ifndef _SNIFFER_H
#define _SNIFFER_H

#include <stdbool.h>

#define ARP_BIT 1
#define TCP_BIT 2
#define UDP_BIT 3
#define ICMP_BIT 4

/* filter structure */
typedef struct _filter
{
    unsigned long sip;
    unsigned long dip;
    unsigned int protocol;
} filter;

typedef struct _sniffer
{
    int sockfd;
    char *packet;
    filter filter;
    int max_packet_len;
} sniffer;

/* Create a raw socket. */
int rsock_create(const int protocol);

/* Close a raw socket. */
void rsock_close(int sockfd);

/* Set the network interface to promiscuous mode. */
bool rsock_do_promisc(int sockfd, char *nif);

/* Receive packets from raw socket. */
int rsock_receive(int sockfd, char *recvbuf, int buflen, struct sockaddr_in *from, int *addrlen);

/* Create sniffer. */
sniffer *sniffer_create(int protocol);

void sniffer_free(sniffer *sniffer);

/* set the socket to promiscuous mode to capture all packets. */
bool sniffer_init(sniffer *sniffer);

bool sniffer_test_bit(const unsigned int p, int k);

void sniffer_set_bit(unsigned int *p, int k);

/* Capture packets; */
void sniffer_sniff(sniffer *sniffer);

/* Analyze packets. */
void sniffer_analyze(sniffer *sniffer);

/* Analyze IP packets. */
void parse_ip_packet(sniffer *sniffer);

/* Analyze ARP packets. */
void parse_arp_packet(sniffer *sniffer);

/* Analyze UDP packets. */
void parse_udp_packet(sniffer *sniffer);

/* Analyze TCP packets. */
void parse_tcp_packet(sniffer *sniffer);

/* Analyze ICMP packets. */
void parse_icmp_packet(sniffer *sniffer);

/* Get readable MAC address. */
char *get_hw_addr_str(char *hw_addr_str, const unsigned char *ptr);

/* Get readable IP address from integer. */
char *get_ip_addr_str(const unsigned long ip);

#endif
