#ifndef _INET_HDR_H
#define _INET_HDR_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned long u32;

#pragma pack(1)

/* Header of the ethernet frame. */
typedef struct ether_header_t{
    u8 des_hw_addr[6];
    u8 src_hw_addr[6];
    u16 frametype;
} ether_header_t;

/* Header of the ARP packet. */
typedef struct arp_header_t{
    u16 hw_type;
    u16 prot_type;
    u8 hw_addr_len;
    u8 prot_addr_len;
    u16 flag;
    u8 send_hw_addr[6];
    u32 send_prot_addr;
    u8 des_hw_addr[6];
    u32 des_prot_addr;
} arp_header_t;

/* Header of the IP packet. */
typedef struct ip_header_t{
    u8 hlen_ver;          
    u8 tos;               
    u16 total_len;        
    u16 id;               
    u16 flag;             
    u8 ttl;               
    u8 protocol;          
    u16 checksum;         
    u32 src_ip;           
    u32 des_ip;           
} ip_header_t;

/* Header of the UDP packet. */
typedef struct udp_header_t{
    u16 src_port;          
    u16 des_port;          
    u16 len;               
    u16 checksum;          
} udp_header_t;

/* Header of the TCP packet. */
typedef struct tcp_header_t{
    u16 src_port;         
    u16 des_port;         
    u32 seq;              
    u32 ack;              
    u8 len_res;           
    u8 flag;              
    u16 window;           
    u16 checksum;         
    u16 urp;               
} tcp_header_t;

/* Header of the ICMP packet. */
typedef struct icmp_header_t{
    u8 type;              
    u8 code;              
    u16 checksum;         
    u16 id;                 
    u16 seq;              
} icmp_header_t;

typedef struct arp_packet_t{
    ether_header_t etherheader;
    arp_header_t arpheader;
} arp_packet_t;

typedef struct ip_packet_t{
    ether_header_t etherheader;
    ip_header_t ipheader;
} ip_packet_t;

typedef struct tcp_packet_t{
    ether_header_t etherheader;
    ip_header_t ipheader;
    tcp_header_t tcpheader;
} tcp_packet_t;

typedef struct udp_packet_t{
    ether_header_t etherheader;
    ip_header_t ipheader;
    udp_header_t udpheader;
} udp_packet_t;

typedef struct icmp_packet_t{
    ether_header_t etherheader;
    ip_header_t ipheader;
    icmp_header_t icmpheader;
} icmp_packet_t;

#pragma pack()

#endif
