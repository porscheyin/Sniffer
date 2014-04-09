#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>
#include "sniffer.h"

int main(int argc, char ** argv)
{
    char ch;

    printf("name: %s\n", argv[0]);
    printf("arg: %s\n", argv[1]);

    sniffer *sniffer = sniffer_create(htons(ETH_P_ALL)); // htons here is very important! 

    while ((ch = getopt(argc, argv, "s:d:atui")) != -1) // Get command arguments.
    {
        switch (ch) // Set filter options according to the arguments.
        {
            case 's':
                sniffer->filter.sip = inet_addr(optarg);
                break;
            case 'd':
                sniffer->filter.dip = inet_addr(optarg);
                break;
            case 'a':
                sniffer_set_bit((&sniffer->filter.protocol), ARP_BIT);
                break;
            case 't':
                sniffer_set_bit((&sniffer->filter.protocol), TCP_BIT);
                break;
            case 'u':
                sniffer_set_bit((&sniffer->filter.protocol), UDP_BIT);
                break;
            case 'i':
                sniffer_set_bit((&sniffer->filter.protocol), ICMP_BIT);
                break;
            default:
                break;
        }
    }
    printf("Sniffer created successfully.\n");

    // Initialize the sniffer.
    if (!sniffer_init(sniffer))
    {
        printf("Error: sniffer initialization!\n");
        exit(1);
    }

    // Start to capture and analyze packets;
    sniffer_sniff(sniffer);
}
