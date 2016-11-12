#include <stdio.h>
#include <stdlib.h>

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <err.h>


#ifdef __linux__            // for Linux
#include <netinet/ether.h>
#include <time.h>
#include <pcap/pcap.h>
#endif

#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE (256)
#endif

#define SIZE_ETHERNET (14)       // offset of Ethernet header to L3 protocol
#define SIZE_UDP        8               /* length of UDP header */


struct udphdr {
        u_int16_t uh_sport;  /* source port */
        u_int16_t uh_dport;  /* destination port */
        u_int16_t uh_ulen;   /* udp length */
        u_int16_t uh_sum;    /* udp checksum */
    };


void analyzePacket(const u_char *packet, const ip *my_ip, u_int size_ip);

int n = 0;
int i = 0;

void mypcap_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ip *my_ip;               // pointer to the beginning of IP header
    struct ether_header *eptr;      // pointer to the beginning of Ethernet header
    const struct tcphdr *my_tcp;    // pointer to the beginning of TCP header
    u_int size_ip;

    n++;
    // print the packet header data
    printf("Packet no. %d:\n",n);
    printf("\tLength %d, received at %s",header->len,ctime((const time_t*)&header->ts.tv_sec));
    //    printf("Ethernet address length is %d\n",ETHER_HDR_LEN);

    // read the Ethernet header
    eptr = (struct ether_header *) packet;
    printf("\tSource MAC: %s\n",ether_ntoa((const struct ether_addr *)&eptr->ether_shost)) ;
    printf("\tDestination MAC: %s\n",ether_ntoa((const struct ether_addr *)&eptr->ether_dhost)) ;

    if (ntohs(eptr->ether_type) == ETHERTYPE_IP) {               // see /usr/include/net/ethernet.h for types
        printf("\tEthernet type is  0x%x, i.e. IP packet \n", ntohs(eptr->ether_type));
        my_ip = (struct ip *) (packet + SIZE_ETHERNET);        // skip Ethernet header
        size_ip = my_ip->ip_hl * 4;                           // length of IP header

        printf("\tIP: id 0x%x, hlen %d bytes, version %d, total length %d bytes, TTL %d\n", ntohs(my_ip->ip_id),
               size_ip, my_ip->ip_v, ntohs(my_ip->ip_len), my_ip->ip_ttl);
        printf("\tIP src = %s, ", inet_ntoa(my_ip->ip_src));
        printf("IP dst = %s", inet_ntoa(my_ip->ip_dst));

        if (my_ip->ip_p == 17) {
            analyzePacket(packet, my_ip, size_ip);
        }
    }
}

void analyzePacket(const u_char *packet, const ip *my_ip, u_int size_ip) {
    const struct udphdr *my_udp;    // pointer to the beginning of UDP header
    const char *payload;
    int size_payload;


    printf(", protocol UDP (%d)\n", my_ip->ip_p);
    my_udp = (struct udphdr *) (packet + SIZE_ETHERNET + size_ip); // pointer to the UDP header
    printf("\tSrc port = %d, dst port = %d, length %d\n", ntohs(my_udp->uh_sport), ntohs(my_udp->uh_dport), ntohs(my_udp->uh_ulen));

    payload = (char *) (packet + SIZE_ETHERNET + size_ip + SIZE_UDP);
    size_payload = ntohs(my_ip->ip_len) - (size_ip + SIZE_UDP);

    if (size_payload > ntohs(my_udp->uh_ulen))
        size_payload = ntohs(my_udp->uh_ulen);


    if (size_payload > 0) {
        printf("   Payload (%d bytes):\n", size_payload);

        for (i = 0; i < size_payload; i++) {
            printf("%02x:", payload[i]);

        }
        printf("\n");
        printf("type: %02x", payload[242]);
        printf("\n\n");
    }
}


int main (int argc, char * argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];  // constant defined in pcap.h
    pcap_t *handle;                 // packet capture handle
    char *dev;                      // input device
    struct in_addr a,b;
    bpf_u_int32 netaddr;            // network address configured at the input device
    bpf_u_int32 mask;               // network mask of the input device
    struct bpf_program fp;          // the compiled filter

    if (argc != 2)
        errx(1,"Usage: %s <pcap filter>", argv[0]);

    // open the device to sniff data
    if ((dev = pcap_lookupdev(errbuf)) == NULL)
        err(1,"Can't open input device");

    // get IP address and mask of the sniffing interface
    if (pcap_lookupnet(dev,&netaddr,&mask,errbuf) == -1)
        err(1,"pcap_lookupnet() failed");

    a.s_addr=netaddr;
    printf("Opening interface \"%s\" with net address %s,",dev,inet_ntoa(a));
    b.s_addr=mask;
    printf("mask %s for listening...\n",inet_ntoa(b));

    // open the interface for live sniffing
    if ((handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf)) == NULL)
        err(1,"pcap_open_live() failed");

    // compile the filter
    if (pcap_compile(handle,&fp,argv[1],0,netaddr) == -1)
        err(1,"pcap_compile() failed");

    // set the filter to the packet capture handle
    if (pcap_setfilter(handle,&fp) == -1)
        err(1,"pcap_setfilter() failed");

    // read packets from the interface in the infinite loop (count == -1)
    // incoming packets are processed by function mypcap_handler()
    if (pcap_loop(handle,-1,mypcap_handler,NULL) == -1)
        err(1,"pcap_loop() failed");

    // close the capture device and deallocate resources
    pcap_close(handle);
    return 0;
}