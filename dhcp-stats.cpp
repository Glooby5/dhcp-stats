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
#include <map>
#include <string>
#include <vector>
#include <cstring>
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>

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

using namespace std;

namespace std {
    template<typename T>
    std::string to_string(const T &n) {
        std::ostringstream s;
        s << n;
        return s.str();
    }
}

struct udphdr {
    u_int16_t uh_sport;  /* source port */
    u_int16_t uh_dport;  /* destination port */
    u_int16_t uh_ulen;   /* udp length */
    u_int16_t uh_sum;    /* udp checksum */
};

struct device {
    string address;
};

struct network {
    string address;
    int prefix;
    string bits;
    std::vector<device> devices;
};


void analyzePacket(const u_char *packet, const ip *my_ip, u_int size_ip);

void printStats();

bool hasDeviceInNetwork(string deviceIp, network &network);

void requestAck(const ip *my_ip);

int n = 0;
int i = 0;
std::vector<network> networks;


bool isInNetwork(string device, string network, int prefix)
{
    for (int i = 0; i < prefix; i++) {
        if (device[i] != network[i]) {
            return false;
        }
    }

    return true;
}

vector<string> split(string input,const char* delimeter)
{
    char data[input.length() + 1];
    memcpy(data, input.c_str(), input.length() + 1);
    char* token = strtok(data, delimeter);
    vector<string> result;

    while(token != NULL)
    {
        result.push_back(token);
        token = strtok(NULL,delimeter);
    }

    return result;
}

string intToStringBits(int number)
{
    string binary  ("");
    int mask = 1;

    for (int i = 0; i < 8; i++) {
        if ((mask & number) >= 1) {
            binary = "1" + binary;
        } else {
            binary = "0" + binary;
        }

        mask <<= 1;
    }

    return binary;
}

string ipToStringBits(string input)
{
    vector<string> octets = split(input, ".");
    string ipBytes ("");

    for (auto &i : octets) {
        int number = std::stoi(i);
        string bits = intToStringBits(number);
        ipBytes.append(bits);
    }

    return ipBytes;
}

void mypcap_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ip *my_ip;               // pointer to the beginning of IP header
    struct ether_header *eptr;      // pointer to the beginning of Ethernet header
    const struct tcphdr *my_tcp;    // pointer to the beginning of TCP header
    u_int size_ip;

    n++;

    // read the Ethernet header
    eptr = (struct ether_header *) packet;

    if (ntohs(eptr->ether_type) == ETHERTYPE_IP) {               // see /usr/include/net/ethernet.h for types
        my_ip = (struct ip *) (packet + SIZE_ETHERNET);        // skip Ethernet header
        size_ip = my_ip->ip_hl * 4;                           // length of IP header

        if (my_ip->ip_p == 17) {
            analyzePacket(packet, my_ip, size_ip);
        }
    }
}

void analyzePacket(const u_char *packet, const ip *my_ip, u_int size_ip) {
    const struct udphdr *my_udp;
    const char *payload;
    int size_payload;

    my_udp = (struct udphdr *) (packet + SIZE_ETHERNET + size_ip);
    payload = (char *) (packet + SIZE_ETHERNET + size_ip + SIZE_UDP);
    size_payload = ntohs(my_ip->ip_len) - (size_ip + SIZE_UDP);

    if (size_payload > ntohs(my_udp->uh_ulen)) {
        size_payload = ntohs(my_udp->uh_ulen);
    }

    if (!size_payload) {
        return;
    }

    char type = payload[242];

    if (type == 5) {
        requestAck(my_ip);
    }

    printStats();
}

void requestAck(const ip *my_ip) {
    network *actual;
    string deviceIp = inet_ntoa(my_ip->ip_dst);
    string deviceBits = ipToStringBits(deviceIp);

    for ( auto &i : networks ) {
        if (!isInNetwork(deviceBits, i.bits, i.prefix)) {
            continue;
        }

        bool found = hasDeviceInNetwork(deviceIp, i);

        if (!found) {
            device newDevice;
            newDevice.address = deviceIp;

            i.devices.push_back(newDevice);
        }
    }
}

bool hasDeviceInNetwork(string deviceIp, network & network) {
    for (auto &networkDevice : network.devices) {
        if (networkDevice.address == deviceIp) {
            return true;
        }
    }

    return false;
}

void printStats() {
    cout << endl << "################################################################################" << endl;

    for ( auto &network : networks ) {
        cout << network.address << "/" << network.prefix << endl;

        for (auto &networkDevice : network.devices) {
            cout << networkDevice.address << endl;
        }
    }

    cout  << "################################################################################" << endl << endl;
}


int main (int argc, char * argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];  // constant defined in pcap.h
    pcap_t *handle;                 // packet capture handle
    char *dev;                      // input device
    struct in_addr a,b;
    bpf_u_int32 netaddr;            // network network configured at the input device
    bpf_u_int32 mask;               // network mask of the input device
    struct bpf_program fp;          // the compiled filter

    network firstAddress;
    firstAddress.address = "192.168.1.0";
    firstAddress.prefix = 24;
    firstAddress.bits = ipToStringBits(firstAddress.address);
    networks.push_back(firstAddress);


    string deviceBits = ipToStringBits("192.168.2.6");

    if (isInNetwork(deviceBits, firstAddress.bits, firstAddress.prefix)) {
        cout << "stejna" << std::endl;
    } else {
        cout << "nestejna" << std::endl;
    }

    // open the device to sniff data
    if ((dev = pcap_lookupdev(errbuf)) == NULL)
        err(1,"Can't open input device");

    // get IP network and mask of the sniffing interface
    if (pcap_lookupnet(dev,&netaddr,&mask,errbuf) == -1)
        err(1,"pcap_lookupnet() failed");

    a.s_addr=netaddr;
    printf("Opening interface \"%s\" with net network %s,",dev,inet_ntoa(a));
    b.s_addr=mask;
    printf("mask %s for listening...\n",inet_ntoa(b));

    // open the interface for live sniffing
    if ((handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf)) == NULL)
        err(1,"pcap_open_live() failed");

    // compile the filter
    if (pcap_compile(handle,&fp,"port 67",0,netaddr) == -1)
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