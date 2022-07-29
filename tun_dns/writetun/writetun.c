//
// Created by galaxnet on 22-7-28.
//
#include "writetun.h"

void writetun(char *hostname, char *src_ip, char *dest_ip, int tun_fd, char *tun_name) {
    int nwrite,length;
    unsigned char buffer[PCKT_LEN];
    unsigned char name[512];
    unsigned short int packetLength;
    char* qname;
    struct IPHeader *ip;
    struct UdpHeader *udp;
    struct DnsHeader *dns;
    struct DnsQuestion *dnsq;

    ip = (struct IPHeader *) buffer;
    udp = (struct UdpHeader *) (buffer + sizeof(struct IPHeader));
    dns = (struct DnsHeader *) (buffer + sizeof(struct IPHeader) + sizeof(struct UdpHeader));
    qname = (buffer + sizeof(struct IPHeader) + sizeof(struct UdpHeader) + sizeof(struct DnsHeader));
    memset(buffer, 0, PCKT_LEN);
    strcpy(name, hostname);
    QnameConvert(qname, name);
    length = strlen(qname) + 1;
    dnsq = (struct DnsQuestion *) (qname + length);
    packetLength = (sizeof(struct IPHeader) + sizeof(struct UdpHeader) + sizeof(struct DnsHeader) +
                                       length +
                                       sizeof(struct DnsQuestion));
    // ip header
    ip->iph_ihl = 5;
    ip->iph_ver = 4;
    ip->iph_len = htons(packetLength);
    ip->iph_sourceip = inet_addr(src_ip);
    ip->iph_destip = inet_addr(dest_ip);
    ip->iph_ident = htons(rand());
    ip->iph_ttl = 110;
    ip->iph_protocol = 17;
    ip->iph_chksum = csum((unsigned short *) buffer, sizeof(struct IPHeader));

    // udp header
    udp->udph_srcport = htons(33333);
    udp->udph_destport = htons(53);
    udp->udph_len = htons(sizeof(struct UdpHeader) + sizeof(struct DnsHeader) + length + sizeof(struct DnsQuestion));
    udp->udph_chksum = 0;

    // dns header
    dns->flags = htons(0x0100);
    dns->ANCOUNT = htons(0);
    dns->QDCOUNT = htons(1);
    dns->NSCOUNT = htons(0);
    dns->ARCOUNT = htons(0);

    //dns question
    dnsq->qtype = htons(1);
    dnsq->qclass = htons(1);

    nwrite = write(tun_fd, buffer, 1500);
    if (nwrite < 0) {
        perror("Writing from interface");
    }

    printf("Write %d bytes from device %s\n", nwrite, tun_name);

}
