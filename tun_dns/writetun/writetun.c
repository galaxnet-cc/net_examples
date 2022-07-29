//
// Created by galaxnet on 22-7-28.
//
#include "writetun.h"

void writetun(char *hostname, char *src_ip, char *dest_ip, int tun_fd, char *tun_name) {
    int nwrite;
    unsigned char buffer[PCKT_LEN];
    unsigned char name[512];

    struct IPHeader *ip = (struct IPHeader *) buffer;
    struct UdpHeader *udp = (struct UdpHeader *) (buffer + sizeof(struct IPHeader));
    struct DnsHeader *dns = (struct DnsHeader *) (buffer + sizeof(struct IPHeader) + sizeof(struct UdpHeader));
    char *qname = (buffer + sizeof(struct IPHeader) + sizeof(struct UdpHeader) + sizeof(struct DnsHeader));
    memset(buffer, 0, PCKT_LEN);
    strcpy(name, hostname);
    QnameConvert(qname, name);
    int length = strlen(qname) + 1;
    struct DnsQuestion *dnsq = (struct DnsQuestion *) (qname + length);
    unsigned short int packetLength = (sizeof(struct IPHeader) + sizeof(struct UdpHeader) + sizeof(struct DnsHeader) +
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

    nwrite = write(tun_fd, buffer, sizeof(buffer));
    if (nwrite < 0) {
        perror("Writing from interface");
    }
    sleep(1);

    printf("Write %d bytes from device %s\n", nwrite, tun_name);

}
