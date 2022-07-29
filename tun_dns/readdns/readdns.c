//
// Created by galaxnet on 22-7-28.
//
#include "readdns.h"

void read_dns(int tun_fd, char *tun_name) {
    unsigned char buffer2[PCKT_LEN];
    unsigned char *reader;
    struct RES_RECORD answers[20];
    int nread, stop;
    struct in_addr src_ip, dest_ip;
    struct sockaddr_in ans_ip;
    struct IPHeader *ip2;
    struct UdpHeader *udp2;
    struct DnsHeader *dns2;
    char *start;
    char token[64];

    // 读取dns response
    ip2 = (struct IPHeader *) buffer2;
    udp2 = (struct UdpHeader *) (buffer2 + sizeof(struct IPHeader));
    dns2 = (struct DnsHeader *) (buffer2 + sizeof(struct IPHeader) + sizeof(struct UdpHeader));

    // 将读取到的response存入buffer2
    nread = read(tun_fd, buffer2, sizeof(buffer2));
    if (nread < 0) {
        perror("Reading from interface");
    }

    if (ntohs(udp2->udph_srcport) != 53) {
        return;
    }

    start = (buffer2 + sizeof(struct IPHeader) + sizeof(struct UdpHeader) + sizeof(struct DnsHeader));

    src_ip.s_addr = ip2->iph_sourceip;
    dest_ip.s_addr = ip2->iph_destip;

    // read qustions
    // parse from qname.
    while (ntohs(dns2->QDCOUNT)) {
        unsigned char qlen = start[0];
        qlen = qlen & 0x3f;
        // qname terminate
        if (qlen == 0) {
            start++;
            break;
        }
        start++; // skip qlen.
        memcpy(token, start, qlen);
        token[qlen] = '\0';
        start += qlen;
    }

    // skip the type and class.
    // now pointer to the answer in rr format.
    start += 4;

    // read answers
    reader = start;
    for (int i = 0; i < ntohs(dns2->ANCOUNT); i++) {
        answers[i].rname = ReadName(reader, (unsigned char*)(dns2), &stop);
        reader = reader + 2; //假设都是压缩模式

        answers[i].answer = (struct DnsAnswer *) (reader);
        reader = reader + sizeof(struct DnsAnswer);
        if (ntohs(answers[i].answer->type) == 1) {  // if it is an ipv4 address
            answers[i].rdata = (unsigned char *) malloc(ntohs(answers[i].answer->length));
            for (int j = 0; j < ntohs(answers[i].answer->length); j++) {
                answers[i].rdata[j] = reader[j];
            }

            answers[i].rdata[ntohs(answers[i].answer->length)] = '\0';

        } else {
            answers[i].rdata = ReadName(reader, (unsigned char*)(dns2), &stop);
        }
        reader = reader + ntohs(answers[i].answer->length);
    }

    printf("Read %d bytes from device %s\n", nread, tun_name);
    printf("The response contains : \n");
    printf("Ip header source IP: %s\n", inet_ntoa(src_ip));
    printf("Ip header dest IP: %s\n", inet_ntoa(dest_ip));
    printf("Ip length: %d\n", ntohs(ip2->iph_len));
    printf("Udp header srcport: %d\n", ntohs(udp2->udph_srcport));
    printf("Udp header destport: %d\n", ntohs(udp2->udph_destport));
    printf("Udp header length: %d\n", ntohs(udp2->udph_len));
    printf("%d Questions. \n", ntohs(dns2->QDCOUNT));
    printf("%d Answers. \n", ntohs(dns2->ANCOUNT));

    // print answer_s
    printf("\n Answers Records: %d \n", ntohs(dns2->ANCOUNT));
    for (int i = 0; i < ntohs(dns2->ANCOUNT); i++) {
        printf("Name : %s\n", answers[i].rname);
        if (ntohs(answers[i].answer->type) == 1) { // IPV4 address
            long *p;
            p = (long *) answers[i].rdata;
            ans_ip.sin_addr.s_addr = (*p);
            printf("has IPV4 address : %s\n", inet_ntoa(ans_ip.sin_addr));
            free(answers[i].rdata);
        }
        if (ntohs(answers[i].answer->type) == 5) {
            printf("has alias name: %s\n", answers[i].rdata);
        }
        printf("\n");
    }
}
