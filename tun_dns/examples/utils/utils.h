//
// Created by galaxnet on 22-7-25.
//

#ifndef DNS_UTILS_H
#define DNS_UTILS_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>

//#define PCKT_LEN 256
#define PCKT_LEN 1500

struct IPHeader {
    unsigned char iph_ihl:4, iph_ver:4;
    unsigned char iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    //unsigned char      iph_flag;
    unsigned short int iph_offset;
    unsigned char iph_ttl;
    unsigned char iph_protocol;
    unsigned short int iph_chksum;
    unsigned int iph_sourceip;
    unsigned int iph_destip;
};

struct UdpHeader {
    unsigned short int udph_srcport;
    unsigned short int udph_destport;
    unsigned short int udph_len;
    unsigned short int udph_chksum;
};

struct DnsHeader {
    unsigned short int query_id;
    unsigned short int flags;
    unsigned short int QDCOUNT;
    unsigned short int ANCOUNT;
    unsigned short int NSCOUNT;
    unsigned short int ARCOUNT;
};


struct DnsQuestion {
    unsigned short int qtype;
    unsigned short int qclass;
};
#pragma pack(push, 1)
struct DnsAnswer {
    unsigned short int type;
    unsigned short int class;
    unsigned int ttl;
    unsigned short int length;
};
#pragma pack(pop)

struct RES_RECORD {
    unsigned char* rname;
    struct DnsAnswer *answer;
    unsigned char *rdata;
};


int tun_alloc(char *dev, int flags);

void writetuntest();

void readtun();

unsigned short csum(unsigned short *buf, int nwords);

void QnameConvert(unsigned char *qname, unsigned char *host);

void testQnameConvert();

u_char* ReadName(unsigned char* reader,unsigned char* buffer,int* count);

u_char* ReadName2(unsigned char* reader,unsigned char* buffer,int* count);

#endif //DNS_UTILS_H
