//
// Created by galaxnet on 22-7-25.
//

#include "utils.h"


int tun_alloc(char *dev, int flags) {

    struct ifreq ifr;
    int fd, err;
    char *clonedev = "/dev/net/tun";


    if ((fd = open(clonedev, O_RDWR)) < 0) {
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = flags;

    if (*dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
        close(fd);
        return err;
    }

    strcpy(dev, ifr.ifr_name);

    return fd;
}


void readtun() {
    int tun_fd, nread;
    unsigned char buffer[2000];
    char tun_name[IFNAMSIZ];

    /* Connect to the device */
    strcpy(tun_name, "tun77");
    tun_fd = tun_alloc(tun_name, IFF_TUN | IFF_NO_PI);  /* tun interface */

    if (tun_fd < 0) {
        perror("Allocating interface");
        exit(1);
    }

    /* Now read data coming from the kernel */
    while (1) {
        /* Note that "buffer" should be at least the MTU size of the interface, eg 1500 bytes */
        nread = read(tun_fd, buffer, sizeof(buffer));
        if (nread < 0) {
            perror("Reading from interface");
            close(tun_fd);
            exit(1);
        }

        /* Do whatever with the data */
        printf("Read %d bytes from device %s\n", nread, tun_name);
    }
}

// reference:
// https://raw.githubusercontent.com/Batyi/Computer-and-Internet-Security-Labs/d5ced135b1bdc58d19b26267162a934c6da42bdf/19.%20Remote%20DNS%20Attack%20(Kaminsky)/code/udp.c
// https://github.com/Batyi/Computer-and-Internet-Security-Labs/blob/d5ced135b1bdc58d19b26267162a934c6da42bdf/19.%20Remote%20DNS%20Attack%20(Kaminsky)/code/udp.c
void writetuntest() {
    int tun_fd, nwrite;//nread;
    // TODO: change to default ethernet MTU 1500.
    unsigned char buffer[PCKT_LEN];
//    unsigned char buffer2[PCKT_LEN];

    // TODO:
    //  1. Should parse after read ok from tun.
    //  2. use ip total len to move to udp header.
    //  3. check ip protocol equals UDP.
    //  4. check udp src port is DNS server well-known port.
    struct IPHeader *ip = (struct IPHeader *) buffer;
    struct UdpHeader *udp = (struct UdpHeader *) (buffer + sizeof(struct IPHeader));
    struct DnsHeader *dns = (struct DnsHeader *) (buffer + sizeof(struct IPHeader) + sizeof(struct UdpHeader));
    char *qname = (buffer + sizeof(struct IPHeader) + sizeof(struct UdpHeader) + sizeof(struct DnsHeader));
    // TODO: no magic number. (refer to DNS rfc decide length.)
    unsigned char name[512];

    memset(buffer, 0, PCKT_LEN);

    strcpy(name, "www.qq.com");
    QnameConvert(qname, name);

    // TODO: split local variable def and assignment.
    int length = strlen(qname) + 1;
    struct DnsQuestion *dnsq = (struct DnsQuestion *) (qname + length);

    // TODO: split to 2 functions, 1 for sending dns request. 1 for proc reply.
    // sendDns(tun_fd, host_name, dns server ip)
    // recvDns(tun_fd)
    unsigned short int packetLength = (sizeof(struct IPHeader) + sizeof(struct UdpHeader) + sizeof(struct DnsHeader) +
                                       length +
                                       sizeof(struct DnsQuestion));

    // ip header
    ip->iph_ihl = 5;
    ip->iph_ver = 4;
    ip->iph_len = htons(packetLength);
    ip->iph_sourceip = inet_addr("100.100.100.1");
    ip->iph_destip = inet_addr("114.114.114.114");
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

    // dns question
    dnsq->qtype = htons(1);
    dnsq->qclass = htons(1);

    // TODO: encap to a function
    // init_tun(tun_name)
    // return a tun fd.
    char tun_name[IFNAMSIZ];
    strcpy(tun_name, "tun77");
    tun_fd = tun_alloc(tun_name, IFF_TUN | IFF_NO_PI);
    if (tun_fd < 0) {
        perror("Allocating interface");
        exit(1);
    }

    // 设置tun接口up
    char command1[50], command2[100], command3[100], command4[50];
    strcpy(command1, "ip link set tun77 up"); // 使用sprintf
    strcpy(command2, "ip addr add 100.100.100.100/32 dev tun77");
    strcpy(command3, "iptables -t nat -A POSTROUTING -d 114.114.114.114 -s 100.100.100.1 -j MASQUERADE");
    strcpy(command4, "ip route add 100.100.100.1/32 dev tun77");
    system(command1);
    system(command2);
    system(command3);
    system(command4);


    unsigned char buffer2[PCKT_LEN];
    unsigned char *reader;
    struct RES_RECORD answers[20];
    int nread, stop;
    struct in_addr src_ip, dest_ip;
    struct sockaddr_in ans_ip;
    // 读取dns response
    struct IPHeader *ip2 = (struct IPHeader *) buffer2;
    struct UdpHeader *udp2 = (struct UdpHeader *) (buffer2 + sizeof(struct IPHeader));
    struct DnsHeader *dns2 = (struct DnsHeader *) (buffer2 + sizeof(struct IPHeader) + sizeof(struct UdpHeader));


    for (;;) {
        nwrite = write(tun_fd, buffer, sizeof(buffer));
        if (nwrite < 0) {
            perror("Writing from interface");
        }
        sleep(1);

        printf("Write %d bytes from device %s\n", nwrite, tun_name);


        // 将读取到的response存入buffer2
        nread = read(tun_fd, buffer2, sizeof(buffer2));
        if (nread < 0) {
            perror("Reading from interface");
        }

        printf("Read %d bytes from device %s\n", nread, tun_name);

        if (ntohs(udp2->udph_srcport) != 53) {
            continue;
        }

        char *start = (buffer2 + sizeof(struct IPHeader) + sizeof(struct UdpHeader) + sizeof(struct DnsHeader));


        src_ip.s_addr = ip2->iph_sourceip;
        dest_ip.s_addr = ip2->iph_destip;
        printf("The response contains : \n");
        printf("Ip header source IP: %s\n",inet_ntoa(src_ip));
        printf("Ip header dest IP: %s\n",inet_ntoa(dest_ip));
        printf("Ip length: %d\n",ntohs(ip2->iph_len));
        printf("Udp header srcport: %d\n",ntohs(udp2->udph_srcport));
        printf("Udp header destport: %d\n",ntohs(udp2->udph_destport));
        printf("Udp header length: %d\n",ntohs(udp2->udph_len));
        printf("%d Questions. \n", ntohs(dns2->QDCOUNT));
        printf("%d Answers. \n", ntohs(dns2->ANCOUNT));

        // read qustions
        char token[64];
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
            printf("qlen %d, token %s\n", qlen, token);
            start += qlen;
        }

        // skip the type and class.
        // now pointer to the answer in rr format.
        start += 4;

        // read answers
//        stop = 0;
        reader = start;
        for(int i = 0; i < ntohs(dns2->ANCOUNT) ; i++) {
            answers[i].rname = ReadName(reader, start, &stop);
            reader = reader + 2; //假设都是压缩模式

            answers[i].answer = (struct DnsAnswer*)(reader);
            reader = reader + sizeof(struct DnsAnswer);
            if (ntohs(answers[i].answer->type) == 1) {  // if it is an ipv4 address
                answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].answer->length));
                for(int j = 0; j < ntohs(answers[i].answer->length); j++) {
                    answers[i].rdata[j] = reader[j];
                }

                answers[i].rdata[ntohs(answers[i].answer->length)] = '\0';

            } else {
                answers[i].rdata = ReadName(reader,start,&stop);
            }
            reader = reader + ntohs(answers[i].answer->length);
        }

        // print answer_s
        printf("\n Answers Records: %d \n",ntohs(dns2->ANCOUNT));
        for(int i = 0; i < ntohs(dns2->ANCOUNT); i++) {
            printf("Name : %s\n",answers[i].rname);
            if (ntohs(answers[i].answer->type) == 1) { // IPV4 address
                long *p;
                p = (long*)answers[i].rdata;
                ans_ip.sin_addr.s_addr = (*p);
                printf("has IPV4 address : %s\n",inet_ntoa(ans_ip.sin_addr));
                free(answers[i].rdata);
            }
            if(ntohs(answers[i].answer->type) == 5) {
                printf("has alias name: %s\n",answers[i].rdata);
            }
            printf("\n");
        }

    }
}

unsigned short csum(unsigned short *buf, int nwords) {
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short) (~sum);
}

void QnameConvert(unsigned char *qname, unsigned char *host) {
    int lock = 0, i;
    strcat((char *) host, ".");

    for (i = 0; i < strlen((char *) host); i++) {
        if (host[i] == '.') {
            *qname++ = i - lock;
            for (; lock < i; lock++) {
                *qname++ = host[lock];
            }
            lock++; //or lock=i+1;
        }
    }
    *qname++ = '\0';
}


u_char *ReadName(unsigned char *reader, unsigned char *buffer, int *count) {
    unsigned char *name;
    unsigned int p = 0, jumped = 0, offset;
    int i, j;

    name = (unsigned char *) malloc(256);

    name[0] = '\0';

    if (*reader & 0xc0) {
        jumped = 1;
        offset = ntohs(*(unsigned short *)(reader));
        // clear compress 2 bits.
        offset = offset & 0x3fff; // 00111111 11111111
        reader = buffer + offset;
    }

    //read the names in 3www6google3com format
    while (*reader != 0) {
        name[p++] = *reader;
        reader = reader + 1;
    }
    name[p] = '\0'; //string complete

    //now convert 3www6google3com0 to www.google.com
    for (i = 0; i < (int) strlen((const char *) name); i++) {
        p = name[i];
        for (j = 0; j < (int) p; j++) {
            name[i] = name[i + 1];
            i = i + 1;
        }
        name[i] = '.';
    }
    name[i - 1] = '\0'; //remove the last dot
    return name;
}

u_char* ReadName2(unsigned char* reader,unsigned char* buffer,int* count)
{
    unsigned char *name;
    unsigned int p=0,jumped=0,offset;
    int i , j;

    *count = 1;
    name = (unsigned char*)malloc(256);

    name[0]='\0';

    //read the names in 3www6google3com format
    while(*reader!=0)
    {
        if(*reader>=192)
        {
            offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
            reader = buffer + offset - 1;
            jumped = 1; //we have jumped to another location so counting wont go up!
        }
        else
        {
            name[p++]=*reader;
        }

        reader = reader+1;

        if(jumped==0)
        {
            *count = *count + 1; //if we havent jumped to another location then we can count up
        }
    }

    name[p]='\0'; //string complete
    if(jumped==1)
    {
        *count = *count + 1; //number of steps we actually moved forward in the packet
    }

    //now convert 3www6google3com0 to www.google.com
    for(i=0;i<(int)strlen((const char*)name);i++)
    {
        p=name[i];
        for(j=0;j<(int)p;j++)
        {
            name[i]=name[i+1];
            i=i+1;
        }
        name[i]='.';
    }
    name[i-1]='\0'; //remove the last dot
    return name;
}
