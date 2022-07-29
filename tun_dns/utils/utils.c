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

// signal handler
void sighandler(int signum) {
    printf("\n Caught signal %d,exit the program...\n",signum);
    exit(1);
}

