#include <stdio.h>
#include <signal.h>
#include "writetun/writetun.h"
#include "tun/tun.h"
#include "readdns/readdns.h"
#include "utils/utils.h"

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s [dns server ip] [hostname]\n",argv[0]);
        return 1;
    }
    int tun_fd;
    unsigned char* dns_server = argv[1];
    unsigned char* hostname = argv[2];
    unsigned char tun_name[128],tun_ip[128],dest_ip[128],snat_ip[128],src_ip[128];
    strcpy(tun_name,"tun88");
    strcpy(tun_ip,"100.100.100.100/32");
    strcpy(src_ip,"100.100.100.1");
    strcpy(snat_ip,"100.100.100.1");

    // ctrl+c to exit
    signal(SIGINT,sighandler);

    tun_fd = init_tun(tun_name,tun_ip,dns_server,snat_ip);

    for(;;) {
        writetun(hostname,src_ip,dns_server,tun_fd,tun_name);
        read_dns(tun_fd,tun_name);
        sleep(1);
    }

}

