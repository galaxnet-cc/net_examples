//
// Created by galaxnet on 22-7-28.
//
#include "tun.h"

int init_tun(char* name,char* tun_ip,char* dest_ip,char* snat_ip) {
    char tun_name[IFNAMSIZ];
    int tun_fd;
    char command1[50],command2[100],command3[100],command4[50];

    strcpy(tun_name,name);
    tun_fd = tun_alloc(tun_name,IFF_TUN | IFF_NO_PI);
    if (tun_fd < 0) {
        perror("Allocating interface");
        exit(1);
    }

    // tun config
    sprintf(command1,"ip link set %s up",tun_name);
    sprintf(command2,"ip addr add %s dev %s",tun_ip,tun_name);
    sprintf(command3,"iptables -t nat -A POSTROUTING -d %s -s %s -j MASQUERADE",dest_ip,snat_ip);
    sprintf(command4,"ip route add %s dev %s",snat_ip,tun_name);

    system(command1);
    system(command2);
    system(command3);
    system(command4);

    return tun_fd;
}