//
// Created by galaxnet on 22-7-28.
//

#ifndef DNS3_WRITETUN_H
#define DNS3_WRITETUN_H

#include "../utils/utils.h"

void writetun(char* hostname,char* src_ip,char* dest_ip,int tun_fd,char* tun_name);

#endif //DNS3_WRITETUN_H

