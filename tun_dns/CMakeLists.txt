cmake_minimum_required(VERSION 3.16)
project(tun_app C)

set(CMAKE_C_STANDARD 99)

add_executable(tun_app main.c utils/utils.c utils/utils.h tun/tun.c tun/tun.h
            writetun/writetun.c writetun/writetun.h readdns/readdns.h readdns/readdns.c
        )

target_link_libraries(tun_app "-lpthread")


# reference examples
project(xtun)

add_executable(xtun examples/xtun/xtun.c)

target_link_libraries(xtun "-lpthread")

project(dns)

add_executable(dns examples/dns/dns.c)

project(dns2)

add_executable(dns2 examples/dns2/dns2.c)

project(dns3)

add_executable(dns3 examples/dns3/dns3.c)