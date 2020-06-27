#ifndef TRANSPORT_LAYER_H
#define TRANSPORT_LAYER_H

#include <pcap.h>
#include <string.h>

#define TCP_FLAGS_FIN  0x01
#define TCP_FLAGS_SYN  0x02
#define TCP_FLAGS_RST  0x04
#define TCP_FLAGS_PSH  0x08
#define TCP_FLAGS_ACK  0x10
#define TCP_FLAGS_URG  0x20

#define TCP_SPORT   0b1
#define TCP_DPORT   0b10
#define TCP_SN      0b100
#define TCP_AN      0b1000
#define TCP_FLAGS   0b10000
#define TCP_PORT    (TCP_SPORT | TCP_DPORT)

struct tcp{
    u_short tcp_sport;      //源端口号
    u_short tcp_dport;      //目的端口号
    unsigned int tcp_seq;   //序号
    unsigned int tcp_ack;   //确认号
    u_char tcp_len_rsvd;    //首部长度(4)和保留(4)
    u_char tcp_flags;       //标志字段
    u_short tcp_win;        //接收窗口大小
    u_short tcp_sum;        //校验和
    u_short tcp_urp;        //紧急数据指针
};

struct udp{
    u_short udp_sport;  //源端口
    u_short udp_dport;  //目的端口
    u_short udp_len;    //首部加数据的长度，单位字节
    u_short udp_sum;    //校验和
};

const u_char* unpack_tcp(const u_char*, struct tcp*);

void print_tcp(struct tcp*, uint);

#endif
