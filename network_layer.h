#ifndef NETWORK_LAYER_H
#define NETWORK_LAYER_H

#include <pcap.h>
#include <string.h>


// IP
#define IP_PROTOCOL_ICMP    1
#define IP_PROTOCOL_TCP     6
#define IP_PROTOCOL_UDP     17
#define IP_PROTOCOL_IGMP    2
#define IP_PROTOCOL_OSPF    89
#define IP_PROTOCOL_GRE     47
#define IP_PROTOCOL_ESP     50

#define IP_HEAD_LEN     0b1
#define IP_TOTAL_LEN    0b10
#define IP_PROTOCOL     0b100
#define IP_SIP          0b1000
#define IP_DIP          0b10000
#define IP_ALL          0b11111
#define IP_IP           (IP_SIP | IP_DIP)

// ARP
#define ARP_REQ 1
#define ARP_RES 2
#define RARP_REQ 3
#define RARP_RES 4

#define ARP_OP   0b1
#define ARP_SMAC 0b10
#define ARP_SIP  0b100
#define ARP_DMAC 0b1000
#define ARP_DIP  0b10000
#define ARP_ALL  0b11111
#define ARP_MAC  (ARP_SMAC | ARP_DMAC)
#define ARP_IP   (ARP_SIP | ARP_DIP)

struct ip{
    u_char ip_vhl;          //前四位版本号，后四位首部长度，单位是4字节，首部长度最大 15x4=60(字节)
    u_char ip_tos;          //服务类型
    u_short ip_len;         //数据报长度，单位为字节
    u_short ip_id;          //标识
    u_short ip_off;         //标志(3)，偏移(13)
    u_char ip_ttl;          //ttl
    u_char ip_p;            //协议
    u_short ip_sum;         //首部校验和
    struct in_addr ip_src;  //ip源地址
    struct in_addr ip_dst;  //ip目的地址
};

struct arp{
    u_short ht;         //硬件类型
    u_short pt;         //协议类型
    u_char hl;          //硬件地址长度
    u_char pl;          //协议长度
    u_short op;         //操作类型
    u_char smac[6];     //源MAC地址
    u_char ip_src[4];   //源IP地址
    u_char dmac[6];     //目的MAC地址
    u_char ip_dst[4];   //目的IP地址
};


// IP
const u_char* unpack_ip(const u_char*, struct ip*);

const char* get_ip_proto_desc(struct ip*);

void print_ip(struct ip*, uint);

// ARP
void unpack_arp(const u_char*, struct arp*);

const char* get_arp_op_desc(struct arp*);

void print_arp(struct arp*, u_int);

#endif
