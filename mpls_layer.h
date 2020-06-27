#ifndef MPLS_LAYER_H
#define MPLS_LAYER_H

#include <pcap.h>
#include <string.h>

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


void unpack_arp(const u_char*, struct arp*);

const char* get_arp_op_desc(struct arp*);

void print_arp(struct arp*, u_int);

#endif
