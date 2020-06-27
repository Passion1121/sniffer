#ifndef LINK_LAYER_H
#define LINK_LAYER_H

#include <pcap.h>
#include <string.h>

#define ETHER_ADDR_LEN 6
#define SIZE_ETHERNET 14

#define ETHERNET_TYPE_IP    0x0800
#define ETHERNET_TYPE_ARP   0x0806
#define ETHERNET_TYPE_IPV6  0x86DD
#define ETHERNET_TYPE_PPP   0x880B
#define ETHERNET_TYPE_PPPOE 0x8863

#define ETHERNET_DMAC 0b1
#define ETHERNET_SMAC 0b10
#define ETHERNET_TYPE 0b100
#define ETHERNET_ALL  0b111

struct ethernet{
    u_char ether_dmac[ETHER_ADDR_LEN];  //目的MAC
    u_char ether_smac[ETHER_ADDR_LEN];  //源MAC
    u_short ether_type;                 //网络层协议类型
};

struct pppoe{
    u_int32_t version;  //pppoe版本，为0x01
    u_int32_t type;     //pppoe类型，为0x01
    u_char code;        //Discovery和PPPoE会话中分别指定
    u_short session_id; //与以太网smac和dmac一起实际地定义了一个PPPoE会话
    u_short len;        //负载长度，不包括pppoe头部，单位为字节
};

// 解析帧头部，返回下一层位置指针
const u_char* unpack_ethernet(const u_char*, struct ethernet*);

// 解析帧头部类型转化成字符串
const char* get_ethernet_type_desc(struct ethernet*);

// 打印相关信息
void print_ethernet_header(struct ethernet*, u_int);

#endif
