#include "network_layer.h"


// IP ------------------------------------ IP
const u_char* unpack_ip(const u_char* data, struct ip* ip_header)
{
    memcpy(ip_header, data, sizeof (struct ip));
    return (data + ((ip_header->ip_vhl) & 0x0f) * 4);
}

const char* get_ip_proto_desc(struct ip* ip_header)
{
    const char* desc = NULL;
    switch (ip_header->ip_p) {
    case IP_PROTOCOL_TCP:
        desc = "tcp";
        break;
    case IP_PROTOCOL_UDP:
        desc = "udp";
        break;
    case IP_PROTOCOL_ICMP:
        desc = "icmp";
        break;
    default:
        desc = "unknown";
    }
    return desc;
}

void print_ip(struct ip* ip_header, uint flags)
{
    printf("IP:\n");
    if (flags & IP_HEAD_LEN)
    {
        printf("IP header len: %d\n", ((ip_header->ip_vhl) & 0x0f) * 4);
    }
    if (flags & IP_TOTAL_LEN)
    {
        printf("IP total len: %d\n", htons(ip_header->ip_len));
    }
    if (flags & IP_PROTOCOL)
    {
        printf("IP protocol: %s\n", get_ip_proto_desc(ip_header));
    }
    if ((flags & IP_IP) == IP_IP)
    {
        printf("%s --> ", inet_ntoa(ip_header->ip_src));
        printf("%s\n", inet_ntoa(ip_header->ip_dst));
    }
    else
    {
        if (flags & IP_DIP)
        {
            printf("--> %s\n", inet_ntoa(ip_header->ip_dst));
        }
        if (flags & IP_SIP)
        {
            printf("%s -->\n", inet_ntoa(ip_header->ip_src));
        }
    }
}

// IP ------------------------------------ IP

// ARP ------------------------------------ ARP
void unpack_arp(const u_char* data, struct arp* arp_data)
{
    memcpy(arp_data, data, sizeof (struct arp));
}

const char* get_arp_op_desc(struct arp* arp_data)
{
    const char* desc = NULL;
    switch (htons(arp_data->op)) {
    case ARP_REQ:
        desc = "arp请求";
        break;
    case ARP_RES:
        desc = "arp回复";
        break;
    case RARP_REQ:
        desc = "rarp请求";
        break;
    case RARP_RES:
        desc = "rarp回复";
        break;
    default:
        desc = "unknown";
    }
    return desc;
}

void print_arp(struct arp* arp_data, u_int flags)
{
    printf("Arp:\n");
    if (flags & ARP_OP)
    {
        printf("Arp op type: %s\n", get_arp_op_desc(arp_data));
    }
    if ((flags & ARP_MAC) == ARP_MAC)
    {
        printf("%X %X %X %X %X %X --> %X %X %X %X %X %X\n",
               arp_data->smac[0], arp_data->smac[1], arp_data->smac[2],
               arp_data->smac[3], arp_data->smac[4], arp_data->smac[5],
               arp_data->dmac[0], arp_data->dmac[1], arp_data->dmac[2],
               arp_data->dmac[3], arp_data->dmac[4], arp_data->dmac[5]);
    }
    else
    {
        if (flags & ARP_DMAC)
        {
            printf("--> %X %X %X %X %X %X\n",
                   arp_data->dmac[0], arp_data->dmac[1], arp_data->dmac[2],
                   arp_data->dmac[3], arp_data->dmac[4], arp_data->dmac[5]);
        }
        if (flags & ARP_SMAC)
        {
            printf("%X %X %X %X %X %X -->\n",
                   arp_data->smac[0], arp_data->smac[1], arp_data->smac[2],
                   arp_data->smac[3], arp_data->smac[4], arp_data->smac[5]);
        }
    }
    if ((flags & ARP_IP) == ARP_IP)
    {
        printf("%d.%d.%d.%d --> %d.%d.%d.%d\n",
               arp_data->ip_src[0], arp_data->ip_src[1],
               arp_data->ip_src[2], arp_data->ip_src[3],
               arp_data->ip_dst[0], arp_data->ip_dst[1],
               arp_data->ip_dst[2], arp_data->ip_dst[3]);
    }
    else
    {
        if (flags & ARP_DIP)
        {
            printf("--> %d.%d.%d.%d\n",
                   arp_data->ip_dst[0], arp_data->ip_dst[1],
                   arp_data->ip_dst[2], arp_data->ip_dst[3]);
        }
        if (flags & ARP_SIP)
        {
            printf("%d.%d.%d.%d -->\n",
                   arp_data->ip_src[0], arp_data->ip_src[1],
                   arp_data->ip_src[2], arp_data->ip_src[3]);
        }
    }
}

// ARP ------------------------------------ ARP
