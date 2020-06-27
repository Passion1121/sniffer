#include "mpls_layer.h"


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
