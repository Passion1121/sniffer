#include "link_layer.h"

const u_char* unpack_ethernet(const u_char* data, struct ethernet* ether_header)
{
    memcpy(ether_header, data, sizeof (struct ethernet));
    return (data + SIZE_ETHERNET);
}

const char* get_ethernet_type_desc(struct ethernet* ether_header)
{
    const char* desc = NULL;
    switch (htons(ether_header->ether_type)) {
    case ETHERNET_TYPE_IP:
        desc = "ip";
        break;
    case ETHERNET_TYPE_ARP:
        desc = "arp";
        break;
    case ETHERNET_TYPE_IPV6:
        desc = "ipv6";
        break;
    case ETHERNET_TYPE_PPP:
        desc = "ppp";
        break;
    case ETHERNET_TYPE_PPPOE:
        desc = "pppoe";
        break;
    default:
        desc = "unknown";
    }
    return desc;
}

void print_ethernet_header(struct ethernet* ether_header, u_int flags)
{
    printf("Ethernet:\n");
    if ((flags & (ETHERNET_DMAC | ETHERNET_SMAC)) == (ETHERNET_DMAC | ETHERNET_SMAC))
    {
        printf("%X %X %X %X %X %X --> %X %X %X %X %X %X\n",
               ether_header->ether_smac[0], ether_header->ether_smac[1], ether_header->ether_smac[2],
               ether_header->ether_smac[3], ether_header->ether_smac[4], ether_header->ether_smac[5],
               ether_header->ether_dmac[0], ether_header->ether_dmac[1], ether_header->ether_dmac[2],
               ether_header->ether_dmac[3], ether_header->ether_dmac[4], ether_header->ether_dmac[5]);
    }
    else
    {
        if (flags & ETHERNET_DMAC)
        {
            printf("--> %X %X %X %X %X %X\n",
                   ether_header->ether_dmac[0], ether_header->ether_dmac[1], ether_header->ether_dmac[2],
                   ether_header->ether_dmac[3], ether_header->ether_dmac[4], ether_header->ether_dmac[5]);
        }
        if (flags & ETHERNET_SMAC)
        {
            printf("%X %X %X %X %X %X -->\n",
                   ether_header->ether_smac[0], ether_header->ether_smac[1], ether_header->ether_smac[2],
                   ether_header->ether_smac[3], ether_header->ether_smac[4], ether_header->ether_smac[5]);
        }
    }
    if (flags & ETHERNET_TYPE)
    {
        printf("Ethernet type: %s\n", get_ethernet_type_desc(ether_header));
    }
}
