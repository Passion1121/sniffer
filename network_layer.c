#include "network_layer.h"


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
