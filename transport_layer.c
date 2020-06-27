#include "transport_layer.h"

const u_char* unpack_tcp(const u_char* data, struct tcp* tcp_header)
{
    memcpy(tcp_header, data, sizeof (struct tcp));
    return (data + (((tcp_header->tcp_len_rsvd) >> 4) & 0x0f) * 4);
}

void print_tcp(struct tcp* tcp_header, uint flags)
{
    printf("TCP:\n");
    if ((flags & TCP_PORT) == TCP_PORT)
    {
        printf("%d --> %d\n", htons(tcp_header->tcp_sport), htons(tcp_header->tcp_dport));
    }
    else
    {
        if (flags & TCP_DPORT)
        {
            printf("--> %d\n", htons(tcp_header->tcp_dport));
        }
        if (flags & TCP_SPORT)
        {
            printf("%d -->\n", htons(tcp_header->tcp_sport));
        }
    }
    if (flags & TCP_FLAGS)
    {
        printf("UGA:%d  ACK:%d  PSH:%d  RST:%d  SYN:%d  FIN:%d\n",
               tcp_header->tcp_flags & TCP_FLAGS_URG ? 1 : 0,
               tcp_header->tcp_flags & TCP_FLAGS_ACK ? 1 : 0,
               tcp_header->tcp_flags & TCP_FLAGS_PSH ? 1 : 0,
               tcp_header->tcp_flags & TCP_FLAGS_RST ? 1 : 0,
               tcp_header->tcp_flags & TCP_FLAGS_SYN ? 1 : 0,
               tcp_header->tcp_flags & TCP_FLAGS_FIN ? 1 : 0);
    }
}
