#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <signal.h>
#include "parse_cmd.h"
#include "link_layer.h"
#include "network_layer.h"
#include "transport_layer.h"

int packet_id = 0;


void handler_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet_data)
{
    const u_char* data = NULL;
    packet_id++;
    printf("=====================%d\n", packet_id);
    printf("%s", ctime((const time_t *)&header->ts.tv_sec));
    printf("数据包长度: %d\n", header->len);
    struct ethernet ether_header;
    struct arp arp_data;
    struct ip ip_header;
    struct tcp tcp_header;
    data = unpack_ethernet(packet_data, &ether_header);
    print_ethernet_header(&ether_header, ETHERNET_ALL);

    switch (htons(ether_header.ether_type)) {
    case ETHERNET_TYPE_ARP:
        unpack_arp(data, &arp_data);
        print_arp(&arp_data, ARP_ALL);
        break;
    case ETHERNET_TYPE_IP:
        data = unpack_ip(data, &ip_header);
        print_ip(&ip_header, IP_ALL);
        if (ip_header.ip_p == IP_PROTOCOL_TCP)
        {
            unpack_tcp(data, &tcp_header);
            print_tcp(&tcp_header, TCP_PORT | TCP_FLAGS);
        }
        break;
    }

    printf("\n");
}

pcap_t *opened_device = NULL;
pcap_if_t* device_info = NULL;

void stop_capture_packet()
{
    printf("终止捕获!\n");
    pcap_breakloop(opened_device);
    pcap_freealldevs(device_info);
    pcap_close(opened_device);
    printf("清理完毕!\n");
}

int main(int argc, char **argv)
{
    char err_buf[PCAP_ERRBUF_SIZE];
    struct cmd_params_data params_data;
    char *interface_name = "en0";


    parse_cmd(argc, argv, &params_data);

    if (params_data.is_help == 1)
    {
        printf("./sniffer -h\n"
               "./sniffer --help\n"
               "./sniffer -i en0\n"
               "./sniffer --interface en0\n");
        return 0;
    }

    pcap_findalldevs(&device_info, err_buf);

    pcap_if_t *tdevice_info_head = device_info;
    while (tdevice_info_head) {
        if (strcmp(tdevice_info_head->name, params_data.interface) == 0)
        {
            interface_name = params_data.interface;
            break;
        }
        tdevice_info_head = tdevice_info_head->next;
    }

    if (interface_name == NULL)
    {
        printf("接口名字未找到!\n");
        return 0;
    }

    opened_device = pcap_open_live(interface_name, 65535, 1, 100, err_buf);

    if (opened_device == NULL)
    {
        printf("打开接口失败!\n");
        return 0;
    }
    signal(SIGINT, stop_capture_packet);

    printf("开始嗅探...\n");
    pcap_loop(opened_device, -1, handler_packet, NULL);

    return 0;
}
