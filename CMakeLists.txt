cmake_minimum_required(VERSION 3.5)

project(sniffer LANGUAGES C)


include_directories(/usr/local/Cellar/libpcap/1.9.1/include)
link_directories(/usr/local/Cellar/libpcap/1.9.1/lib)

include_directories(parse_cmd.h link_layer.h network_layer.h transport_layer.h)
add_executable(sniffer main.c parse_cmd.c link_layer.c network_layer.c transport_layer.c)

target_link_libraries(sniffer pcap)
