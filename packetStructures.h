//////////////////////////////////////////////////////////////////////////////////////
//  School:     Faculty of Information Technology, Brno University of Technology    //
//  Course:     Computer Communications and Networks                                //
//  Project:    ZETA                                                                //
//  Module:     packetStructures.h                                                  //
//  Author:    Alexander Polok (xpolok03)                                          //
//////////////////////////////////////////////////////////////////////////////////////

#ifndef SNIFFER_PACKETSTRUCTURES_H
#define SNIFFER_PACKETSTRUCTURES_H

// default values
#define SIZE_OF_ETHERNET_HEADER 14

// macros to get part of merged values
#define IP_HEADER_LEN(ip)       (((ip)->version_header_len) & 0x0f)
#define IP_VERSION4_CHECK(ip)          (((ip)->version_header_len & 0xf0) >> 4)
#define TCP_OFFSET(tcp)       (((tcp)->data_offset_res & 0xf0) >> 4)

// struct for ipv4 header
struct ipv4_header {
    u_char version_header_len;
    u_char ip_tos;
    u_short len;
    u_short id;
    u_short offset;
    u_char time_to_live;
    u_char protocol;
    u_short checksum;
    struct in_addr src_adr, des_adr;
};

// struct for ipv6 header
struct ipv6_header {
    u_int version_tc_fl;
    u_short payload_len;
    u_char next_header;
    u_char hop_limit;
    struct in6_addr src_adr;
    struct in6_addr des_adr;
};

// struct for tcp header
struct tcp_header {
    u_short src_port;
    u_short des_port;
    u_int seq_number;
    u_int ack_number;
    u_char data_offset_res;
    u_char res_flags;
    u_short window;
    u_short checksum;
    u_short urgent_pointer;
};

// struct for udp header
struct udp_header {
    u_short src_port;
    u_short des_port;
    u_short length;
    u_short checksum;
};

#endif //SNIFFER_PACKETSTRUCTURES_H
