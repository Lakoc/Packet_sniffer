//////////////////////////////////////////////////////////////////////////////////////
//  School:     Faculty of Information Technology, Brno University of Technology    //
//  Course:     Computer Communications and Networks                                //
//  Project:    ZETA                                                                //
//  Module:     ipk-sniffer.h                                                       //
//  Author:    Alexander Polok (xpolok03)                                          //
//////////////////////////////////////////////////////////////////////////////////////

#ifndef SNIFFER_IPK_SNIFFER_H
#define SNIFFER_IPK_SNIFFER_H

#include <pcap.h>
#include <string>
#include <iostream>
#include <cstdlib>
#include <getopt.h>
#include <cstring>
#include <cmath>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <bits/stdc++.h>

using namespace std;

// structure for settings from arguments
struct settings {
    int port{};
    bool tcpOnly{};
    bool udpOnly{};
    int numberOfPackets{};
    string interface;
    bool ipv4Only{};
    bool ipv6Only{};
    string ports;
};

// structure to stop PacketHandling
struct Configuration{
    unsigned numberOfPacketsToSend;
    pcap_t *handle;
    map<string, string> dnsCache;
};

// declaration of used functions
settings getSettings(int argc, char *argv[]);

string unixTimeStampConverter(time_t unixTimeStamp, suseconds_t microSeconds);

string ipToDomainName(char *ipv4);

void printHeader(const string &timestamp, const string &src_ip_name, unsigned short src_port,
                 const string &des_ip_name,
                 unsigned short des_port);

void printData(unsigned dataLength, const u_char *data, float valuesPerLine, unsigned offset);

void parsePacket(const u_char *packet, const string &time, const string &sourceIpOrDomain,
                 unsigned short sourcePort, const string &destinationIpOrDomain, unsigned short destinationPort,
                 u_int sizeOfHeaders, unsigned dataLength);

void packetHandler(Configuration args[], const struct pcap_pkthdr *header, const u_char *packet);

string checkIfStringIsValidPort(string port_s);

#endif //SNIFFER_IPK_SNIFFER_H

