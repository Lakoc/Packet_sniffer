//////////////////////////////////////////////////////////////////////////////////////
//  School:     Faculty of Information Technology, Brno University of Technology    //
//  Course:     Computer Communications and Networks                                //
//  Project:    ZETA                                                                //
//  Module:     ipk-sniffer.c                                                       //
//  Author:    Alexander Polok (xpolok03)                                          //
//////////////////////////////////////////////////////////////////////////////////////

#include "ipk-sniffer.h"
#include "packetStructures.h"

// arguments parsing function return struct with settings
settings getSettings(int argc, char *argv[]) {
    //  main structure
    struct settings programArguments;
    // value for getopt
    int c;

    // initial settings
    programArguments.numberOfPackets = 1;
    programArguments.udpOnly = false;
    programArguments.tcpOnly = false;
    programArguments.port = -1;
    programArguments.ipv4Only = false;
    programArguments.ipv6Only = false;
    programArguments.ports = "";

    // loop to fetch all arguments, unknown are skipped
    while (true) {
        int option_index = 0;
        // long options
        static struct option long_options[] = {
                {"tcp",            no_argument,       nullptr, 0},
                {"udp",            no_argument,       nullptr, 0},
                {"ipv4",           no_argument,       nullptr, 0},
                {"ipv6",           no_argument,       nullptr, 0},
                {"multiple_ports", required_argument, nullptr, 0},
                {0,                0,                 0,       0},
        };
        opterr = 0;
        // short options
        c = getopt_long(argc, argv, "i:p:tun:",
                        long_options, &option_index);
        // if no argument fund, break loop
        if (c == -1)
            break;

        switch (c) {
            case 0:
                if (strcmp(long_options[option_index].name, "tcp") == 0)
                    programArguments.tcpOnly = true;
                else if (strcmp(long_options[option_index].name, "udp") == 0)
                    programArguments.udpOnly = true;
                else if (strcmp(long_options[option_index].name, "ipv4") == 0)
                    programArguments.ipv4Only = true;
                else if (strcmp(long_options[option_index].name, "ipv6") == 0)
                    programArguments.ipv6Only = true;
                else if (strcmp(long_options[option_index].name, "multiple_ports") == 0)
                    programArguments.ports = optarg;
                break;

                // case for each option
            case 't':
                programArguments.tcpOnly = true;
                break;

            case 'u':
                programArguments.udpOnly = true;
                break;

            case 'i':
                programArguments.interface = optarg;
                break;

            case 'n': {
                int numberOfPackets;
                try {
                    numberOfPackets = stoi(optarg);
                }
                    // error handling
                catch (...) {
                    fprintf(stderr, "Please make sure that specified number of packets is number!\n");
                    exit(1);
                }
                if (numberOfPackets >= 1 && numberOfPackets <= INT_MAX) {
                    programArguments.numberOfPackets = numberOfPackets;
                } else {
                    fprintf(stderr,
                            "Please specify number of packets as number greater than 0 and lower than INT_MAX!\n");
                    exit(1);
                }
                programArguments.numberOfPackets = numberOfPackets;
                break;
            }

            case 'p': {
                checkIfStringIsValidPort(optarg);
                programArguments.port = stoi(optarg);
                break;
            }

            case '?': {
                fprintf(stderr, "Please make sure that you have specified all needed params!\n");
                exit(1);
            }

            default:
                fprintf(stderr, "Unsupported param %c!\n", c);
                exit(1);
        }
    }

    // in case of no interface return list of active interfaces
    if (programArguments.interface.empty()) {
        pcap_if_t *alldevs;
        pcap_if_t *d;
        char errbuf[PCAP_ERRBUF_SIZE];

        // if we can't find interfaces exit with error code
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
            exit(1);
        }

        // print all interfaces
        for (d = alldevs; d != nullptr; d = d->next) {
            cout << d->name << endl;
        }

        // free them all and exit with 0
        pcap_freealldevs(alldevs);
        exit(EXIT_SUCCESS);
    }

    // return structure with options
    return programArguments;
}

// function to get time stamp in format "HH:MM:SS.ssssss"
string unixTimeStampConverter(time_t unixTimeStamp, suseconds_t microSeconds) {
    struct tm *time = localtime(&unixTimeStamp);
    char buf[10];
    strftime(buf, 10, "%H:%M:%S", time);
    string result(buf);
    return result + '.' + to_string(microSeconds);
}

// function that tries to result domain name of ip, in case of failure return ip
string ipToDomainName(char *ip, map <string, string> &dnsCache) {
    // check if we have this domain name cached if not add it to cache
    auto search = dnsCache.find(ip);
    if (search != dnsCache.end()) {
        return search->second;
    } else {
        struct addrinfo *res = nullptr;
        string result(ip);
        if (getaddrinfo(ip, nullptr, nullptr, &res) == 0) {
            char host[512];
            if (getnameinfo(res->ai_addr, res->ai_addrlen, host, 512, nullptr, 0, 0) == 0) {
                freeaddrinfo(res);
                result = host;
            } else {
                freeaddrinfo(res);
            }
        }
        dnsCache.insert({ip, result});
        return result;
    }
}

// function that prints header "timestamp src_ip : src_port > des_ip : des_port"
void printHeader(const string &timestamp, const string &src_ip_name, unsigned short src_port,
                 const string &des_ip_name,
                 unsigned short des_port) {
    cout << timestamp << " " << src_ip_name << " : "
         << src_port << " > " << des_ip_name << " : " << des_port << endl << endl;
}

// main printing function, prints data in format "offset: hh hh .... ascii_val"
void printData(unsigned dataLength, const u_char *data, float valuesPerLine, unsigned offset) {
    // pointer for every char
    const u_char *valueToPrint = data;
    // cycle over data, we round up number to prettify output
    for (int i = ceil((float) dataLength / valuesPerLine); i > 0; i--) {
        // print offset in format "0xhhhh"
        printf("0x%04x: ", offset);
        unsigned chars = 16;
        // in last cycle we need to fill up rest of output whit spaces, so we need to know how many chars to print
        if (i == 1) {
            chars = dataLength % 16;
            if (chars == 0) {
                chars = 16;
            }
        }
        // string to append ascii values
        string characters;
        for (int j = 0; j < 16; j++) {
            // if char print "hh" value else whitespace, also append its ascii value to string(in case of printable else '.'
            if (chars) {
                printf("%02x ", *valueToPrint);
                if (isprint(*valueToPrint)) {
                    characters.push_back(*valueToPrint);
                } else {
                    characters.push_back('.');
                }
                valueToPrint++;
                chars--;
            } else {
                characters.push_back(' ');
                cout << "   ";
            }
            if (j == 7) {
                characters.push_back(' ');
                cout << " ";
            }
        }
        // increase offset print ascii values
        offset += 16;
        cout << characters << endl;
    }
    cout << endl;
}

// print header than parse header data(prettify format) and then payload also prettified
void parsePacket(const u_char *packet, const string &time, const string &sourceIpOrDomain,
                 unsigned short sourcePort, const string &destinationIpOrDomain, unsigned short destinationPort,
                 u_int sizeOfHeaders, unsigned dataLength) {
    printHeader(time, sourceIpOrDomain, sourcePort, destinationIpOrDomain, destinationPort);
    printData(sizeOfHeaders, (u_char * )(packet), 16.0, 0);
    if (dataLength) {
        printData(dataLength, (u_char * )(packet + sizeOfHeaders), 16.0, (unsigned) ceil(sizeOfHeaders / 16.0) * 16);

    }
}

// main scope for packet handling
void packetHandler(Configuration args[], const struct pcap_pkthdr *header, const u_char *packet) {
    // structures for ip4 and ipv6
    struct ipv4_header *ipv4;
    struct ipv6_header *ipv6 = nullptr;
    unsigned sizeIp;
    // static value to count already seen packets
    static unsigned alreadySeen = 0;

    // we simply skip ethernet header, we don't need any info from it
    ipv4 = (struct ipv4_header *) (packet + SIZE_OF_ETHERNET_HEADER);
    // we get size of ip header, only works with v4
    sizeIp = IP_HEADER_LEN(ipv4) * 4;
    // version is placed same in ipv4 and ipv6 so we can check it like that, we need to separate some bits with bitwise operation
    unsigned version = IP_VERSION4_CHECK(ipv4);
    // in case it's not ipv4 we initialize ipv6 struct with data and below check for nullptr to specify if we are using ipv4 or ipv6
    if (version == 6) {
        ipv6 = (struct ipv6_header *) (packet + SIZE_OF_ETHERNET_HEADER);
        // fixed size in case of TCP / UDP, no extension headers allowed
        sizeIp = 40;
    } else if (version == 4) {
        // if not valid just skip it
        if (sizeIp < 20) {
            return;
        }
    } else {
        // if unknown version of ip protocol skip
        return;
    }

    // strings for timestamp, domain names
    string time = unixTimeStampConverter(header->ts.tv_sec, header->ts.tv_usec);
    string sourceIpOrDomain;
    string destinationIpOrDomain;

    // we fill needed information
    if (version == 4) {
        sourceIpOrDomain = ipToDomainName(inet_ntoa(ipv4->src_adr), args[0].dnsCache);
        destinationIpOrDomain = ipToDomainName(inet_ntoa(ipv4->des_adr), args[0].dnsCache);
    } else {
        char str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ipv6->src_adr), str, INET6_ADDRSTRLEN);
        sourceIpOrDomain = ipToDomainName(str, args[0].dnsCache);
        inet_ntop(AF_INET6, &(ipv6->des_adr), str, INET6_ADDRSTRLEN);
        destinationIpOrDomain = ipToDomainName(str, args[0].dnsCache);
    }

    // just to be sure we don't print more information
    if (args[0].numberOfPacketsToSend == alreadySeen) {
        pcap_breakloop(args[0].handle);
    }

    // switch to find protocol in ip headers
    switch (ipv6 ? ipv6->next_header : ipv4->protocol) {
        // tcp header
        case IPPROTO_TCP: {
            // we skip ip header and parse values to new struct
            auto *tcp = (struct tcp_header *) (packet + SIZE_OF_ETHERNET_HEADER + sizeIp);
            // we calculate offset
            unsigned dataOffset = TCP_OFFSET(tcp) * 4;
            // if offset is greater than 20 tcp header is valid and we can print it
            if (dataOffset > 20) {
                // we calculate size of header by adding size of all pretending headers
                // and also calculate length of payload data
                parsePacket(packet, time, sourceIpOrDomain,
                            ntohs(tcp->src_port), destinationIpOrDomain, ntohs(tcp->des_port),
                            SIZE_OF_ETHERNET_HEADER + sizeIp + dataOffset,
                            ipv6 ? ntohs(ipv6->payload_len) - dataOffset : ntohs(ipv4->len) - (sizeIp + dataOffset));
                // packet already printed so we can increase our counter
                alreadySeen++;
            }
            break;
        }
            // udp header
        case IPPROTO_UDP: {
            // also parse values to struct
            auto *udp = (struct udp_header *) (packet + SIZE_OF_ETHERNET_HEADER + sizeIp);
            // size of upd header is fixed
            unsigned sizeUdp = sizeof(udp_header);
            // we calculate size of payload

            int sizeUdpData = (int) (ntohs(udp->length) - sizeof(udp_header));
            // if size of payload is lower than 0 packet is not valid so we skip it
            if (sizeUdpData >= 0) {
                // also calculate new sizes and print it
                parsePacket(packet, time, sourceIpOrDomain, ntohs(udp->src_port), destinationIpOrDomain,
                            ntohs(udp->des_port), SIZE_OF_ETHERNET_HEADER + sizeIp + sizeUdp,
                            sizeUdpData);
                // also increase counter
                alreadySeen++;
            }
            break;
        }
            // in case other header appeared we end application with internal error, this should not occur
        default: {
            fprintf(stderr, "Internal error!\n");
            exit(3);
        }
    }
    // if we have printed sufficient number of packets we can break our loop and exit
    if (args[0].numberOfPacketsToSend == alreadySeen) {
        pcap_breakloop(args[0].handle);
    }
}

// check if string is valid port number
string checkIfStringIsValidPort(string port_s) {
    int port;
    try {
        port = stoi(port_s);
    }
        // error handling
    catch (...) {
        fprintf(stderr, "Please make sure that specified port is a number!\n");
        exit(1);
    }
    if (port >= 0 && port <= 65535) {
        return port_s;
    } else {
        fprintf(stderr, "Please specify port as number between 0-65535!\n");
        exit(1);
    }
}

// main scope
int main(int argc, char *argv[]) {
    // declare needed variables
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp{};
    bpf_u_int32 mask;
    bpf_u_int32 net;
    struct settings programArguments;

    // fill struct with arguments
    programArguments = getSettings(argc, argv);

    // get used interface
    char *dev = const_cast<char *>(programArguments.interface.c_str());

    // scan this interface for netmask
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
                dev, errbuf);
        net = 0;
        mask = 0;
    }

    // open interface of packet sniffing
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(2);
    }

    // set filters
    char *filter_exp;
    string filter = "";

    // ipv4 and ipv6 filters
    if (programArguments.ipv4Only && !programArguments.ipv6Only) {
        filter = "ip and";
    } else if (!programArguments.ipv4Only && programArguments.ipv6Only) {
        filter = "ip6 and ";
    }

    // network layer filters are always set
    // udp and tcp == !udp and !tcp
    if (programArguments.udpOnly && programArguments.tcpOnly) {
        filter = filter + "(tcp or udp)";
    } else if (programArguments.udpOnly || programArguments.tcpOnly) {
        filter = filter + (programArguments.udpOnly ? "udp" : "tcp");
    } else {
        filter = filter + "(tcp or udp)";
    }

    // if we need to filter port/ports append to filter
    if (programArguments.ports.length() > 0) {
        string ports = programArguments.ports;
        string delimiter = ",";
        size_t pos = 0;
        string token;
        string filterToAppend = " and (";
        // cycle over passed string and check if all ports are valid port numbers, split by ","
        while ((pos = ports.find(delimiter)) != string::npos) {
            filterToAppend = filterToAppend + "port " + checkIfStringIsValidPort(ports.substr(0, pos)) + " or ";
            ports.erase(0, pos + delimiter.length());
        }
        // parse last part of string and remove unnecessary or
        filterToAppend = filterToAppend + "port " + checkIfStringIsValidPort(ports.substr(0, ports.length())) + " or ";
        filter = filter + filterToAppend.substr(0, filterToAppend.length() - 4) + ")";
    } else if (programArguments.port >= 0) {
        filter = filter + " and (port " + to_string(programArguments.port) + ")";
    }

    // cast to char*
    filter_exp = const_cast<char *>(filter.c_str());

    // try to compile and set filter
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(2);
    }

    // cache to store domain names
    map <string, string> dnsCache;
    // fill configuration for breaking loop
    Configuration conf[1] = {
            {static_cast<unsigned int>(programArguments.numberOfPackets), handle, dnsCache}};

    // loop for packets and handle them
    pcap_loop(handle, -1, reinterpret_cast<pcap_handler>(packetHandler),
              (u_char *) conf);

    // free used resources
    pcap_freecode(&fp);
    pcap_close(handle);

    // finish
    return (0);
}