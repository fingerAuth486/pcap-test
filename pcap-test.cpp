#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include <arpa/inet.h>
#include <string.h>

//struct ether_header* eth_header;
struct libnet_ipv4_hdr* ip_header;
struct libnet_tcp_hdr* tcp_header;
struct pcap_pkthdr* pcap_header;
const u_char* packet;
struct libnet_ethernet_hdr *eth_header;

void ether_header_pf(const unsigned char *data);
int ip_header_pf(const unsigned char *data);
int tcp_header_pf(const unsigned char *data);
void data_pf(const unsigned char *data);

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param  = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}


int main(int argc, char* argv[]) {
    int offset = 0;
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE]; //error
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        int res = pcap_next_ex(pcap, &pcap_header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) { //PCAP_ERROR = -1, PCAP_ERROR_BREAK = -2
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        ip_header = (libnet_ipv4_hdr*)packet;
        if('6' == ip_header->ip_p){
            ether_header_pf(packet);
            packet = packet + 14;
            offset = ip_header_pf(packet);
            packet = packet + offset; //ip_header_offset
            offset = tcp_header_pf(packet);
            packet = packet + offset;
            data_pf(packet);
        }else{
            printf("No TCP\n");
        }
        }

    pcap_close(pcap);
}

void ether_header_pf(const u_char* data)
{
    u_short ether_type;
    eth_header = (libnet_ethernet_hdr *)data;
    ether_type = ntohs(eth_header->ether_type);

    if(ether_type != 0x0800){ //ethernet type check 0x0800
        printf("Wrong!!\n");
    }
    else{
        printf("===================================================\n");
        printf("<<<<<ETHERNET HEADER>>>>>\n");
        printf("Src MAC : {%02x:%02x:%02x:%02x:%02x:%02x}\n",eth_header->ether_shost[0],eth_header->ether_shost[1],eth_header->ether_shost[2],eth_header->ether_shost[3],eth_header->ether_shost[4],eth_header->ether_shost[5] );
        printf("Dst MAC : {%02x:%02x:%02x:%02x:%02x:%02x}\n",eth_header->ether_dhost[0],eth_header->ether_dhost[1],eth_header->ether_dhost[2],eth_header->ether_dhost[3],eth_header->ether_dhost[4],eth_header->ether_dhost[5]);
    }
}

int ip_header_pf(const u_char* data){
    ip_header = (libnet_ipv4_hdr*)data;
    printf("{%o}",ip_header->ip_p);
    printf("<<<<<IP HEADER>>>>>\n");
    printf("Src IP : {%s} \n", inet_ntoa(ip_header->ip_src));
    printf("Dst IP : {%s} \n", inet_ntoa(ip_header->ip_dst));
    return ip_header -> ip_hl*4;
}

int tcp_header_pf(const u_char* data){
    tcp_header = (libnet_tcp_hdr* )data;

    printf("<<<<<TCP HEADER>>>>>\n");
    printf("Src Port : {%d} \n", ntohs(tcp_header->th_sport));
    printf("Dst Port : {%d} \n", ntohs(tcp_header->th_dport));
    return tcp_header -> th_off * 4;
}
void data_pf(const u_char* data){
    printf("<<<<<PAYLOAD HEADER>>>>>\n");
    printf("data : {%02x%02x%02x%02x%02x%02x%02x%02x} \n",data[0],data[1],data[2],data[3],data[4],data[5],data[6],data[7]);
    printf("===================================================\n");
}

