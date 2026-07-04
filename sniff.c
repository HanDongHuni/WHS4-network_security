#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <pcap.h>
#include <arpa/inet.h>

#include "myheader.h"


void got_packet(u_char *args,const struct pcap_pkthdr *header,const u_char *packet)

{
    struct ethheader *eth;
    struct ipheader *ip;
    struct tcpheader *tcp;

    int ip_header_len;
    int tcp_header_len;
    int payload_len;
    int i;

    const u_char *data;


    // ethernet header
    eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) != 0x0800)
        return;


    // ip header
    ip = (struct ipheader *)(packet + sizeof(struct ethheader));

    if (ip->iph_protocol != IPPROTO_TCP)
        return;


    // IP header 길이
    ip_header_len = ip->iph_ihl * 4;


    // tcp header 위치
    tcp = (struct tcpheader *) (packet + sizeof(struct ethheader) + ip_header_len);

    // TCP header 길이
    tcp_header_len = TH_OFF(tcp) * 4;


    // application data 위치
    data = packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len;


    // application data 길이
    payload_len = ntohs(ip->iph_len)- ip_header_len - tcp_header_len;


    printf("\n-------------------------------------------------\n");

    printf("[Ethernet Header]\n");

    printf("src mac : %02X:%02X:%02X:%02X:%02X:%02X\n",
           eth->ether_shost[0],
           eth->ether_shost[1],
           eth->ether_shost[2],
           eth->ether_shost[3],
           eth->ether_shost[4],
           eth->ether_shost[5]);

    printf("dst mac : %02X:%02X:%02X:%02X:%02X:%02X\n",
           eth->ether_dhost[0],
           eth->ether_dhost[1],
           eth->ether_dhost[2],
           eth->ether_dhost[3],
           eth->ether_dhost[4],
           eth->ether_dhost[5]);


    printf("\n[IP Header]\n");

    printf("src ip : %s\n",
           inet_ntoa(ip->iph_sourceip));

    printf("dst ip : %s\n",
           inet_ntoa(ip->iph_destip));


    printf("\n[TCP Header]\n");

    printf("src port : %d\n",
           ntohs(tcp->tcp_sport));

    printf("dst port : %d\n",
           ntohs(tcp->tcp_dport));


    printf("\n[HTTP Message]\n");

    if (payload_len > 0) {
        for (i = 0; i < payload_len; i++) {
            if (isprint(data[i]) || data[i] == '\n' || data[i] == '\r' || data[i] == '\t'){
                printf("%c", data[i]);
            }
            else {
                printf(".");
            }
        }

        printf("\n");
    }
    else {
        printf("No Data\n");
    }
}


int main(int argc, char *argv[])
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    char *dev;


    if (argc != 2) {
        printf("usage : %s interface\n", argv[0]);
        return 1;
    }

    dev = argv[1];


    handle = pcap_open_live(
        dev,
        BUFSIZ,
        1,
        1000,
        errbuf
    );

    pcap_compile(
        handle,
        &fp,
        filter_exp,
        0,
        0
    );


    pcap_setfilter(
        handle,
        &fp
    );


    printf("packet sniffing start\n");


    pcap_loop(
        handle,
        -1,
        got_packet,
        NULL
    );


    pcap_close(handle);

    return 0;
}