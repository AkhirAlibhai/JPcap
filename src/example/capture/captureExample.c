#include<pcap.h>
#include<stdlib.h>
#include<string.h>
#include<arpa/inet.h>
#include<net/ethernet.h>
#include<netinet/ip.h>

int main() {
    pcap_t *handle;

    char errbuf[PCAP_ERRBUF_SIZE], *devname;

    handle = pcap_open_offline("TeamSpeak2.pcap", errbuf);

    struct pcap_pkthdr header;
    const u_char *packet;
    int count = 0;

    char source_ip[16], dest_ip[16]; 

    while (1) {
        packet = pcap_next(handle, &header);
        if (packet == NULL) {
            break;
        }
        count++;

        printf("Packet %i\n", count);
        struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));
        struct sockaddr_in source, dest;
        
        memset(&source, 0, sizeof(source));
        source.sin_addr.s_addr = iph->saddr;

        strcpy(source_ip, inet_ntoa(source.sin_addr));

        memset(&dest, 0, sizeof(dest));
        dest.sin_addr.s_addr = iph->daddr;

        strcpy(dest_ip, inet_ntoa(dest.sin_addr));

        printf("Got a packet from %s going to %s\n", 
			source_ip, dest_ip);
    }
    return 0;
}
