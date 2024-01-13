#include<stdio.h>
#include<stdlib.h>
#include<pcap.h>
#include"netapi.h"
#include<time.h>
void caught(u_char *usr_args, const struct pcap_pkthdr *header,const u_char *packet);
void __ether(const u_char *ether_pack);
void __ip(const u_char *ip_pack);
u_int __tcp(const u_char *tcp_pack);
void banner();

int main(){
    struct pcap_pkthdr *header;    
    char errbuf[PCAP_ERRBUF_SIZE];
    int rtcode,many;
    pcap_if_t *interface;
    pcap_t *pcap_handle;
    const char *device;


    if((rtcode = pcap_findalldevs(&interface,errbuf))==-1){
        fprintf(stderr,"! %s\n",errbuf);
        exit(-1);
    }

    banner();

    device=interface->name;
    printf("[+]sniffing on active device: %s\n",device);

    if((pcap_handle = pcap_open_live(device,4096,1,1,errbuf))==NULL){
        fprintf(stderr,"! %s\n",errbuf);
        exit(-1);
    }

    printf("\n");
    printf("ThresHold: ");
    scanf("%d",&many);
    printf("\n");
    printf("[+]Asmodius started capturing Packet\n");
    pcap_loop(pcap_handle,many,caught,NULL);
    pcap_close(pcap_handle);
}

void caught(u_char *usr_args, const struct pcap_pkthdr *header,const u_char *packet){
    int TCP_HDR_SIZE,PCK_SIZE,T_LEN;
    u_char *pack;
    printf("\n");
    printf("++++++++++++++++++  Got %d bytes len packet +++++++++++++++++++\n",header->len);
    printf("\t\tPacket Recived at %s",ctime((const time_t*)&header->ts.tv_sec));
    printf("\n");
    __ether(packet);
    __ip(packet+ETH_HDR_LEN);
    TCP_HDR_SIZE=__tcp(packet+ETH_HDR_LEN+sizeof(struct ip_hdr));
    
    T_LEN=ETH_HDR_LEN+sizeof(struct ip_hdr)+TCP_HDR_SIZE;
    
    pack=(u_char*)packet+T_LEN;
    PCK_SIZE=header->len - T_LEN;

    if(PCK_SIZE > 0){
        printf("\t\t\t Bytes of Data in packet %u\n",PCK_SIZE);
        hexDump(pack,PCK_SIZE);
    }else{
        printf("\t\t\t NO Data in Captued Packet\n");
    }

}


void __ether(const u_char *ether_pack){
    
    int i;
    const struct ether_hdr *etherHeader;

    etherHeader=(const struct ether_hdr*)ether_pack;
    printf("((Layer2 -> Ethernet Header))\n");
    printf("( SRC: %02x",etherHeader->ether_src_addr[0]);
    for(i=1;i<ETH_ADR_LEN; i++)
        printf(":%02x",etherHeader->ether_src_addr[i]);
    printf("\tDEST : %02x",etherHeader->ether_dest_addr[0]);
    for(i=0;i<ETH_ADR_LEN;i++)
        printf(":%02x",etherHeader->ether_dest_addr[i]);

    printf("\tTYPE: %hu)\n",etherHeader->ether_type);
    printf("\n");
}

void __ip(const u_char *ip_pack){
    const struct ip_hdr *ipHeader;
    ipHeader=(const struct ip_hdr*)ip_pack;

    printf("\t[[Layer3 -> -> -> Ip Header]]\n");
    printf("\t[SRC: %s\t",inet_ntoa(*(struct in_addr*)&ipHeader->ip_src_addr));
    printf("DEST: %s ]\n",inet_ntoa(*(struct in_addr*)&ipHeader->ip_dest_addr));
    printf("\t[ TYPE: %u",(u_int)ipHeader->ip_type);
    printf("\tID: %hu\tLENGTH: %hu ]",ntohs(ipHeader->ip_id),ntohs(ipHeader->ip_len));
    printf("\n");

}

u_int __tcp(const u_char *tcp_pack){
    u_int tcp_size;
    const struct tcp_hdr *tcpHeader;
    tcpHeader=(const struct tcp_hdr*)tcp_pack;
    tcp_size=4*tcpHeader->tcp_offset; //tcp_offset has bit feild value 4 offset has 32 bit word
    printf("\n");
    printf("\t\t{{ Layer -> -> -> -> Tcp Header }}\n");
    printf("\t\t{SRC PORT: %hu\t",ntohs(tcpHeader->tcp_src_port));
    printf("DEST PORT: %hu }\n",ntohs(tcpHeader->tcp_dest_port));
    printf("\t\t{ SEQ# : %hu\t ACK#: %hu }\n",ntohl(tcpHeader->tcp_seq),ntohl(tcpHeader->tcp_ack));
    printf("\t\t{HEADER SIZE : %u\t FLAG: ",tcp_size);
    if(tcpHeader->tcp_flag & TCP_FIN)
        printf("FIN ");
    if(tcpHeader->tcp_flag & TCP_SYN)
        printf("SYN ");
    if(tcpHeader->tcp_flag & TCP_RST)
        printf("RST ");
    if(tcpHeader->tcp_flag & TCP_PUSH)
        printf("PUSH ");
    if(tcpHeader->tcp_flag & TCP_ACK)
        printf("ACK ");
    if(tcpHeader->tcp_flag & TCP_URG)
        printf("URG ");
    printf(" }\n");
    printf("\n");
    return tcp_size;
}

void banner(){
printf("\n");
printf("                                                                \n");
printf("   db    .dPY8**8b    d8  dP'Yb  8888b.  888888 88   88 .dPY8   \n"); 
printf("  dPYb   'Ybo.. 88b  d88 dP   Yb  8I  Yb 88__   88   88 'Ybo.   \n");
printf(" dP__Yb  o.'Y8b 88YbdP88 Yb   dP  8I  dY 88''   Y8   8P o.'Y8b  \n");
printf("dP    Yb 8bodP' 88 YY 88  YbodP  8888YH  888888 'YbodP' 8bodP'  \n");
printf("                                            sin of hacking      \n");
}
