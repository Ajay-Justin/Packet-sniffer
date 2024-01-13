#define ETH_ADR_LEN  6
#define ETH_HDR_LEN	14

struct ether_hdr{
    unsigned char ether_dest_addr[ETH_ADR_LEN];
    unsigned char ether_src_addr[ETH_ADR_LEN];
    unsigned short ether_type;
};

struct ip_hdr{
    unsigned char ip_version_ihl;
    unsigned char ip_tos;
    unsigned short ip_len;
    unsigned short ip_id;
    unsigned short ip_offset;
    unsigned char ip_ttl;
    unsigned char ip_type;
    unsigned short ip_check_sum;
    unsigned int ip_src_addr;
    unsigned int ip_dest_addr;
};

struct tcp_hdr{
    unsigned short tcp_src_port;
    unsigned short tcp_dest_port;
    unsigned int   tcp_seq;
    unsigned int   tcp_ack;
    unsigned char  tcp_reserved:4;
    unsigned char  tcp_offset:4;
    unsigned char  tcp_flag;
# define TCP_FIN	0x01
# define TCP_SYN	0x02
# define TCP_RST	0x04
# define TCP_PUSH	0x08
# define TCP_ACK	0x10
# define TCP_URG	0x20
    unsigned short tcp_wind;
    unsigned short tcp_sum;
    unsigned short tcp_urp;

};



void hexDump(const unsigned char *data, const unsigned int recv_len){
    unsigned int i,j;
    unsigned char byte;

    for(i=0;i<recv_len;i++){
        byte=data[i];
        printf("%02x ",data[i]);
        if(((i%16) == 15) ||(i == recv_len -1)){
            for(j=0;j< 15-(i%16);j++)
                printf(" ");
            printf("|");
            for(j=(i-(i%16));j<=i;j++){
                byte=data[j];
                if((byte > 31) && (byte < 127))
                    printf("%c",byte);
                else
                    printf(".");
            }
            printf("\n");
        }
    }
}
