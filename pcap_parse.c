#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

struct __attribute__((packed)) pcap_global_header {
     uint32_t magic_number;
     uint16_t version_major;
     uint16_t version_minor;
     int32_t  thiszone;
     uint32_t sigfigs;
     uint32_t snaplen;
     uint32_t network;
};

struct __attribute__((packed)) pcap_packet_header {
      uint32_t ts_sec;
      uint32_t ts_usec;
      uint32_t incl_len;
      uint32_t orig_len;
};
struct __attribute__((packed)) ethernet_header {
       uint8_t dst_mac[6];
       uint8_t src_mac[6];
       uint16_t ethertype;
};
struct __attribute__((packed)) ipv4_header {
       uint8_t ver_ihl;
       uint8_t tos;
       uint16_t total_len;
       uint16_t id;
       uint16_t flags_frag;
       uint8_t ttl;
       uint8_t protocol;
       uint16_t checksum;
       uint32_t src_ip;
       uint32_t dst_ip;
};

int main(int argc, char *argv[]){
     if (argc <2) {
     printf("Usage:./pcap_parse.c <filename>\n");
     return 1;
}
     FILE *f = fopen(argv[1], "rb");
     if (f == NULL){
     printf("Error: cannot open file\n");
     return 1;
    }

    struct pcap_global_header gh;
    fread(&gh, sizeof(gh), 1, f);
    
    if (gh.magic_number != 0xa1b2c3d4 &&
        gh.magic_number != 0xd4c3b2a1) {
        printf("Error: not a pcap file\n");
        fclose(f);
        return 1;
}

printf("Magic: %08x\n" , gh.magic_number);



struct pcap_packet_header ph;
int packet_num = 1;

while (fread(&ph, sizeof(ph), 1, f) == 1) {
      uint8_t buffer[65536];
      fread(buffer, 1, ph.incl_len, f);

      struct ethernet_header *eth = (struct ethernet_header *)buffer;

      for(int i =0; i<6; i++) {
      printf("%02x", eth->dst_mac[i]);
      if (i < 5)
       printf(":");

}
      printf("\n");
      printf("src: ");
      for(int i=0;i < 6; i++) {
      printf("%02x" , eth->src_mac[i]);
      if (i<5)
        printf(":");

}
       printf("\n");
       printf("EtherType : 0x%04x\n", ntohs(eth->ethertype));

        printf("\n");

      if (ntohs(eth->ethertype) == 0x0800){
          struct ipv4_header *ip = (struct ipv4_header *)(buffer + sizeof(struct ethernet_header));

          uint8_t *s = (uint8_t *)&ip->src_ip;
          uint8_t *d = (uint8_t *)&ip->dst_ip;

          printf("Src IP: %d.%d.%d.%d\n", s[0], s[1], s[2], s[3]);
          printf("Dst IP: %d.%d.%d.%d\n", d[0], d[1], d[2], d[3]);
          printf("TTL: %d\n", ip->ttl);
          printf("Protocol: %d\n", ip->protocol);
}
      printf("Packet %d: len=%d\n", packet_num, ph.incl_len);

      packet_num++;
} 

     fclose(f);
     return 0;
}

