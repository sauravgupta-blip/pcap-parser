#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

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

struct __attribute__((packed)) tcp_header {
       uint16_t src_port;
       uint16_t dst_port;
       uint32_t seq_num;
       uint32_t ack_num;
       uint8_t  data_offset;
       uint8_t  flags;
       uint16_t window;
       uint16_t checksum;
       uint16_t urgent_ptr;
};

struct __attribute__((packed)) udp_header {
      uint16_t src_port;
      uint16_t dst_port;
      uint16_t length;
      uint16_t checksum;
};

int running = 1;

void handle_sigint(int sig) {
          running = 0;
}

int main(int argc, char *argv[]){
     int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
     signal(SIGINT ,  handle_sigint);
     unsigned int ifindex = if_nametoindex("enp0s1");

     struct sockaddr_ll addr;
     memset(&addr, 0, sizeof(addr));
     addr.sll_family = AF_PACKET;
     addr.sll_protocol = htons(ETH_P_ALL);
     addr.sll_ifindex = ifindex;

  bind(sockfd, (struct sockaddr*)&addr, sizeof(addr));

  while (running) {
        uint8_t buffer[65536];
        int n = recv(sockfd, buffer, sizeof(buffer), 0);
        if (n < 0) continue;
        if (n < (int)sizeof(struct ethernet_header)) continue;

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
      if (n < (int)(sizeof(struct ethernet_header) + sizeof(struct ipv4_header))) continue;
          struct ipv4_header *ip = (struct ipv4_header *)(buffer + sizeof(struct ethernet_header));

          uint8_t *s = (uint8_t *)&ip->src_ip;
          uint8_t *d = (uint8_t *)&ip->dst_ip;
          uint8_t ihl = ip->ver_ihl & 0x0F;
          int ihl_bytes = ihl * 4;

          printf("Src IP: %d.%d.%d.%d\n", s[0], s[1], s[2], s[3]);
          printf("Dst IP: %d.%d.%d.%d\n", d[0], d[1], d[2], d[3]);
          printf("TTL: %d\n", ip->ttl);
          printf("Protocol: %d\n", ip->protocol);
          printf("IHL: %d bytes\n", ihl_bytes);
          printf("\n");

          if (ip->protocol == 6) {
              struct tcp_header *tcp = (struct tcp_header *)(buffer + sizeof(struct ethernet_header) + ihl_bytes);
              printf("Src Port: %d\n", ntohs(tcp->src_port));
              printf("Dst Port: %d\n", ntohs(tcp->dst_port));

           if (tcp->flags & 0x01) {
               printf("FIN ");
}
           if (tcp->flags & 0x02) {
               printf("SYN ");
}
           if (tcp->flags & 0x04) {
               printf("RST ");
}
           if (tcp->flags & 0x08) {
               printf("PSH ");
}
          if (tcp->flags & 0x10) {
              printf("ACK ");
}
          if (tcp->flags & 0x20) {
              printf("URG ");
}
         printf("\n");

         }
                 else if (ip->protocol == 17) {
                 struct udp_header *udp = (struct udp_header *)(buffer + sizeof(struct ethernet_header) + ihl_bytes);
                 printf("Src Port: %d\n", ntohs(udp->src_port));
                 printf("Dst Port: %d\n", ntohs(udp->dst_port));
}
          else{
                printf("Unknown EtherType: 0x%04x, skipping\n", ntohs(eth->ethertype));
                printf("\n");
}
}
}
         close(sockfd);
         printf("Sniffer stopped.\n");
     return 0;
}

 
