#include "bouncer.h"
#include "icmplist.c"
#include "tcplist.c"
#include <regex.h>

#define IP_HL(ip)   (((ip)->ip_hl) & 0x0f)

static unsigned int BOUNCER_TO_SERVER_TCP_PORT = 20000;
static u_int16_t FTP_P1 = 200;
static u_int16_t FTP_P2 = 200;
//static char* modPortStart = NULL;

int getBouncerDataPort() {
    return FTP_P1 * 256 + (++FTP_P2);
}

unsigned short inetChecksum(unsigned short *addr, int len) {
    register long sum = 0;
    u_short answer = 0;
    register u_short *w = addr;
    register int nleft = len;
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1) {
        *(u_char *) (&answer) = *(u_char *) w;
        sum += answer;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    //printf("Calculated checksum: %d\n", answer);
    return (answer);
}

int sendPacket(struct ip * ip, unsigned int dPort) {
    int sock; //socket
    struct sockaddr_in dAddr;
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock == -1) {
        //fprintf(stdout, "Unable to open socket to send \n");
        return -1;
    }
    memset(&dAddr, 0, sizeof (dAddr));
    dAddr.sin_family = AF_INET;
    if (dPort != 0) {
        dAddr.sin_port = htons(dPort);
    }
    dAddr.sin_addr.s_addr = ip->ip_dst.s_addr;
    int optval = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof (int));
    if (sendto(sock, ip, ntohs(ip->ip_len), 0, (struct sockaddr *) &dAddr, sizeof (struct sockaddr)) < 0) {
        //fprintf(stdout, "Unable to send packet\n");
        return -1;
    }
    close(sock);
    return 1;

}

void processICMPPacket(struct icmp* icmp, struct ip* ip) {
    bool dontSend = false;
    //printf("Started processing ICMP with type code %d \n", icmp->icmp_type);

    if (icmp->icmp_type == 8) {//Echo request
        //printf("ICMP REQ:\t");
        add_to_list(icmp->icmp_hun.ih_idseq.icd_id, icmp->icmp_hun.ih_idseq.icd_seq, ip->ip_src.s_addr);
        inet_aton(bouncerAddress, &(ip->ip_src));
        //printf("server address: [%s]\n", serverAddress);
        //inet_aton(serverAddress, &(ip->ip_dst));
        ip->ip_dst.s_addr = inet_addr(serverAddress);
    } else {//Echo reply
        //printf("ICMP REP:\t");
        uint32_t found = search_in_list(icmp->icmp_hun.ih_idseq.icd_id, icmp->icmp_hun.ih_idseq.icd_seq);
        if (found != 0) {
            inet_aton(bouncerAddress, &(ip->ip_src));
            ip->ip_dst.s_addr = found;
        } else {
            //printf("Bad ICMP reply ID\n");
            dontSend = true;
        }
    }
    if (!dontSend) {
        ip->ip_sum = 0;
        ip->ip_sum = inetChecksum((unsigned short *) ip, ip->ip_hl << 2);
        //printf("Sending ICMP packet Src:[%s] Dst:[%s]\n", inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst));
        sendPacket(ip, 0);
    }
}

struct tcpPsdHeader {
    u_int32_t psdSrcAddr;
    u_int32_t psdDstAddr;
    u_int8_t psdReserved;
    u_int8_t psdProtocol;
    u_int16_t psdLength;
};

unsigned short calculateTCPChecksum(struct tcphdr* tcphdr, struct ip* ip) {
    struct tcpPsdHeader* tcpPsdHeader = (struct tcpPsdHeader*) malloc(sizeof (tcpPsdHeader));
    u_int totalLength = ntohs(ip->ip_len);
    u_int ipSize = ip->ip_hl * 4;
    u_int tcpHeaderLength = sizeof (struct tcphdr);
    u_int tcpOptionsLength = (tcphdr->th_off * 4) - ipSize;
    u_int tcpDataLength = totalLength - (tcphdr->th_off * 4) - ipSize;

    tcpPsdHeader->psdSrcAddr = ip->ip_src.s_addr;
    tcpPsdHeader->psdDstAddr = ip->ip_dst.s_addr;
    tcpPsdHeader->psdReserved = htons(0);
    tcpPsdHeader->psdProtocol = IPPROTO_TCP;
    tcpPsdHeader->psdLength = htons(tcpHeaderLength + tcpOptionsLength + tcpDataLength);

    unsigned char checksumBuffer[65536];
    memcpy((unsigned char *) checksumBuffer, tcpPsdHeader, 12);
    memcpy((unsigned char *) checksumBuffer + 12, (unsigned char *) tcphdr, tcpHeaderLength);
    memcpy((unsigned char *) checksumBuffer + 12 + tcpHeaderLength, (unsigned char *) tcphdr + tcpHeaderLength, tcpOptionsLength);
    memcpy((unsigned char *) checksumBuffer + 12 + tcpHeaderLength + tcpOptionsLength, (unsigned char *) tcphdr + tcpHeaderLength + tcpOptionsLength, tcpDataLength);

    int bufferLength = 12 + tcpHeaderLength + tcpOptionsLength + tcpDataLength;
    while (tcpDataLength % 4 != 0) {
        checksumBuffer[bufferLength] = 0;
        bufferLength++;
        tcpDataLength++;
    }

    free(tcpPsdHeader);
    return inetChecksum((u_short *) checksumBuffer, bufferLength);
}

struct ip* processFTPPacket(const u_char *p, struct ip* ip, struct tcphdr* tcphdr, struct tcp_node* node) {
    u_int ipLen = ntohs(ip->ip_len);
    u_int ipHdrLen = ip->ip_hl * 4;
    u_int tcpHdrLen = sizeof (struct tcphdr);
    u_int tcpOptionsLen = (tcphdr->th_off * 4) - ipHdrLen;
    u_int tcpDataLen = ipLen - (tcphdr->th_off * 4) - ipHdrLen;

    char * ftpPacket = (char *) tcphdr + tcpHdrLen + tcpOptionsLen;
    /*int reti;
    regex_t re;
    regmatch_t match;
    char msgbuf[100];

    if (regcomp(&re, "[0-9]+\r\n", REG_EXTENDED) != 0) exit(1);
    reti = regexec(&re, ftpPacket, 1, &match, 0);

    if (reti == 0) {
        puts("Match\n");
        //return NULL;
        exit(0);
    } else if (reti == REG_NOMATCH) {
        puts("No match\n");
    } else {
        regerror(reti, &re, msgbuf, sizeof (msgbuf));
        fprintf(stderr, "Regex match failed: %s\n", msgbuf);
        printf("Regex match failed: %s\n", msgbuf);
    }*/
    //printf("***********Processing FTP packet !*********\n");
    if (strncmp(ftpPacket, "PORT", 4) == 0) {
        node->isFTP = true;
        //printf("PORT command received\n");
        char *token; //*modifiedPort = NULL;
//        char *ftp_p2;o
        int count = 0, p1, p2;
        while ((token = strsep(&ftpPacket, ","))) {
            //printf("[%s] \n", token);
            if (count == 4) {
                p1 = atoi(token);
                //printf("P1 %d\n", p1);
                //printf("P1 %s\n", token);
            } else if (count == 5) {
                token = strsep(&token, "\r");
                p2 = atoi(token);
                //printf("P2 %d\n", p2);
            }
            count++;
        }
        node->sourceDataPort = p1 * 256 + p2;
        //printf("Calculated active port: %d\n", node->sourceDataPort);
        node->bouncerDataPort = getBouncerDataPort();

        unsigned char portCommandParams[6];
        u_int32_t bouncerIp = inet_addr(bouncerAddress);
        portCommandParams[0] = bouncerIp & 0xFF;
        portCommandParams[1] = (bouncerIp >> 8) & 0xFF;
        portCommandParams[2] = (bouncerIp >> 16) & 0xFF;
        portCommandParams[3] = (bouncerIp >> 24) & 0xFF;
        portCommandParams[4] = FTP_P1;
        portCommandParams[5] = FTP_P2;

        char *ftpData = malloc(40);
        memcpy(ftpData, "PORT ", 5);
        u_int modifiedTCPDataLength = 5;
        char portData[30];
        sprintf(portData, "%d,%d,%d,%d,%d,%d\r\n", portCommandParams[0], portCommandParams[1], portCommandParams[2], portCommandParams[3], portCommandParams[4], portCommandParams[5]);
        memcpy(ftpData + modifiedTCPDataLength, portData, strlen(portData));
        modifiedTCPDataLength += strlen(portData);

        //printf("Modified data: %s\n", ftpData);

        u_int modifiedIPTotalLength = ipLen - tcpDataLen + modifiedTCPDataLength;
        struct ip* newIP = (struct ip*) malloc(modifiedIPTotalLength);
        memcpy((unsigned char *) newIP, (unsigned char *) ip, ipLen - tcpDataLen);
        memcpy((unsigned char *) newIP + ipLen - tcpDataLen, ftpData, modifiedTCPDataLength);
        newIP->ip_len = htons(modifiedIPTotalLength);
        free(ftpData);
        return newIP;
    }
    return ip;
}

void processTCPPacket(const u_char *p, struct ip* ip) {
    struct tcphdr* tcphdr;
    tcphdr = (struct tcphdr*) (p + sizeof (struct ether_header) + sizeof (struct iphdr));
    if (tcphdr->th_off * 4 < 20 || tcphdr->th_off * 4 > 60) {
        //printf("Invalid TCP Header Length\n");
        return;
    }
    unsigned short receivedChecksum = tcphdr->th_sum;
    tcphdr->th_sum = 0;
    unsigned short calculatedChecksum = calculateTCPChecksum(tcphdr, ip);
    if (receivedChecksum != calculatedChecksum) {
        //printf("Invalid TCP checksum\n");
        return;
    }
    //printf("Valid TCP packet received!\n");
    unsigned int bouncerPortForThisConn;\
    //printf("[%s] [%s]\n",inet_ntoa(ip->ip_src), serverAddress);

    int port_actual_dst = ntohs(tcphdr->th_dport);
    int port_actual_src = ntohs(tcphdr->th_sport);

    if (strcmp(inet_ntoa(ip->ip_src), serverAddress) != 0) {//TCP Packet from client
        printf("Packet from client src:[%d] [%d] dest:[%d] [%d]**************************\n"
                , ntohs(tcphdr->th_sport), ip->ip_src.s_addr, ntohs(tcphdr->th_dport), ip->ip_dst.s_addr);

        struct tcp_node* node = NULL;

        //printf("tcphdr->syn:%d\n",tcphdr->syn);
        //printf("port_actual_dst:%d\n",port_actual_dst);
        //printf("bouncerPort:%d\n",bouncerPort);
        if (tcphdr->syn == 1 && port_actual_dst == bouncerPort) {
            //printf("TCP SYN request from client!\n");
            if (BOUNCER_TO_SERVER_TCP_PORT == bouncerPort) {
                BOUNCER_TO_SERVER_TCP_PORT++;
            }
            bouncerPortForThisConn = BOUNCER_TO_SERVER_TCP_PORT++;
            add_to_tcp_list(bouncerPortForThisConn, ntohs(tcphdr->th_sport), ip->ip_src.s_addr);
        } else {//Existing connection from client


            node = search_in_tcp_list(ntohs(tcphdr->th_sport), ip->ip_src.s_addr, 0);
            if (node == NULL) {
               // printf("TCP connection not found. Dropping packet!\n");
                return;
            }

            bouncerPortForThisConn = node->bouncerPort;
            //printf("TCP connection found. Bouncer Port: %d\n", bouncerPortForThisConn);

            //if (serverPort == 21) {
                ip = processFTPPacket(p, ip, tcphdr, node);
                tcphdr = (struct tcphdr*) ((char *) ip + ip->ip_hl * 4);
            //}
        }
        //Modify packet
        if (port_actual_dst == bouncerPort) {
            tcphdr->th_dport = htons(serverPort);
            tcphdr->th_sport = htons(bouncerPortForThisConn);
        }else if (port_actual_dst == (bouncerPort - 1)) {
            tcphdr->th_dport = htons(node->serverDataPort);
            tcphdr->th_sport = htons(node->bouncerDataPort);
        }

        ip->ip_dst.s_addr = inet_addr(serverAddress);
        ip->ip_src.s_addr = inet_addr(bouncerAddress);

    } else {//TCP Packet from server
        //printf("Packet from server**************************\n");
        printf("Packet from server src:[%d] [%d] dest:[%d] [%d]**************************\n"
                , ntohs(tcphdr->th_sport), ip->ip_src.s_addr, ntohs(tcphdr->th_dport), ip->ip_dst.s_addr);
        struct tcp_node* node = search_in_tcp_list(0, 0, port_actual_dst);
        if (node == NULL) {
            //printf("TCP connection not found. Dropping packet!\n");
            return;
        }
        if(node->isFTP && tcphdr->syn == 1 && port_actual_src != serverPort){
            node->serverDataPort = port_actual_src;
            printf("Server data port:%d\n",node->serverDataPort);
        }
//        int srcPort = node->sourcePort;
        uint32_t srcAddr = node->inAddr;
        //printf("TCP connection found. Source: [%d] [%d]\n", srcPort, srcAddr);

        //Modify header
        if (port_actual_src == node->serverDataPort) {
            printf("Packet from server data port!!!\n");
            tcphdr->th_dport = htons(node->sourceDataPort);
            tcphdr->th_sport = htons(bouncerPort - 1);
        } else {
            tcphdr->th_dport = htons(node->sourcePort);
            tcphdr->th_sport = htons(bouncerPort);
        }

        ip->ip_dst.s_addr = srcAddr;
        ip->ip_src.s_addr = inet_addr(bouncerAddress);
    }
    //Modify checksum
    ip->ip_sum = 0;
    ip->ip_sum = inetChecksum((unsigned short *) ip, ip->ip_hl << 2);
    tcphdr->th_sum = 0;
    tcphdr->th_sum = calculateTCPChecksum(tcphdr, ip);

    //printf("Relaying TCP packet from src: [%d] [%d] to dest [%d] [%d]\n",
        //    ntohs(tcphdr->th_sport), ip->ip_src.s_addr, ntohs(tcphdr->th_dport), ip->ip_dst.s_addr);
    sendPacket(ip, 0);

}

void process_pkt(u_char *args, const struct pcap_pkthdr *header,
        const u_char *p) {
    /* Define pointers for p's attributes */
    struct ip* ip;
    //struct pacp_pkthdr head = *header;
    u_int length = header->len;
    u_int hlen, version;

    int len;

    /* jump pass the ethernet header */
    ip = (struct ip*) (p + sizeof (struct ether_header));
    length -= sizeof (struct ether_header);

    if (ip->ip_p == 1) {
        //printf("Captured a new ICMP packet!\n");
    } else if (ip->ip_p == 6) {
        //printf("Captured a new TCP packet!\n");
    } else {
        //printf("Captured IP packet with invalid upper layer protocol!\n");
        return;
    }
    if (ip->ip_ttl < 1) {
        //fprintf(stdout, "IP TTL Expired\n");
        return;
    }
    if (htons(ip->ip_off) == IP_RF) {
        //printf("IP Evil bit set\n");
        return;
    }
    unsigned short receivedChecksum = ip->ip_sum;
    ip->ip_sum = 0;
    //printf("Received IP checksum: %d\n", receivedChecksum);
    unsigned short calculatedChecksum = inetChecksum((unsigned short *) ip, 20);
    if (receivedChecksum != calculatedChecksum) {
        //fprintf(stdout, "Invalid IP Checksum\n");
        return;
    }
    ip->ip_sum = receivedChecksum;
    /* check to see we have a packet of valid length */
    if (length < sizeof (struct ip)) {
        //printf("Truncated IP %d", length);
        return;
    }

    len = ntohs(ip->ip_len);
    hlen = IP_HL(ip); /* header length */
    version = ip->ip_v; /* ip version */
    /* check version */
    if (version != 4) {
        //fprintf(stdout, "Unknown IP version %d\n", version);
        return;
    }

    /* check header length */
    if (hlen < 5) {
        //fprintf(stdout, "bad IP HLEN %d \n", hlen);
        return;
    }

    /* see if we have as much packet as we should */
    if (length < len) {
        //printf("Truncated IP - %d bytes missing\n", len - length);
        return;
    }


    /* Check to see if we have the first fragment */
    //off = ntohs(ip->ip_off);
    /*if ((off & 0x1fff) == 0){
        //fprintf(stdout, "IP: ");
        //fprintf(stdout, "%s ",
        //        inet_ntoa(ip->ip_src));
        //fprintf(stdout, "%s %d %d %d %d\n",
        //        inet_ntoa(ip->ip_dst),
        //        hlen, version, len, off);
    }*/

    if (ip->ip_p == 1) {//ICMP packet
        struct icmp* icmp;
        icmp = (struct icmp*) (p + sizeof (struct ether_header) + sizeof (struct iphdr));
        //printf("ICMP type:%d,code:%d,checksum:%d\n", icmp->icmp_type, icmp->icmp_code, icmp->icmp_cksum);
        if (icmp->icmp_type != 0 && icmp->icmp_type != 8) {
            //printf("Invalid ICMP type\n");
            return;
        }
        if (icmp->icmp_code != 0) {
            //printf("Invalid ICMP code\n");
            return;
        }
        unsigned short receivedICMPChecksum = icmp->icmp_cksum;
        //printf("Received ICMP checksum: %d\n", receivedICMPChecksum);
        icmp->icmp_cksum = 0;
        unsigned short calculatedICMPChecksum = inetChecksum((unsigned short *) icmp, (ntohs(ip->ip_len) - 20));
        if (receivedICMPChecksum != calculatedICMPChecksum) {
            //fprintf(stdout, "Invalid ICMP Checksum\n");
            return;
        }
        icmp->icmp_cksum = receivedICMPChecksum;
        processICMPPacket(icmp, ip);
        return;
    } else if (ip->ip_p == 6) {//TCP packet
        processTCPPacket(p, ip);
    }
}

