/* Port Bouncer
 * To be called as nbouncer local_ip local_port remote_ip remote_port
 */

#include "bouncer.h"


void process_pkt(u_char *args, const struct pcap_pkthdr *header,
        const u_char *packet);

char* itoa(int val, int base) {
    static char buf[32] = {0};
    int i = 30;
    for (; val && i; --i, val /= base)
        buf[i] = "0123456789abcdef"[val % base];
    return &buf[i + 1];
}

int main(int argc, char *argv[]) {

    /* Include here your code to initialize the PCAP capturing process */
    if (argc < 6) {
        //printf("Invalid argument set. Usage: ./bouncer.sh <listen_ip> <listen_port> <server_ip> <server_port>\n");
        exit(EXIT_FAILURE);
    }

    bouncerDevice = argv[1];
    bouncerAddress = argv[2];
    bouncerPort = (u_int16_t) atoi(argv[3]);
    serverAddress = argv[4];
    serverPort = (u_int16_t) atoi(argv[5]);

    /*bouncerDevice ="tap0";
    bouncerAddress = "192.168.3.140";
    bouncerPort = 4444;
    serverAddress = "192.168.3.15";
    serverPort = 5555;*/
    
    if (bouncerPort == 0) {
        //printf("Invalid <listen_port>. Usage: ./bouncer.sh <listen_ip> <listen_port> <server_ip> <server_port>\n");
        exit(EXIT_FAILURE);
    } else if (serverPort == 0) {
        //printf("Invalid <server_port>. Usage: ./bouncer.sh <listen_ip> <listen_port> <server_ip> <server_port>\n");
        exit(EXIT_FAILURE);
    }
    //printf("Bouncer Device: %s\n", bouncerDevice);
    //printf("Bouncer Address: %s\n", bouncerAddress);
    //printf("Bouncer Port: %d\n", bouncerPort);
    //printf("Server Address: %s\n", serverAddress);
    //printf("Server Port: %d\n", serverPort);

    pcap_t *pcapHandle; /* Session handle */
    char errorBuffer[PCAP_ERRBUF_SIZE]; /* Error string */
    struct bpf_program compiledFilterExpression; /* The compiled filter expression */
    char filterExpression[] = "ip dst host "; /* The filter expression */
    bpf_u_int32 bouncerDeviceNetmask; /* The netmask of our sniffing device */
    bpf_u_int32 bouncerDeviceIP; /* The IP of our sniffing device */

    strcat(filterExpression, bouncerAddress);

    if (pcap_lookupnet(bouncerDevice, &bouncerDeviceIP, &bouncerDeviceNetmask, errorBuffer) == -1) {
        //printf("Can't get netmask for device %s: %s\n", bouncerDevice, errorBuffer);
        exit(EXIT_FAILURE);
    }
    //printf("Netmask obtained for device %s\n", bouncerDevice);
    pcapHandle = pcap_open_live(bouncerDevice, BUFSIZ, 1, 1, errorBuffer);
    if (pcapHandle == NULL) {
        //printf("Couldn't open device %s: %s\n", bouncerDevice, errorBuffer);
        exit(EXIT_FAILURE);
    }
    //printf("Device %s opened for live capture\n", bouncerDevice);
    if (pcap_compile(pcapHandle, &compiledFilterExpression, filterExpression, 0, bouncerDeviceIP) == -1) {
        //printf("Couldn't parse filter %s: %s\n", filterExpression, pcap_geterr(pcapHandle));
        exit(EXIT_FAILURE);
    }
    //printf("Filter successfully compiled: %s\n", filterExpression);
    if (pcap_setfilter(pcapHandle, &compiledFilterExpression) == -1) {
        //printf("Couldn't install filter %s: %s\n", filterExpression, pcap_geterr(pcapHandle));
        exit(EXIT_FAILURE);
    }
    //printf("Filter successfully installed\n");
    pcap_freecode(&compiledFilterExpression);
    pcap_loop(pcapHandle, 0, process_pkt, NULL);
    pcap_close(pcapHandle);
    return (0);
}//End of the bouncer   
