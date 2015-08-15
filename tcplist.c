
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "bouncer.h"

struct tcp_node {
    int bouncerPort, sourcePort;
    int bouncerDataPort, sourceDataPort, serverDataPort;
    bool isFTP;
    uint32_t inAddr;
    struct tcp_node *next;
};

struct tcp_node *tcp_head = NULL;
struct tcp_node *tcp_curr = NULL;

void print_tcp_list(void) {
    struct tcp_node *ptr = tcp_head;

    //printf("\n -------Printing list Start------- \n");
    while (ptr != NULL) {
        //printf("\n [%d]:[%d]:[%d]:bouncerDataPort[%d]:sourceDataPort[%d] \n", ptr->bouncerPort, ptr->sourcePort, ptr->inAddr, ptr->bouncerDataPort, ptr->sourceDataPort);
        ptr = ptr->next;
    }
    //printf("\n -------Printing list End------- \n");

    return;
}

struct tcp_node* create_tcp_list(int bouncerPort, int sourcePort, uint32_t inAddr) {
    //printf("\n creating list with tcp_head node as [%d]\n", bouncerPort);
    struct tcp_node *ptr = (struct tcp_node*) malloc(sizeof (struct tcp_node));
    if (NULL == ptr) {
        //printf("\n Node creation failed \n");
        return NULL;
    }
    ptr->bouncerPort = bouncerPort;
    ptr->sourcePort = sourcePort;
    ptr->inAddr = inAddr;
    ptr->next = NULL;

    tcp_head = tcp_curr = ptr;
    return ptr;
}

struct tcp_node* add_to_tcp_list(int bouncerPort, int sourcePort, uint32_t inAddr) {
    if (NULL == tcp_head) {
        return (create_tcp_list(bouncerPort, sourcePort, inAddr));
    }

    struct tcp_node *ptr = (struct tcp_node*) malloc(sizeof (struct tcp_node));
    if (NULL == ptr) {
        //printf("\n Node creation failed \n");
        return NULL;
    }
    ptr->bouncerPort = bouncerPort;
    ptr->sourcePort = sourcePort;
    ptr->inAddr = inAddr;
    ptr->isFTP = false;
    ptr->serverDataPort = -1;
    /*ptr->next = NULL;

    tcp_curr->next = ptr;
    tcp_curr = ptr;*/

    ptr->next = tcp_head->next;
    tcp_head = ptr;

    return ptr;
}

struct tcp_node* search_in_tcp_list(int sourcePort, uint32_t inAddr, int bouncerPort) {
    struct tcp_node *ptr = tcp_head;

    //printf("\n Searching the list for source port [%d] source IP [%d] bouncerPort [%d]\n", sourcePort, inAddr, bouncerPort);
    print_tcp_list();
    while (ptr != NULL) {
        if (bouncerPort == 0) {
            if (ptr->inAddr == inAddr && (ptr->sourcePort == sourcePort || ptr->sourceDataPort == sourcePort)) {
                return ptr;
            } else {
                ptr = ptr->next;
            }
        } else {
            if (ptr->bouncerPort == bouncerPort || ptr->bouncerDataPort == bouncerPort) {
                return ptr;
            } else {
                ptr = ptr->next;
            }
        }
    }
    return NULL;
}

void delete_tcp_node(int bouncerPort) {
    struct tcp_node *ptr = tcp_head;
    struct tcp_node *tmp = NULL;
    bool found = false;

    while (ptr != NULL && !found) {
        if (ptr->bouncerPort == bouncerPort) {
            found = true;
        } else {
            tmp = ptr;
            ptr = ptr->next;
        }
    }
    if (true == found) {
        if (tmp != NULL) {
            tmp->next = ptr->next;
        } else {
            tcp_head = NULL;
        }
        free(ptr);
        tcp_curr = tmp;
    }
}