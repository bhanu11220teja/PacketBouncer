
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "bouncer.h"

struct icmp_node {
    int id, seq_num;
    uint32_t inAddr;
    struct icmp_node *next;
};

struct icmp_node *head = NULL;
struct icmp_node *curr = NULL;

void print_list(void) {
    struct icmp_node *ptr = head;

    //printf("\n -------Printing list Start------- \n");
    while (ptr != NULL) {
        //printf("\n [%d]:[%d] \n", ptr->id, ptr->seq_num);
        ptr = ptr->next;
    }
    //printf("\n -------Printing list End------- \n");

    return;
}

struct icmp_node* create_list(int id, int seq_num, uint32_t inAddr) {
    //printf("\n creating list with head node as [%d]\n", id);
    struct icmp_node *ptr = (struct icmp_node*) malloc(sizeof (struct icmp_node));
    if (NULL == ptr) {
        //printf("\n Node creation failed \n");
        return NULL;
    }
    ptr->id = id;
    ptr->seq_num = seq_num;
    ptr->inAddr = inAddr;
    ptr->next = NULL;

    head = curr = ptr;
    return ptr;
}

struct icmp_node* add_to_list(int id, int seq_num, uint32_t inAddr) {
    if (NULL == head) {
        return (create_list(id, seq_num, inAddr));
    }

    struct icmp_node *ptr = (struct icmp_node*) malloc(sizeof (struct icmp_node));
    if (NULL == ptr) {
        //printf("\n Node creation failed \n");
        return NULL;
    }
    ptr->id = id;
    ptr->seq_num = seq_num;
    ptr->inAddr = inAddr;
    /*ptr->next = NULL;

    curr->next = ptr;
    curr = ptr;*/
    ptr->next=head->next;
    head=ptr;
    return ptr;
}

uint32_t search_in_list(int id, int seq_num) {
    struct icmp_node *ptr = head;
//    struct icmp_node *tmp = NULL;
    bool found = false;
    uint32_t result = 0;

    //printf("\n Searching the list for *input [%d][%d] \n", id, seq_num);
    print_list();
    while (ptr != NULL && !found) {
        ////printf("Inside ptr: [%d]\n", ptr->id);
        if (ptr->id == id && ptr->seq_num == seq_num) {
            found = true;
        } else {
//            tmp = ptr;
            ptr = ptr->next;
        }
    }

    if (true == found) {
        result = ptr->inAddr;
        /*if (tmp != NULL) {
            tmp->next = ptr->next;
        } else{
            head = NULL;
        }
        free(ptr);
        curr = tmp;*/
    }
    return result;
}