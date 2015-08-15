#include "bouncer.h"

struct TCPConn *Head = NULL;

struct TCPConn *searchServerConnection(int_16 destinationPort){
   struct TCPConn *curr; 
   if(Head == NULL) {
      return NULL;
   }
   curr = Head;
   while(curr != NULL) {
      if(curr->dummyPort == destinationPort) {
         return curr;
      }
      curr=curr->next;  
   }  
   return NULL;    
}

struct TCPConn *searchClientConnection(int_16 senderPort, u_int32_t clientAddr) {
   struct TCPConn *curr;  
   if(Head == NULL) {
      return NULL;
   }  
   curr = Head;   
   while(curr != NULL) {
      if(curr->sourcePort == senderPort && curr->address == clientAddr) {
         return curr;
      }
      curr=curr->next;  
   }  
   return NULL;  
}  

void addNewTCPConnection(int_16 senderPort, int_16 bouncerPort, int_32 addr, int data){  
   struct TCPConn *temp = (struct TCPConn*)malloc(sizeof(struct TCPConn));  
   temp->sourcePort = senderPort;  
   temp->dummyPort = bouncerPort;  
   temp->address = addr;
   temp->isData = data;
   temp->counterFin = 2;
   if (data == 1) {
      temp->isActive = 0;
   } else {
      temp->isActive = 1;
   }
   if (Head == NULL) {  
      Head=temp;  
      Head->next=NULL;  
   }else {  
      temp->next=Head;  
      Head=temp; 
   }
     
}   

void deleteTCPConnection(struct TCPConn *node){
   struct TCPConn *curr, *tempNode;
   if(Head == NULL) {
      return;
   }
   if (node == Head) {
      tempNode = Head;
      Head = Head->next;
      free(tempNode);
      tempNode = NULL;
      return;
   }
   curr = Head;
   while(curr->next != NULL) {  
      if(curr->next == node){
         tempNode = curr->next;
         curr->next = tempNode->next;
         free(tempNode);
         tempNode = NULL;
         return;
      }
      curr=curr->next;
   }
}
