/*
** SNMPDecodeTest.c - Test sending SNMP UPD packets
   Bruno Chianca Ferreira - PG33878
   The network part is based on Beej's network Tutorial
*/
#include "decoder.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define SNMPDEFPORT "161"    // the port users will be connecting to

#define MAXBUFLEN 64*1024


void printhelp();

FILE *ifd;
char inFile[] = ""; //filename variable
// get sockaddr, IPv4 or IPv6:

void *get_in_addr(struct sockaddr *sa) //gets internet address
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(int argc, char *argv[])
{
    //Check arguments
    if (argc<2){
        fprintf(stderr, "Too few arguments.");
        printhelp();
    }
    
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    int rv;
    size_t numbytes, bytesread;
    struct sockaddr_storage their_addr;
    char *buf;
    socklen_t addr_len;
    char s[INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // set to AF_INET to force IPv4
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    buf=calloc(MAXBUFLEN,sizeof(uint8_t));

    if(strcmp(argv[1],"-f")==0){
        //Using fake agent
        if ((rv = getaddrinfo(NULL, SNMPDEFPORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
        }

        // loop through all the results and bind to the first we can
        for(p = servinfo; p != NULL; p = p->ai_next) {
            if ((sockfd = socket(p->ai_family, p->ai_socktype, //gets file descriptor for the socket
                    p->ai_protocol)) == -1) {
                perror("snmpdecodetest: socket");
                continue;
            }

            if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) { //binds the socket to our address
                close(sockfd);
                perror("snmpdecodetest: bind");
                continue;
            }

            break;
        }

        if (p == NULL) {
            fprintf(stderr, "snmpdecodetest: failed to bind socket\n");
            return 2;
        }

        freeaddrinfo(servinfo);

        printf("snmpdecodetest: snmp fake agent started on port %d...\n",atoi(SNMPDEFPORT));
        while(1){ //creates a infity loop waiting for data on the file descriptor to be read
            addr_len = sizeof their_addr;
            if ((numbytes = recvfrom(sockfd, buf, MAXBUFLEN-1 , 0,(struct sockaddr *)&their_addr, &addr_len)) == -1) {
                perror("recvfrom");
                exit(1);
            }

            printf("snmpdecodetest: received a packet from %s trying to decode as SNMP...\n",
                inet_ntop(their_addr.ss_family,get_in_addr((struct sockaddr *)&their_addr),s, sizeof s));
            printf("snmpdecodetest: received packet is %lu bytes long\n", numbytes);
            snmpbufdecode(buf,numbytes); //Calls function with received buffer and its lenght
            printf("Finished decoding.\n");
            printf("\n");
            printf("Listening again\n");

        }
        close(sockfd);

    }else {
        strcat(inFile,argv[1]); //Using the option parse the buffer file instead
        ifd = fopen(inFile, "rb");
        if (ifd==NULL){
            fprintf(stderr, "Problem trying to open file for reading buffer! Maybe you don't have read permissions or the file does not exist.\n");
            exit(1);
        }
        printf("snmpdecodetest: reading %s\n", inFile);
        bytesread = fread(buf,sizeof(uint8_t),MAXBUFLEN,ifd); //reads file
        printf("snmpdecodetest: read  %lu bytes\n", bytesread);
        snmpbufdecode(buf,bytesread); // calls function with the buffer read and the lenght
        printf("Finished decoding.\n");
        printf("\n");
    }



    return 0;
}

void printhelp(){
    fprintf(stderr,"\n");
    fprintf(stderr,"SNMP Decoder Tester 1.0\n");
    fprintf(stderr,"This software tests the SNMPV2 API part of this package\n");
    fprintf(stderr,"Usage:\n");
    fprintf(stderr,"snmpdecodetest [OPTIONS]:\n");
    fprintf(stderr,"\n");
    fprintf(stderr,"Valid options:\n");
    fprintf(stderr,"-f start a fake agent on port 161\n");
    fprintf(stderr,"[filename] pass as argument a buffer saved in binary format\n");
    fprintf(stderr,"\n");
    exit(1);
}