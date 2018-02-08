/*
** SNMPTest.c - Test sending SNMP UPD packets
   Bruno Chianca Ferreira - PG33878
   The network part is based on Beej's network Tutorial
*/

#include "encoder.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <getopt.h>
#include <string.h>
#include <malloc.h>

#define SNMPDEFPORT "161"    // the port users will be connecting to
#define SNMPDEFTAG 1
#define SNMPDEFVERSION 2


FILE *ofd;
OCTET_STRING_t community,value_str;
Counter32_t value_counter;
Counter64_t value_bigcounter;
IpAddress_t value_ip;
TimeTicks_t value_ticks;
Unsigned32_t value_uinteger;
OBJECT_IDENTIFIER_t value_oid, oid_buffer;
char *hostdest,*snmppdu,*snmpporta, *snmpsintax,*outFile, *value_error;
char validsintax[9][15]= {"integer", "string", "objectid", "ip", "counter", "ticks", "bigcounter", "uinteger", "response_error"};
char validpdus[5][15]= {"getrequest", "setrequest", "getnextrequest", "response", "getbulkrequest"};
uint32_t *oid;
int c,tag=SNMPDEFTAG,version=SNMPDEFVERSION, value_int;
long max_rep=0, non_rep=0;
static int verbose_flag=0,filedump_flag=0;
struct snmpbuffer buf;


void printhelp();
void checkopts(int _argc, char *_argv[]);
struct snmpbuffer execpdu(char *_snmppdu, char *_snmpsintax);

int main(int argc, char *argv[])
{

    if (argc < 2) { //too few arguments, call help and quit
        printhelp();
    }
    
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    int rv;
    int numbytes;
    size_t byteswritten;
    value_error = calloc(256,sizeof(char));
    
  
    checkopts(argc, argv); //check options passed as parameters

    if (snmpporta==NULL){
        snmpporta = (char *) malloc(sizeof(char)*10);
        snmpporta = SNMPDEFPORT;
    }

    if (community.buf==NULL){
        community.buf="private"; //user private if none is passed as parameter
        community.size=7;
    }
    //some sanity testing
    if (snmppdu==NULL){
        fprintf(stderr,"\nDefining the desired pdu is obligatory.\n");
        fprintf(stderr,"\n");
        printhelp();
    }

    if ((snmpsintax==NULL)&&(!strcmp(snmppdu,"setrequest"))){
        fprintf(stderr,"\nDefining the desired sintax is obligatory.\n");
        fprintf(stderr,"\n");
        printhelp();
    }
    if ((snmpsintax==NULL)&&(!strcmp(snmppdu,"response"))){
        fprintf(stderr,"\nDefining the desired sintax is obligatory.\n");
        fprintf(stderr,"\n");
        printhelp();
    }
    if ((non_rep==0)&&(max_rep==0)&&(!strcmp(snmppdu,"getbulkrequest"))){
        fprintf(stderr,"\nPlease define the repeaters configuration, both values can't be 0 when using bulk request.\n");
        fprintf(stderr,"\n");
        printhelp();
    }
    if (oid==NULL){
        fprintf(stderr,"\nDefining the desired oid is obligatory.\n");
        fprintf(stderr,"\n");
        printhelp();
    }
    //encondes the oid
    oid_buffer=snmpOIDencoder(oid);

    //check the parameters in order to know which function use from the API
    buf = execpdu(snmppdu,snmpsintax);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    
    if ((rv = getaddrinfo(hostdest, snmpporta, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and make a socket
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,p->ai_protocol)) == -1) {
            perror("snmptest: socket");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "snmptest: failed to create socket\n");
        return 2;
    }

    //sends the buffer in the socket
    if ((numbytes = sendto(sockfd, buf._buffer, buf._size, 0,
             p->ai_addr, p->ai_addrlen)) == -1) {
        perror("snmptest: sendto");
        exit(1);
    }

    printf("snmptest: sent %d bytes to %s\n", numbytes, hostdest);

    //file user requires the file dump...
    if (filedump_flag){
        ofd = fopen(outFile, "wb");
        if (ofd==NULL){
            fprintf(stderr, "Problem trying to open file for saving buffer! Maybe you don't have write permissions.\n");
            exit(1);
        }
        printf("snmptest: exporting %d bytes to %s\n", numbytes, outFile);
        byteswritten = fwrite(buf._buffer, sizeof(uint8_t),buf._size,ofd);
        printf("snmptest: written %lu bytes to %s\n", byteswritten, outFile);
        fclose(ofd);
    }

    freeaddrinfo(servinfo);
    //closing out file descriptors
    close(sockfd);

    return 0;
}


void printhelp(){
    fprintf(stderr,"\n");
    fprintf(stderr,"SNMP Tester 1.0\n");
    fprintf(stderr,"This software tests the SNMPV2 API part of this package\n");
    fprintf(stderr,"Usage:\n");
    fprintf(stderr,"snmptest [OPTIONS]:\n");
    fprintf(stderr,"\n");
    fprintf(stderr,"Valid options:\n");
    fprintf(stderr,"-a --address [IP Adress or hostname]\n");
    fprintf(stderr,"-p --port [SNMP port (161 default)]\n");
    fprintf(stderr,"-c --community [commnunity string]\n");
    fprintf(stderr,"-i --implementation [snmp version (only 2 suported now)]\n");
    fprintf(stderr,"-u --pdu [getrequest, getnextrequest, getbulkrequest, setrequest, response]\n");
    fprintf(stderr,"-o --oid [oid to be used]\n");
    fprintf(stderr,"-s --sintax [integer, string, objectid, ip, counter, ticks, bigcounter, uinteger, reponse_error]\n");
    fprintf(stderr,"-v --value [value]\n");
    fprintf(stderr,"-t --tag [value]\n");
    fprintf(stderr,"-f --filedump [filename]\n");
    fprintf(stderr,"-m --maxrepeaters [repeaters]\n");
    fprintf(stderr,"-n --nonrepeaters [nonrepeaters]\n");
    fprintf(stderr,"-h --help Print this help\n");
    fprintf(stderr,"--verbose\n");
    fprintf(stderr,"\n");
    exit(1);
}

void checkopts(int _argc, char *_argv[]){
    
    while (1){
      static struct option long_options[] =
        {
          /* These options set a flag. */
          {"verbose", no_argument,   &verbose_flag, 1},
          {"help", no_argument,   0, 'h'},
          /* These options don’t set a flag.
             We distinguish them by their indices. */
          {"value",         required_argument, 0, 'v'},
          {"sintax",        required_argument, 0, 's'},
          {"pdu",           required_argument, 0, 'u'},
          {"community",     required_argument, 0, 'c'},
          {"implementation",required_argument, 0, 'i'},
          {"adress",        required_argument, 0, 'a'},
          {"port",          required_argument, 0, 'p'},
          {"oid",           required_argument, 0, 'o'},
          {"tag",           required_argument, 0, 't'},
          {"filedump",      required_argument, 0, 'f'},
          {"maxrepeaters",  required_argument, 0, 'm'},
          {"nonrepeaters",  required_argument, 0, 'n'},
          {0, 0, 0, 0}
        };
      /* getopt_long stores the option index here. */
      int option_index = 0;

      c = getopt_long (_argc, _argv, "hv:s:c:p:i:a:o:u:t:f:m:n:",
                       long_options, &option_index);

      /* Detect the end of the options. */
      if (c == -1)
        break;

      switch (c)
        {
        case 0:
          /* If this option set a flag, do nothing else now. */
          if (long_options[option_index].flag != 0)
            break;
          printf ("option %s", long_options[option_index].name);
          if (optarg)
            printf (" with arg %s", optarg);
          printf ("\n");
          break;

        case 'a':
        {
            hostdest = (char *) malloc(sizeof(char)*strlen(optarg));
            strcat(hostdest,optarg); //gets destination host
            break;
        }
        case 'c':
            community.buf = optarg; //gets community string
            community.size =strlen(optarg);
            break;
        case 'i':
        {
            version = atoi(optarg); //gets snmp version
            break;
        }
        case 'm':
        {
            max_rep = atol(optarg); //gets max repetitions for bulk request
            break;
        }
        case 'n':
        {
            non_rep = atol(optarg); //gets non repeaters for bulk request
            break;
        }
        case 'h':
        {
            printhelp(); //prints help
            break;
        }
        case 'f':
        {
            outFile = calloc (256, sizeof(char));
            strcat(outFile,optarg); //gets filename for buffer dump
            filedump_flag = 1;
            break;
        }
        case 'u':
        {
            snmppdu = (char *) malloc(sizeof(char)*strlen(optarg));
            strcat(snmppdu,optarg); //gets pdu to be used
            int key=0;
            for (int i=0;i<5;i++){
                if (strcmp(validpdus[i],snmppdu)==0){ //check if it's a valid pdu
                    key=1;
                }    
            }
            if (key==0) {
                fprintf(stderr,"Invalid pdu\n");
                exit(1);
            }
            break;
        }
        case 'p':
        {
            snmpporta = (char *) malloc(sizeof(char)*strlen(optarg));
            strcat(snmpporta,optarg); //gets port to be used
            break;
        }
        case 'o':
        {
            oid = calloc(1024,sizeof(int));
            oid = soidtonoid(optarg); //gets oid
            break;
        }
        case 's':
            snmpsintax = (char *) malloc(sizeof(char)*strlen(optarg));
            strcat(snmpsintax,optarg); //gets sintax
            int key=0;
            for (int i=0;i<9;i++){
                if (strcmp(validsintax[i],snmpsintax)==0){ //check if it is a valid sintax
                    key=1;
                }    
            }
            if (key==0) {
                fprintf(stderr,"Invalid sintax\n");
                printhelp();
            }
            break;
        case 'v':{
            
            if(snmpsintax==NULL){ //check if the sintax has been defined before getting the value
                fprintf(stderr,"The sintax needs to be defined before the value.\n");
            }
            else {
                if (!strcmp(snmpsintax,"integer")){
                    value_int = atoi(optarg);
                }
                else if(!strcmp(snmpsintax,"string")){
                    value_str.buf = optarg;
                    value_str.size = strlen(optarg);
                }
                else if(!strcmp(snmpsintax,"objectid")){  
                    value_oid=snmpOIDencoder(soidtonoid(optarg));
                }
                else if(!strcmp(snmpsintax,"ip")){  
                    value_ip=siptonip(optarg);
                }
                else if(!strcmp(snmpsintax,"counter")){  
                    value_counter=(uint32_t)atoi(optarg);
                }
                else if(!strcmp(snmpsintax,"bigcounter")){  
                    value_bigcounter=scountertoicounter(optarg);
                }
                else if(!strcmp(snmpsintax,"ticks")){  
                    value_ticks=atoi(optarg);
                }
                else if(!strcmp(snmpsintax,"uinteger")){  
                    value_uinteger=atoi(optarg);
                }
                else if(!strcmp(snmpsintax,"response_error")){  
                    strcat(value_error,optarg);
                }
            }
            break;
        } 
        case 't':
        {
            tag = atoi(optarg); //gets the tag
            break;
        }
        case '?':
          printhelp(); //if invalid option, prints help
          break;

        default:
          abort ();
        }
    }
}
/*#################################################################
Function that chooses the correct function based on pdu
*/
struct snmpbuffer execpdu(char *_snmppdu, char *_snmpsintax){ 
    //printf("%s, %s\n",_snmppdu, _snmpsintax);
    struct snmpbuffer _buf;
    
    if (!strcmp(_snmppdu,"setrequest")){ //if set, choose sintax
        
        if (!strcmp(_snmpsintax,"integer")){
            
            _buf = snmpSetRequestInt(community, tag, oid_buffer,value_int, verbose_flag, version);
        }
        else if (!strcmp(_snmpsintax,"string")){
            
            _buf = snmpSetRequestStr(community, tag, oid_buffer,value_str, verbose_flag, version);
        }
        else if (!strcmp(_snmpsintax,"objectid")){
            
            _buf = snmpSetRequestOid(community, tag, oid_buffer,value_oid, verbose_flag, version);
        }
        else if (!strcmp(_snmpsintax,"ip")){
            
            _buf = snmpSetRequestIp(community, tag, oid_buffer,value_ip, verbose_flag, version);
        }
        else if (!strcmp(_snmpsintax,"counter")){
            
            _buf = snmpSetRequestCounter(community, tag, oid_buffer,value_counter, verbose_flag, version);
        }
        else if (!strcmp(_snmpsintax,"ticks")){
            
            _buf = snmpSetRequestTicks(community, tag, oid_buffer,value_ticks, verbose_flag, version);
        }
        else if (!strcmp(_snmpsintax,"bigcounter")){
            
            _buf = snmpSetRequestBigCounter(community, tag, oid_buffer,value_bigcounter, verbose_flag, version);
        }
        else if (!strcmp(_snmpsintax,"uinteger")){
            
            _buf = snmpSetRequestUint(community, tag, oid_buffer,value_uinteger, verbose_flag, version);
        }
    }
    else if(!strcmp(_snmppdu,"getrequest")){
        _buf  = snmpGetRequest(community, tag, oid_buffer,verbose_flag, version);
    }
    else if(!strcmp(_snmppdu,"getnextrequest")){
        _buf  = snmpGetNextRequest(community, tag, oid_buffer,verbose_flag, version);
    }
    else if(!strcmp(_snmppdu,"getbulkrequest")){
        _buf  = snmpGetBulkRequest(community, tag, oid_buffer,verbose_flag, version, max_rep, non_rep);
    }
        
    else if (!strcmp(_snmppdu,"response")){ //if response choose sintax
        
        
        if (!strcmp(_snmpsintax,"integer")){
            
            _buf = snmpResponseInt(community, tag, oid_buffer,value_int, verbose_flag, version);
        }
        else if (!strcmp(_snmpsintax,"string")){
            
            _buf = snmpResponseStr(community, tag, oid_buffer,value_str, verbose_flag, version);
        }
        else if (!strcmp(_snmpsintax,"objectid")){
            
            _buf = snmpResponseOid(community, tag, oid_buffer,value_oid, verbose_flag, version);
        }
        else if (!strcmp(_snmpsintax,"ip")){
            
            _buf = snmpResponseIp(community, tag, oid_buffer,value_ip, verbose_flag, version);
        }
        else if (!strcmp(_snmpsintax,"counter")){
            
            _buf = snmpResponseCounter(community, tag, oid_buffer,value_counter, verbose_flag, version);
        }
        else if (!strcmp(_snmpsintax,"ticks")){
            
            _buf = snmpResponseTicks(community, tag, oid_buffer,value_ticks, verbose_flag, version);
        }
        else if (!strcmp(_snmpsintax,"bigcounter")){
            
            _buf = snmpResponseBigCounter(community, tag, oid_buffer,value_bigcounter, verbose_flag, version);
        }
        else if (!strcmp(_snmpsintax,"uinteger")){
            
            _buf = snmpResponseUint(community, tag, oid_buffer,value_uinteger, verbose_flag, version);
        }
        else if (!strcmp(_snmpsintax,"response_error")){
                        
            _buf = snmpResponseError(community, tag, oid_buffer,value_error, verbose_flag, version);
        }
        else {
            printf("Unknown sintax\n");
            printhelp();
        }
            
    }
    
    return _buf;
}

