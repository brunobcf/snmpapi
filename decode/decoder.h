/*
** decoder.c - API for enconding SNMP PDUs
   Bruno Chianca Ferreira - PG33878
   Made heavily with the help of ASN1C compiler
*/
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <stdlib.h>    
#include <getopt.h>   
#include <string.h>   
#include <sysexits.h>    
#include <errno.h>   
#include <unistd.h>  
#include "asn1c.h"

#define MAXSNMP 64*1024
#define SNMP_MSG_OID_END ((uint32_t) -1)

struct snmpbuffer{
    uint8_t *_buffer;
    int _size;
};

struct longoid{
    uint32_t *buf;
    int size;
};

struct decodedPDU_t{
    uint8_t pdu_type;
    struct longoid oid_type;
    uint8_t obj_type;
    uint8_t sintax_type;
};



OBJECT_IDENTIFIER_t snmpOIDencoder(uint32_t _oid[]);
Counter64_t scountertoicounter(char *_optarg);
uint32_t *soidtonoid(char *_optarg);
IpAddress_t siptonip(char *_optarg);
int snmpbufdecode(uint8_t *_buffer_final, size_t _buffer_final_size);
struct decodedPDU_t decodePDU(PDUs_t *_pdu,VarBind_t* _var_bind,ObjectSyntax_t _objectSyntax,SimpleSyntax_t _simpleSyntax);
struct longoid snmpOIDdecoder(VarBind_t* _var_bind);
struct longoid snmpOIDdecoderOIDtype(OBJECT_IDENTIFIER_t _oid);
static char to_printable();
int hexdump_line(const char *data, const char *data_start, const char *data_end);
void hexdump(const char *title, const void *data, size_t len);
int filedump_line(const char *data, const char *data_start, const char *data_end, FILE *_ofd);
void filedump(const char *title, const void *data, size_t len, FILE *_ofd);
