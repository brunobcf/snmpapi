/*
** encoder.h - API for enconding SNMP PDUs
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

struct snmpbuffer snmpSetRequestInt(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, int value, int _verbose_flag, int _version);
struct snmpbuffer snmpSetRequestStr(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, OCTET_STRING_t value, int _verbose_flag, int _version);
struct snmpbuffer snmpSetRequestOid(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, OBJECT_IDENTIFIER_t value, int _verbose_flag, int _version);
struct snmpbuffer snmpSetRequestIp(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, IpAddress_t value, int _verbose_flag, int _version);
struct snmpbuffer snmpSetRequestCounter(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, Counter32_t value, int _verbose_flag, int _version);
struct snmpbuffer snmpSetRequestBigCounter(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, Counter64_t value, int _verbose_flag, int _version);
struct snmpbuffer snmpSetRequestTicks(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, TimeTicks_t value, int _verbose_flag, int _version);
struct snmpbuffer snmpSetRequestUint(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, Unsigned32_t value, int _verbose_flag, int _version);
struct snmpbuffer snmpSetRequest (OCTET_STRING_t community, int tag, int _verbose_flag, int _version, VarBind_t* _var_bind );
struct snmpbuffer snmpGetRequest(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, int _verbose_flag, int _version);
struct snmpbuffer snmpGetNextRequest(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, int _verbose_flag, int _version);
struct snmpbuffer snmpGetBulkRequest(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, int _verbose_flag, int _version, long _max_repeaters, long _non_repeaters);
struct snmpbuffer snmpResponseInt(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, int value, int _verbose_flag, int _version);
struct snmpbuffer snmpResponseStr(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, OCTET_STRING_t value, int _verbose_flag, int _version);
struct snmpbuffer snmpResponseOid(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, OBJECT_IDENTIFIER_t value, int _verbose_flag, int _version);
struct snmpbuffer snmpResponseIp(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, IpAddress_t value, int _verbose_flag, int _version);
struct snmpbuffer snmpResponseCounter(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, Counter32_t value, int _verbose_flag, int _version);
struct snmpbuffer snmpResponseBigCounter(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, Counter64_t value, int _verbose_flag, int _version);
struct snmpbuffer snmpResponseTicks(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, TimeTicks_t value, int _verbose_flag, int _version);
struct snmpbuffer snmpResponseUint(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, Unsigned32_t value, int _verbose_flag, int _version);
struct snmpbuffer snmpResponseError(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, char *_response_error, int _verbose_flag, int _version);
struct snmpbuffer snmpResponse(OCTET_STRING_t community, int tag, int _verbose_flag, int _version,VarBind_t* _var_bind);
OBJECT_IDENTIFIER_t snmpOIDencoder(uint32_t _oid[]);
Counter64_t scountertoicounter(char *_optarg);
uint32_t *soidtonoid(char *_optarg);
IpAddress_t siptonip(char *_optarg);
static char to_printable();
int hexdump_line(const char *data, const char *data_start, const char *data_end);
void hexdump(const char *title, const void *data, size_t len);
int filedump_line(const char *data, const char *data_start, const char *data_end, FILE *_ofd);
void filedump(const char *title, const void *data, size_t len, FILE *_ofd);
