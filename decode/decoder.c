/*
** decoder.c - API for enconding SNMP PDUs
   Bruno Chianca Ferreira - PG33878
   Made heavily with the help of ASN1C compiler
*/

#include "decoder.h"


char valid_pdus[6][16] = {"response_excep","getrequest","getnextrequest","getbulkrequest","response","setrequest"}; 
char valid_object[3][15] = {"","simple","application"};
char valid_simple[4][15] = {"","integer","string","objectid"};
char valid_app[7][15] = {"","ip","counter","ticks","","bigcounter","uinteger"};

/*##################################################################################
Function that decodes the snmp buffer
*/
int snmpbufdecode(uint8_t *_buffer_final, size_t _buffer_final_size){

    Message_t *message = 0;
    PDUs_t* pdu = 0;
    struct decodedPDU_t decodedPDU;
    asn_dec_rval_t rval = asn_decode(0, ATS_BER, &asn_DEF_Message,(void **)&message, _buffer_final, _buffer_final_size);
     //Check error code from asn decode function
    if (rval.code==2){
        fprintf(stderr, "Failed to decode packet as SNMP.\n");
        return 1;
    }
    else if (rval.code==1){
        fprintf(stderr, "More data expected, call again.\n");
        return 1;
    }
    printf("Seems like a valid SNMP packet. Decoding... \n");

    rval = asn_decode(0, ATS_BER, &asn_DEF_PDUs, (void **)&pdu, message->data.buf, message->data.size);
     //Check error code from asn decode function
    if (rval.code==2){
        fprintf(stderr, "Failed to decode PDU.\n");
        return 1;
    }
    else if (rval.code==1){
        fprintf(stderr, "More data expected, call again.\n");
        return 1;
    }
    printf("Seems like a valid PDU. Decoding... \n");
    //Prints community string
    printf("Community string: ");
    for (int i=0;i<message->community.size;i++){
        printf ("%c",message->community.buf[i]);
    }
    printf ("\n");
    printf("SNMP Protocol version: %lu\n",message->version);
    VarBindList_t var_bindings = pdu->choice.set_request.variable_bindings;
    int var_list_size = var_bindings.list.count;
    VarBind_t* var_bind = var_bindings.list.array[0];
    ObjectSyntax_t objectSyntax = var_bind->choice.choice.value;
    SimpleSyntax_t simpleSyntax = objectSyntax.choice.simple;
    ApplicationSyntax_t applicationSyntax = objectSyntax.choice.application_wide;

    //Calls function to decode the PDU received

    decodedPDU = decodePDU(pdu, var_bind, objectSyntax, simpleSyntax ); //Works with the simpleSyntax even if it's application
    printf ("Type of pdu: %s\n",valid_pdus[decodedPDU.pdu_type]);
    printf ("Type of object: %s\n",valid_object[decodedPDU.obj_type]);
   
    if (decodedPDU.oid_type.size==0){
        fprintf(stderr, "Error. No OID included in the packet.\n");
        return 1;
    }
    printf ("OID: ");
    for (int i = 0; i<decodedPDU.oid_type.size-1;i++){
        printf ("%d.",decodedPDU.oid_type.buf[i]);
    }
    printf ("%d\n",decodedPDU.oid_type.buf[decodedPDU.oid_type.size-1]);
    if (decodedPDU.obj_type==1){ //If simple
        printf ("Type of sintax: %s\n",valid_simple[decodedPDU.sintax_type]);
        
        if (decodedPDU.sintax_type==1){
            printf ("Value: %lu\n",simpleSyntax.choice.integer_value);
        }
        else if (decodedPDU.sintax_type==2) {
            printf ("Value: ");
            for (int i=0;i<simpleSyntax.choice.string_value.size;i++){
                printf ("%c",simpleSyntax.choice.string_value.buf[i]);
            }
            printf ("\n");
        }
        else if (decodedPDU.sintax_type==3) {
            printf ("Value: ");
            for (int i=0;i<snmpOIDdecoderOIDtype(simpleSyntax.choice.objectID_value).size-1;i++){
                printf ("%d.",snmpOIDdecoderOIDtype(simpleSyntax.choice.objectID_value).buf[i]);
            }
            printf ("%d\n",snmpOIDdecoderOIDtype(simpleSyntax.choice.objectID_value).buf[snmpOIDdecoderOIDtype(simpleSyntax.choice.objectID_value).size-1]);
        }      
    }
    else if (decodedPDU.obj_type==2){ //If application
        printf ("Type of sintax: %s\n",valid_app[decodedPDU.sintax_type]);

        if (decodedPDU.sintax_type==1){
            printf ("Value: ");
            for (int i=0;i<applicationSyntax.choice.ipAddress_value.size-1;i++){
                printf ("%d.",applicationSyntax.choice.ipAddress_value.buf[i]);
            }
            printf ("%d\n",applicationSyntax.choice.ipAddress_value.buf[applicationSyntax.choice.ipAddress_value.size-1]);
        }
        else if (decodedPDU.sintax_type==2){
            printf ("Value: %lu\n",applicationSyntax.choice.counter_value);
        }
        else if (decodedPDU.sintax_type==3){
            printf ("Value: %lu\n",applicationSyntax.choice.timeticks_value);
        }
        else if (decodedPDU.sintax_type==5) {
            printf ("Value: ");
            for (int i=0;i<applicationSyntax.choice.big_counter_value.size;i++){
                printf ("%d",applicationSyntax.choice.big_counter_value.buf[i]);
            }
            printf ("\n");
        }
        else if (decodedPDU.sintax_type==6){
            printf ("Value: %lu\n",applicationSyntax.choice.unsigned_integer_value);
        }
    }
    return 0;
}
/*##################################################################################
Function that decodes pdu received
*/
struct decodedPDU_t decodePDU(PDUs_t *_pdu,VarBind_t* _var_bind,ObjectSyntax_t _objectSyntax,SimpleSyntax_t _simpleSyntax){
    struct decodedPDU_t _decodedPDU;
    _decodedPDU.pdu_type = _pdu->present;
    _decodedPDU.obj_type = _objectSyntax.present;
    _decodedPDU.sintax_type = _simpleSyntax.present;
    _decodedPDU.oid_type = snmpOIDdecoder(_var_bind);
    return _decodedPDU;
}
/*##################################################################################
Function that decodes the oid received
*/
struct longoid snmpOIDdecoder(VarBind_t* _var_bind){
    /*Function to convert a snmp coded oid in regular uin32_t oid. For some reason can go over 16383. to check*/
    struct longoid decodedOID;
    int oidindex=0;
    int coidindex=0;
    decodedOID.buf = calloc (_var_bind->name.size, sizeof(uint32_t));
    for (int i=0;i<_var_bind->name.size;i++){
        decodedOID.buf[i]=0;
    }
    decodedOID.buf[oidindex]=(int)_var_bind->name.buf[coidindex]/40;
    oidindex++;
    decodedOID.buf[oidindex]=(_var_bind->name.buf[coidindex])%40;
    oidindex++;
    coidindex++;
    while(coidindex<_var_bind->name.size){
        if (_var_bind->name.buf[coidindex]&0x80) {
            decodedOID.buf[oidindex]=_var_bind->name.buf[coidindex]&0x7F;
            decodedOID.buf[oidindex]=decodedOID.buf[oidindex]<<7;
            coidindex++;
        }
        else {
            decodedOID.buf[oidindex]=decodedOID.buf[oidindex]|(_var_bind->name.buf[coidindex]&0x7F);
            oidindex++;
            coidindex++;
        }
    }
    decodedOID.size = oidindex;
    return decodedOID;
}
/*##################################################################################
Function that changes variable type of the OID
*/
struct longoid snmpOIDdecoderOIDtype(OBJECT_IDENTIFIER_t _oid){
    /*Function to convert a snmp coded oid in regular uin32_t oid. For some reason can go over 16383. to check*/
    struct longoid decodedOID;
    int oidindex=0;
    int coidindex=0;
    decodedOID.buf = calloc (_oid.size, sizeof(uint32_t));
    for (int i=0;i<_oid.size;i++){
        decodedOID.buf[i]=0;
    }
    decodedOID.buf[oidindex]=(int)_oid.buf[coidindex]/40; // This is an approximation, but snmp should always start with 1.3.XXXXXX
    oidindex++;
    decodedOID.buf[oidindex]=(_oid.buf[coidindex])%40; // This is an approximation, but snmp should always start with 1.3.XXXXXX
    oidindex++;
    coidindex++;
    while(coidindex<_oid.size){
        if (_oid.buf[coidindex]&0x80) { //Checks if carry is set to 1
            decodedOID.buf[oidindex]=_oid.buf[coidindex]&0x7F; //Extracts data
            decodedOID.buf[oidindex]=decodedOID.buf[oidindex]<<7; //Shifts to the left since it is most significative
            coidindex++;
        }
        else {
            decodedOID.buf[oidindex]=decodedOID.buf[oidindex]|(_oid.buf[coidindex]&0x7F); //Preservs the ones that were shifted (if any) and gets the last current value
            oidindex++;
            coidindex++;
        }
    }
    decodedOID.size = oidindex;
    return decodedOID;
}


/*#################################################################
Converts the oid in array of uint32_t format to OBJECT_IDENTIFIER_t
*/
OBJECT_IDENTIFIER_t snmpOIDencoder(uint32_t *_oid){
    unsigned int n=0;
    uint32_t *reverse_oid;
    int counter=0;
    OBJECT_IDENTIFIER_t _oid_buffer;
    //Start by counting the size of the oid
    while (_oid[n]!=SNMP_MSG_OID_END){
        n++;
    }
    reverse_oid = (uint32_t*) malloc(sizeof(uint32_t)*n);
    int m=n-1;
    //Reverse the oid, since it's easier this way
    for(int i=0;i<=n;i++){
        reverse_oid[m] = _oid[i];
        m--;
    }
    for(int i=0;i<n;i++){
       // printf("%u, %u\n",_oid[i], iOid[i]);
    }
    //Check how big the final oid buffer will be
    for(int i=0;i<n;i++){
        while (_oid[i]>0){
            _oid[i]=(_oid[i]>>7);
            counter++;
        }
    }
    //alocate memory
    counter--;// remove one cause the first two elements of the oid are binded together
    _oid_buffer.buf=(uint8_t*)malloc(counter*sizeof(uint8_t));
    _oid_buffer.size=counter;
    int x=0;
    
    while(counter>1){
        //printf("%d\n",counter);
        _oid_buffer.buf[counter-1] = (reverse_oid[x]&0x7F);
        //OID element must be max 127
        counter--;
        //If bigger it needs to be split in several
        reverse_oid[x]=(reverse_oid[x]>>7);
        while (reverse_oid[x]>0){
            //And have the flag to indicate that         
            _oid_buffer.buf[counter-1] = (reverse_oid[x]&0x7F)|0x80;
            reverse_oid[x]=(reverse_oid[x]>>7);
            counter--;
        }
        x++;
    }
    //Bind the first two together
    _oid_buffer.buf[0] = (40*reverse_oid[x+1]+reverse_oid[x]);
    for(int i=0;i<_oid_buffer.size;i++){
        //printf("%d\n",_oid_buffer._buffer[i]);
    }
    return _oid_buffer;
}

/*######################################################
Converts the oid in string format to array of uint32_t
*/
uint32_t *soidtonoid(char *_optarg){
    int numoid = 1;
    uint32_t *_oid;
    char *_token;
    /*######################################################
    Static because dynamic with realloc is crashing
    */
    _oid = calloc(1024,sizeof(int));
    _token = calloc(50,sizeof(char));
    _token = strtok(_optarg,".");
    _oid[numoid-1] = atoi(_token);
    while(_token!=NULL){
        numoid++;
        if (_token = strtok(NULL,"."))
            _oid[numoid-1] = atoi(_token);
        else{
            _oid[numoid-1]=SNMP_MSG_OID_END;
            break;
        }
    }
    return _oid;
}


/*######################################################
Converts the ip in string format to IpAddress_t
*/
IpAddress_t siptonip(char *_optarg){
    int numip = 1;
    IpAddress_t _ip;
    char *_token;
    /*######################################################
    Static because dynamic with realloc is crashing
    */
    _ip.buf = calloc(1024,sizeof(uint8_t));
    _token = calloc(50,sizeof(char));
    _token = strtok(_optarg,".");
    _ip.buf[numip-1] = (uint8_t) atoi(_token);
    while(_token!=NULL){
        numip++;
        if (_token = strtok(NULL,"."))
            _ip.buf[numip-1] = (uint8_t) atoi(_token);
    }
    _ip.size = numip-1;
    return _ip;
}

/*######################################################
Converts the COUNT64 in string format to Count64_t
*/
Counter64_t scountertoicounter(char *_optarg){
    long long llcounter;
    Counter64_t counter;
    counter.buf = calloc(2,sizeof(uint32_t));
    llcounter = atoll(_optarg);
    //Fill in the buffer inverted
    for (int i = 7; i-->0;){
        counter.buf[i] = (uint8_t) llcounter&0xFF; //Get the fisrt byte and shift
        llcounter =  llcounter>>8;
    }
    counter.size = 7; //Size apparently counts from 0 in asn1c Count64 implementation...
    return counter;
}



static char to_printable(int n){
/*
* Copyright (c) 2017 Dariusz Stojaczyk. All Rights Reserved.
* The following source code is released under an MIT-style license,
* that can be found in the LICENSE file.
*/
    static const char *trans_table = "0123456789abcdef";

    return trans_table[n & 0xf];
}

int hexdump_line(const char *data, const char *data_start, const char *data_end){
 /* Funciont to print the buffer in hexa format on screen
  * Copyright (c) 2017 Dariusz Stojaczyk. All Rights Reserved.
  * The following source code is released under an MIT-style license,
  * that can be found in the LICENSE file.
 */
    static char buf[256] = {0};

    char *buf_ptr = buf;
    int relative_addr = (int) (data - data_start);
    size_t i, j;

    for (i = 0; i < 2; ++i) {
        buf_ptr[i] = ' ';
    }
    buf_ptr += i;

    for (i = 0; i < sizeof(void *); ++i) {
        buf_ptr[i] = to_printable(
            relative_addr >> (sizeof(void *) * 4 - 4 - i * 4));
    }
    buf_ptr += i;

    buf_ptr[0] = ':';
    buf_ptr[1] = ' ';
    buf_ptr += 2;

    for (j = 0; j < 8; ++j) {
        for (i = 0; i < 2; ++i) {
            if (data < data_end) {
                buf[10 + 5 * 8 + 4 + i + 2*j] = (char) (isprint(*data) ? *data : '.');

                buf_ptr[i * 2] = to_printable(*data >> 4);
                buf_ptr[i * 2 + 1] = to_printable(*data);

                ++data;
            } else {
                buf[10 + 5 * 8 + 4 + i + 2*j] = 0;

                buf_ptr[i * 2] = ' ';
                buf_ptr[i * 2 + 1] = ' ';
            }
        }

        buf_ptr[4] = ' ';
        buf_ptr += 5;
    }

    buf[10 + 5 * 8 + 2] = '|';
    buf[10 + 5 * 8 + 3] = ' ';

    printf("%s\n", buf);

    return (int) (i * j);
}

void hexdump(const char *title, const void *data, size_t len) {
 /*
 * Copyright (c) 2017 Dariusz Stojaczyk. All Rights Reserved.
 * The following source code is released under an MIT-style license,
 * that can be found in the LICENSE file.
 */
    const char *data_ptr = data;
    const char *data_start = data_ptr;
    const char *data_end = data_ptr + len;

    printf("%s = {\n", title);
    while (data_ptr < data_end) {
        data_ptr += hexdump_line(data_ptr, data_start, data_end);
    }
    printf("}\n");
}

void filedump(const char *title, const void *data, size_t len, FILE *_ofd) {
 /*
 * Adapted from Dariusz Stojaczyk. All Rights Reserved.
 * The following source code is released under an MIT-style license,
 * that can be found in the LICENSE file.
 */
    const char *data_ptr = data;
    const char *data_start = data_ptr;
    const char *data_end = data_ptr + len;

    fprintf(_ofd,"%s = {\n", title);
    while (data_ptr < data_end) {
        data_ptr += filedump_line(data_ptr, data_start, data_end,_ofd);
    }
    fprintf(_ofd,"}\n");
}

int filedump_line(const char *data, const char *data_start, const char *data_end, FILE *_ofd){
 /* Funciont to print the buffer in hexa format on screen
    * Adapted from Dariusz Stojaczyk. All Rights Reserved.
    * The following source code is released under an MIT-style license,
    * that can be found in the LICENSE file.
 */
    static char buf[256] = {0};

    char *buf_ptr = buf;
    int relative_addr = (int) (data - data_start);
    size_t i, j;

    for (i = 0; i < 2; ++i) {
        buf_ptr[i] = ' ';
    }
    buf_ptr += i;

    for (i = 0; i < sizeof(void *); ++i) {
        buf_ptr[i] = to_printable(
            relative_addr >> (sizeof(void *) * 4 - 4 - i * 4));
    }
    buf_ptr += i;

    buf_ptr[0] = ':';
    buf_ptr[1] = ' ';
    buf_ptr += 2;

    for (j = 0; j < 8; ++j) {
        for (i = 0; i < 2; ++i) {
            if (data < data_end) {
                buf[10 + 5 * 8 + 4 + i + 2*j] = (char) (isprint(*data) ? *data : '.');

                buf_ptr[i * 2] = to_printable(*data >> 4);
                buf_ptr[i * 2 + 1] = to_printable(*data);

                ++data;
            } else {
                buf[10 + 5 * 8 + 4 + i + 2*j] = 0;

                buf_ptr[i * 2] = ' ';
                buf_ptr[i * 2 + 1] = ' ';
            }
        }

        buf_ptr[4] = ' ';
        buf_ptr += 5;
    }

    buf[10 + 5 * 8 + 2] = '|';
    buf[10 + 5 * 8 + 3] = ' ';

    fprintf(_ofd,"%s\n", buf);

    return (int) (i * j);
}