/*
** encoder.c - API for enconding SNMP PDUs
   Bruno Chianca Ferreira - PG33878
   Made heavily with the help of ASN1C compiler
*/

#include "encoder.h"


uint8_t *buffer, *buffer_final;
size_t buffer_size, buffer_final_size;

/*#################################################################
Set request for integer
*/
struct snmpbuffer snmpSetRequestInt(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, int value, int _verbose_flag, int _version) {

    struct snmpbuffer sendbuffer;

    SimpleSyntax_t* simple;
    simple = calloc(1, sizeof(SimpleSyntax_t));
    simple->present = SimpleSyntax_PR_integer_value;
    simple->choice.integer_value = value;

    ObjectSyntax_t* object_syntax;
    object_syntax = calloc(1, sizeof(ObjectSyntax_t));
    object_syntax->present = ObjectSyntax_PR_simple;
    object_syntax->choice.simple = *simple;

    ObjectName_t* object_name;
    object_name = calloc(1, sizeof(ObjectName_t));
    object_name->buf = _oidbuffer.buf;
    object_name->size = _oidbuffer.size;

    VarBind_t* var_bind;
    var_bind = calloc(1, sizeof(VarBind_t));
    var_bind->name = *object_name;
    var_bind->choice.present = choice_PR_value;
    var_bind->choice.choice.value = *object_syntax;

    sendbuffer = snmpSetRequest(community,tag,_verbose_flag, _version, var_bind);

    return sendbuffer;
    
}
/*#################################################################
Set request for string
*/
struct snmpbuffer snmpSetRequestStr(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, OCTET_STRING_t value, int _verbose_flag, int _version) {

    struct snmpbuffer sendbuffer;

    SimpleSyntax_t* simple;
    simple = calloc(1, sizeof(SimpleSyntax_t));
    simple->present = SimpleSyntax_PR_string_value;
    simple->choice.string_value = value;

    ObjectSyntax_t* object_syntax;
    object_syntax = calloc(1, sizeof(ObjectSyntax_t));
    object_syntax->present = ObjectSyntax_PR_simple;
    object_syntax->choice.simple = *simple;

    ObjectName_t* object_name;
    object_name = calloc(1, sizeof(ObjectName_t));
    object_name->buf = _oidbuffer.buf;
    object_name->size = _oidbuffer.size;

    VarBind_t* var_bind;
    var_bind = calloc(1, sizeof(VarBind_t));
    var_bind->name = *object_name;
    var_bind->choice.present = choice_PR_value;
    var_bind->choice.choice.value = *object_syntax;

    sendbuffer = snmpSetRequest(community,tag,_verbose_flag, _version, var_bind);

    return sendbuffer;
    
}
/*#################################################################
Set request for oid
*/
struct snmpbuffer snmpSetRequestOid(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, OBJECT_IDENTIFIER_t value, int _verbose_flag, int _version) {

    struct snmpbuffer sendbuffer;

    SimpleSyntax_t* simple;
    simple = calloc(1, sizeof(SimpleSyntax_t));
    simple->present = SimpleSyntax_PR_objectID_value;
    simple->choice.objectID_value = value;

    ObjectSyntax_t* object_syntax;
    object_syntax = calloc(1, sizeof(ObjectSyntax_t));
    object_syntax->present = ObjectSyntax_PR_simple;
    object_syntax->choice.simple = *simple;

    ObjectName_t* object_name;
    object_name = calloc(1, sizeof(ObjectName_t));
    object_name->buf = _oidbuffer.buf;
    object_name->size = _oidbuffer.size;

    VarBind_t* var_bind;
    var_bind = calloc(1, sizeof(VarBind_t));
    var_bind->name = *object_name;
    var_bind->choice.present = choice_PR_value;
    var_bind->choice.choice.value = *object_syntax;

    sendbuffer = snmpSetRequest(community,tag,_verbose_flag, _version, var_bind);

    return sendbuffer;
    
}
/*#################################################################
Set request for ip address
*/
struct snmpbuffer snmpSetRequestIp(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, IpAddress_t value, int _verbose_flag, int _version) {

    struct snmpbuffer sendbuffer;

    ApplicationSyntax_t* application;
    application = calloc(1, sizeof(ApplicationSyntax_t));
    application->present = ApplicationSyntax_PR_ipAddress_value;
    application->choice.ipAddress_value = value;

    ObjectSyntax_t* object_syntax;
    object_syntax = calloc(1, sizeof(ObjectSyntax_t));
    object_syntax->present = ObjectSyntax_PR_application_wide;
    object_syntax->choice.application_wide = *application;

    ObjectName_t* object_name;
    object_name = calloc(1, sizeof(ObjectName_t));
    object_name->buf = _oidbuffer.buf;
    object_name->size = _oidbuffer.size;

    VarBind_t* var_bind;
    var_bind = calloc(1, sizeof(VarBind_t));
    var_bind->name = *object_name;
    var_bind->choice.present = choice_PR_value;
    var_bind->choice.choice.value = *object_syntax;

    sendbuffer = snmpSetRequest(community,tag,_verbose_flag, _version, var_bind);

    return sendbuffer;
    
}
/*#################################################################
Set request for counter
*/
struct snmpbuffer snmpSetRequestCounter(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, Counter32_t value, int _verbose_flag, int _version) {

    struct snmpbuffer sendbuffer;

    ApplicationSyntax_t* application;
    application = calloc(1, sizeof(ApplicationSyntax_t));
    application->present = ApplicationSyntax_PR_counter_value;
    application->choice.counter_value = value;

    ObjectSyntax_t* object_syntax;
    object_syntax = calloc(1, sizeof(ObjectSyntax_t));
    object_syntax->present = ObjectSyntax_PR_application_wide;
    object_syntax->choice.application_wide = *application;

    ObjectName_t* object_name;
    object_name = calloc(1, sizeof(ObjectName_t));
    object_name->buf = _oidbuffer.buf;
    object_name->size = _oidbuffer.size;

    VarBind_t* var_bind;
    var_bind = calloc(1, sizeof(VarBind_t));
    var_bind->name = *object_name;
    var_bind->choice.present = choice_PR_value;
    var_bind->choice.choice.value = *object_syntax;

    sendbuffer = snmpSetRequest(community,tag,_verbose_flag, _version, var_bind);

    return sendbuffer;
    
}
/*#################################################################
Set request for big counter
*/
struct snmpbuffer snmpSetRequestBigCounter(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, Counter64_t value, int _verbose_flag, int _version) {

    struct snmpbuffer sendbuffer;

    ApplicationSyntax_t* application;
    application = calloc(1, sizeof(ApplicationSyntax_t));
    application->present = ApplicationSyntax_PR_big_counter_value;
    application->choice.big_counter_value = value;

    ObjectSyntax_t* object_syntax;
    object_syntax = calloc(1, sizeof(ObjectSyntax_t));
    object_syntax->present = ObjectSyntax_PR_application_wide;
    object_syntax->choice.application_wide = *application;

    ObjectName_t* object_name;
    object_name = calloc(1, sizeof(ObjectName_t));
    object_name->buf = _oidbuffer.buf;
    object_name->size = _oidbuffer.size;

    VarBind_t* var_bind;
    var_bind = calloc(1, sizeof(VarBind_t));
    var_bind->name = *object_name;
    var_bind->choice.present = choice_PR_value;
    var_bind->choice.choice.value = *object_syntax;

    sendbuffer = snmpSetRequest(community,tag,_verbose_flag, _version, var_bind);

    return sendbuffer;
    
}
/*#################################################################
Set request for time ticks
*/
struct snmpbuffer snmpSetRequestTicks(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, TimeTicks_t value, int _verbose_flag, int _version) {

    struct snmpbuffer sendbuffer;

    ApplicationSyntax_t* application;
    application = calloc(1, sizeof(ApplicationSyntax_t));
    application->present = ApplicationSyntax_PR_timeticks_value;
    application->choice.timeticks_value = value;

    ObjectSyntax_t* object_syntax;
    object_syntax = calloc(1, sizeof(ObjectSyntax_t));
    object_syntax->present = ObjectSyntax_PR_application_wide;
    object_syntax->choice.application_wide = *application;

    ObjectName_t* object_name;
    object_name = calloc(1, sizeof(ObjectName_t));
    object_name->buf = _oidbuffer.buf;
    object_name->size = _oidbuffer.size;

    VarBind_t* var_bind;
    var_bind = calloc(1, sizeof(VarBind_t));
    var_bind->name = *object_name;
    var_bind->choice.present = choice_PR_value;
    var_bind->choice.choice.value = *object_syntax;

    sendbuffer = snmpSetRequest(community,tag,_verbose_flag, _version, var_bind);

    return sendbuffer;
    
}
/*#################################################################
Set request for unsigned integer
*/
struct snmpbuffer snmpSetRequestUint(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, Unsigned32_t value, int _verbose_flag, int _version) {

    struct snmpbuffer sendbuffer;

    ApplicationSyntax_t* application;
    application = calloc(1, sizeof(ApplicationSyntax_t));
    application->present = ApplicationSyntax_PR_unsigned_integer_value;
    application->choice.unsigned_integer_value = value;

    ObjectSyntax_t* object_syntax;
    object_syntax = calloc(1, sizeof(ObjectSyntax_t));
    object_syntax->present = ObjectSyntax_PR_application_wide;
    object_syntax->choice.application_wide = *application;

    ObjectName_t* object_name;
    object_name = calloc(1, sizeof(ObjectName_t));
    object_name->buf = _oidbuffer.buf;
    object_name->size = _oidbuffer.size;

    VarBind_t* var_bind;
    var_bind = calloc(1, sizeof(VarBind_t));
    var_bind->name = *object_name;
    var_bind->choice.present = choice_PR_value;
    var_bind->choice.choice.value = *object_syntax;

    sendbuffer = snmpSetRequest(community,tag,_verbose_flag, _version, var_bind);

    return sendbuffer;
    
}
/*#################################################################
Set request wrapper function
*/
struct snmpbuffer snmpSetRequest (OCTET_STRING_t community, int tag, int _verbose_flag, int _version, VarBind_t* _var_bind ){
    
    struct snmpbuffer sendbuffer;
    VarBindList_t* varlist;
    varlist = calloc(1, sizeof(VarBindList_t));
    int r = ASN_SEQUENCE_ADD(&varlist->list, _var_bind);

    SetRequest_PDU_t* setRequestPDU;
    setRequestPDU = calloc(1, sizeof(SetRequest_PDU_t));
    setRequestPDU->request_id = tag;
    setRequestPDU->error_index = 0;
    setRequestPDU->error_status = 0;
    setRequestPDU->variable_bindings = *varlist;

    PDUs_t *pdu;
    pdu = calloc(1, sizeof(PDUs_t));
    pdu->present = PDUs_PR_set_request;
    pdu->choice.set_request = *setRequestPDU;

    buffer = calloc(1, 1024*sizeof(uint8_t));
    buffer_size = 1024;

    asn_enc_rval_t ret = asn_encode_to_buffer(0, ATS_BER,&asn_DEF_PDUs, pdu, buffer, buffer_size);

    if (ret.encoded == -1) {
        fprintf(stderr, "Failed to encode PDU.\n");
        fprintf(stderr, "Error encoding: %s\n",ret.failed_type->name);
        exit(1);
    }

    ANY_t* data;
    data = calloc(1, sizeof(ANY_t));
    data->buf = buffer;
    data->size = ret.encoded;

    Message_t* message;
    message = calloc(1, sizeof(Message_t));
    message->version = _version;
    message->community = community;
    message->data = *data;
    if (_verbose_flag)
        xer_fprint(stdout,&asn_DEF_Message,message);

    buffer_final = calloc(1, MAXSNMP*sizeof(uint8_t));
    buffer_final_size = MAXSNMP;

    ret = asn_encode_to_buffer(0, ATS_BER,&asn_DEF_Message, message, buffer_final, buffer_final_size);

    if (ret.encoded == -1) {
        fprintf(stderr, "Failed to encode PDU.\n");
        fprintf(stderr, "Error encoding: %s\n",ret.failed_type->name);
        exit(1);
    }
    if (ret.encoded > 63*1024) {
        fprintf(stderr, "Warning, PDU is too big. Few space left for UDP wrapping.\n");
    }
    sendbuffer._buffer = (uint8_t*) malloc (sizeof(uint8_t)*ret.encoded);
    sendbuffer._buffer = buffer_final;
    sendbuffer._size = ret.encoded;
    if (_verbose_flag)
        hexdump("Buffer_final:",buffer_final,ret.encoded);
    return sendbuffer;
}
/*#################################################################
Get request
*/
struct snmpbuffer snmpGetRequest(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, int _verbose_flag, int _version) {

    struct snmpbuffer sendbuffer;

    ObjectName_t* object_name;
    object_name = calloc(1, sizeof(ObjectName_t));
    object_name->buf = _oidbuffer.buf;
    object_name->size = _oidbuffer.size;

    VarBind_t* var_bind;
    var_bind = calloc(1, sizeof(VarBind_t));
    var_bind->name = *object_name;
    var_bind->choice.present = choice_PR_unSpecified;
    var_bind->choice.choice.unSpecified;

    VarBindList_t* varlist;
    varlist = calloc(1, sizeof(VarBindList_t));
    int r = ASN_SEQUENCE_ADD(&varlist->list, var_bind);

    GetRequest_PDU_t* getRequestPDU;
    getRequestPDU = calloc(1, sizeof(GetRequest_PDU_t));
    getRequestPDU->request_id = tag;
    getRequestPDU->error_index = 0;
    getRequestPDU->error_status = 0;
    getRequestPDU->variable_bindings = *varlist;

    PDUs_t *pdu;
    pdu = calloc(1, sizeof(PDUs_t));
    pdu->present = PDUs_PR_get_request;
    pdu->choice.get_request = *getRequestPDU;

    buffer = calloc(1, 1024*sizeof(uint8_t));
    buffer_size = 1024;

    asn_enc_rval_t ret = asn_encode_to_buffer(0, ATS_BER,&asn_DEF_PDUs, pdu, buffer, buffer_size);

    if (ret.encoded == -1) {
        fprintf(stderr, "Failed to encode PDU.\n");
        fprintf(stderr, "Error encoding: %s\n",ret.failed_type->name);
        exit(1);
    }

    ANY_t* data;
    data = calloc(1, sizeof(ANY_t));
    data->buf = buffer;
    data->size = ret.encoded;

    Message_t* message;
    message = calloc(1, sizeof(Message_t));
    message->version = _version;
    message->community = community;
    message->data = *data;

    if (_verbose_flag)
        xer_fprint(stdout,&asn_DEF_Message,message);

    buffer_final = calloc(MAXSNMP, sizeof(uint8_t));
    buffer_final_size = MAXSNMP;

    ret = asn_encode_to_buffer(0, ATS_BER,&asn_DEF_Message, message, buffer_final, buffer_final_size);

    if (ret.encoded == -1) {
        fprintf(stderr, "Failed to encode PDU.\n");
        fprintf(stderr, "Error encoding: %s\n",ret.failed_type->name);
        exit(1);
    }
    if (ret.encoded > 63*1024) {
        fprintf(stderr, "Warning, PDU is too big. Few space left for UDP wrapping.\n");
    }
    sendbuffer._buffer = (uint8_t*) malloc (sizeof(uint8_t)*ret.encoded);
    sendbuffer._buffer = buffer_final;
    sendbuffer._size = ret.encoded;
    if (_verbose_flag)
        hexdump("Buffer_final:",buffer_final,ret.encoded);
    

    return sendbuffer;
    
}
/*#################################################################
Get next request
*/
struct snmpbuffer snmpGetNextRequest(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, int _verbose_flag, int _version) {

    struct snmpbuffer sendbuffer;


    ObjectName_t* object_name;
    object_name = calloc(1, sizeof(ObjectName_t));
    object_name->buf = _oidbuffer.buf;
    object_name->size = _oidbuffer.size;

    VarBind_t* var_bind;
    var_bind = calloc(1, sizeof(VarBind_t));
    var_bind->name = *object_name;
    var_bind->choice.present = choice_PR_unSpecified;
    var_bind->choice.choice.unSpecified;

    VarBindList_t* varlist;
    varlist = calloc(1, sizeof(VarBindList_t));
    int r = ASN_SEQUENCE_ADD(&varlist->list, var_bind);

    GetNextRequest_PDU_t* getNextRequestPDU;
    getNextRequestPDU = calloc(1, sizeof(GetNextRequest_PDU_t));
    getNextRequestPDU->request_id = tag;
    getNextRequestPDU->error_index = 0;
    getNextRequestPDU->error_status = 0;
    getNextRequestPDU->variable_bindings = *varlist;

    PDUs_t *pdu;
    pdu = calloc(1, sizeof(PDUs_t));
    pdu->present = PDUs_PR_get_next_request;
    pdu->choice.get_next_request = *getNextRequestPDU;

    buffer = calloc(1, 1024*sizeof(uint8_t));
    buffer_size = 1024;

    asn_enc_rval_t ret = asn_encode_to_buffer(0, ATS_BER,&asn_DEF_PDUs, pdu, buffer, buffer_size);

    if (ret.encoded == -1) {
        fprintf(stderr, "Failed to encode PDU.\n");
        fprintf(stderr, "Error encoding: %s\n",ret.failed_type->name);
        exit(1);
    }

    ANY_t* data;
    data = calloc(1, sizeof(ANY_t));
    data->buf = buffer;
    data->size = ret.encoded;

    Message_t* message;
    message = calloc(1, sizeof(Message_t));
    message->version = _version;
    message->community = community;
    message->data = *data;

    if (_verbose_flag)
        xer_fprint(stdout,&asn_DEF_Message,message);

    buffer_final = calloc(MAXSNMP, sizeof(uint8_t));
    buffer_final_size = MAXSNMP;

    ret = asn_encode_to_buffer(0, ATS_BER,&asn_DEF_Message, message, buffer_final, buffer_final_size);

    if (ret.encoded == -1) {
        fprintf(stderr, "Failed to encode PDU.\n");
        fprintf(stderr, "Error encoding: %s\n",ret.failed_type->name);
        exit(1);
    }
    if (ret.encoded > 63*1024) {
        fprintf(stderr, "Warning, PDU is too big. Few space left for UDP wrapping.\n");
    }

    sendbuffer._buffer = (uint8_t*) malloc (sizeof(uint8_t)*ret.encoded);
    sendbuffer._buffer = buffer_final;
    sendbuffer._size = ret.encoded;
    if (_verbose_flag)
        hexdump("Buffer_final:",buffer_final,ret.encoded);
    

    return sendbuffer;
    
}
/*#################################################################
Get bulk request
*/
struct snmpbuffer snmpGetBulkRequest(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, int _verbose_flag, int _version, long _max_repeaters, long _non_repeaters) {

    struct snmpbuffer sendbuffer;

    ObjectName_t* object_name;
    object_name = calloc(1, sizeof(ObjectName_t));
    object_name->buf = _oidbuffer.buf;
    object_name->size = _oidbuffer.size;

    VarBind_t* var_bind;
    var_bind = calloc(1, sizeof(VarBind_t));
    var_bind->name = *object_name;
    var_bind->choice.present = choice_PR_unSpecified;
    var_bind->choice.choice.unSpecified;

    VarBindList_t* varlist;
    varlist = calloc(1, sizeof(VarBindList_t));
    int r = ASN_SEQUENCE_ADD(&varlist->list, var_bind);

    GetBulkRequest_PDU_t* getBulkRequestPDU;
    getBulkRequestPDU = calloc(1, sizeof(GetNextRequest_PDU_t));
    getBulkRequestPDU->request_id = tag;
    getBulkRequestPDU->max_repetitions= _max_repeaters;
    getBulkRequestPDU->non_repeaters= _non_repeaters;
    getBulkRequestPDU->variable_bindings = *varlist;

    PDUs_t *pdu;
    pdu = calloc(1, sizeof(PDUs_t));
    pdu->present = PDUs_PR_get_bulk_request;
    pdu->choice.get_bulk_request = *getBulkRequestPDU;

    buffer = calloc(1, 1024*sizeof(uint8_t));
    buffer_size = 1024;

    asn_enc_rval_t ret = asn_encode_to_buffer(0, ATS_BER,&asn_DEF_PDUs, pdu, buffer, buffer_size);

    if (ret.encoded == -1) {
        fprintf(stderr, "Failed to encode PDU.\n");
        fprintf(stderr, "Error encoding: %s\n",ret.failed_type->name);
        exit(1);
    }

    ANY_t* data;
    data = calloc(1, sizeof(ANY_t));
    data->buf = buffer;
    data->size = ret.encoded;

    Message_t* message;
    message = calloc(1, sizeof(Message_t));
    message->version = _version;
    message->community = community;
    message->data = *data;

    if (_verbose_flag)
        xer_fprint(stdout,&asn_DEF_Message,message);

    buffer_final = calloc(MAXSNMP, sizeof(uint8_t));
    buffer_final_size = MAXSNMP;

    ret = asn_encode_to_buffer(0, ATS_BER,&asn_DEF_Message, message, buffer_final, buffer_final_size);

    if (ret.encoded == -1) {
        fprintf(stderr, "Failed to encode PDU.\n");
        fprintf(stderr, "Error encoding: %s\n",ret.failed_type->name);
        exit(1);
    }
    if (ret.encoded > 63*1024) {
        fprintf(stderr, "Warning, PDU is too big. Few space left for UDP wrapping.\n");
    }

    sendbuffer._buffer = (uint8_t*) malloc (sizeof(uint8_t)*ret.encoded);
    sendbuffer._buffer = buffer_final;
    sendbuffer._size = ret.encoded;
    if (_verbose_flag)
        hexdump("Buffer_final:",buffer_final,ret.encoded);
    

    return sendbuffer;
    
}
/*#################################################################
Response for integer
*/
struct snmpbuffer snmpResponseInt(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, int value, int _verbose_flag, int _version) {

    struct snmpbuffer sendbuffer;

    SimpleSyntax_t* simple;
    simple = calloc(1, sizeof(SimpleSyntax_t));
    simple->present = SimpleSyntax_PR_integer_value;
    simple->choice.integer_value = value;

    ObjectSyntax_t* object_syntax;
    object_syntax = calloc(1, sizeof(ObjectSyntax_t));
    object_syntax->present = ObjectSyntax_PR_simple;
    object_syntax->choice.simple = *simple;

    ObjectName_t* object_name;
    object_name = calloc(1, sizeof(ObjectName_t));
    object_name->buf = _oidbuffer.buf;
    object_name->size = _oidbuffer.size;

    VarBind_t* var_bind;
    var_bind = calloc(1, sizeof(VarBind_t));
    var_bind->name = *object_name;
    var_bind->choice.present = choice_PR_value;
    var_bind->choice.choice.value = *object_syntax;

    sendbuffer = snmpResponse (community, tag, _verbose_flag, _version , var_bind);

    return sendbuffer;
}
/*#################################################################
Response for string
*/
struct snmpbuffer snmpResponseStr(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, OCTET_STRING_t value, int _verbose_flag, int _version) {

    struct snmpbuffer sendbuffer;

    SimpleSyntax_t* simple;
    simple = calloc(1, sizeof(SimpleSyntax_t));
    simple->present = SimpleSyntax_PR_string_value;
    simple->choice.string_value = value;

    ObjectSyntax_t* object_syntax;
    object_syntax = calloc(1, sizeof(ObjectSyntax_t));
    object_syntax->present = ObjectSyntax_PR_simple;
    object_syntax->choice.simple = *simple;

    ObjectName_t* object_name;
    object_name = calloc(1, sizeof(ObjectName_t));
    object_name->buf = _oidbuffer.buf;
    object_name->size = _oidbuffer.size;

    VarBind_t* var_bind;
    var_bind = calloc(1, sizeof(VarBind_t));
    var_bind->name = *object_name;
    var_bind->choice.present = choice_PR_value;
    var_bind->choice.choice.value = *object_syntax;

    sendbuffer = snmpResponse(community,tag,_verbose_flag, _version, var_bind);

    return sendbuffer;
    
}
/*#################################################################
Response for oid
*/
struct snmpbuffer snmpResponseOid(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, OBJECT_IDENTIFIER_t value, int _verbose_flag, int _version) {

    struct snmpbuffer sendbuffer;

    SimpleSyntax_t* simple;
    simple = calloc(1, sizeof(SimpleSyntax_t));
    simple->present = SimpleSyntax_PR_objectID_value;
    simple->choice.objectID_value = value;

    ObjectSyntax_t* object_syntax;
    object_syntax = calloc(1, sizeof(ObjectSyntax_t));
    object_syntax->present = ObjectSyntax_PR_simple;
    object_syntax->choice.simple = *simple;

    ObjectName_t* object_name;
    object_name = calloc(1, sizeof(ObjectName_t));
    object_name->buf = _oidbuffer.buf;
    object_name->size = _oidbuffer.size;

    VarBind_t* var_bind;
    var_bind = calloc(1, sizeof(VarBind_t));
    var_bind->name = *object_name;
    var_bind->choice.present = choice_PR_value;
    var_bind->choice.choice.value = *object_syntax;

    sendbuffer = snmpResponse(community,tag,_verbose_flag, _version, var_bind);

    return sendbuffer;
    
}
/*#################################################################
Response for ip address
*/
struct snmpbuffer snmpResponseIp(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, IpAddress_t value, int _verbose_flag, int _version) {

    struct snmpbuffer sendbuffer;

    ApplicationSyntax_t* application;
    application = calloc(1, sizeof(ApplicationSyntax_t));
    application->present = ApplicationSyntax_PR_ipAddress_value;
    application->choice.ipAddress_value = value;

    ObjectSyntax_t* object_syntax;
    object_syntax = calloc(1, sizeof(ObjectSyntax_t));
    object_syntax->present = ObjectSyntax_PR_application_wide;
    object_syntax->choice.application_wide = *application;

    ObjectName_t* object_name;
    object_name = calloc(1, sizeof(ObjectName_t));
    object_name->buf = _oidbuffer.buf;
    object_name->size = _oidbuffer.size;

    VarBind_t* var_bind;
    var_bind = calloc(1, sizeof(VarBind_t));
    var_bind->name = *object_name;
    var_bind->choice.present = choice_PR_value;
    var_bind->choice.choice.value = *object_syntax;

    sendbuffer = snmpResponse(community,tag,_verbose_flag, _version, var_bind);

    return sendbuffer;
    
}
/*#################################################################
Response for counter
*/
struct snmpbuffer snmpResponseCounter(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, Counter32_t value, int _verbose_flag, int _version) {

    struct snmpbuffer sendbuffer;

    ApplicationSyntax_t* application;
    application = calloc(1, sizeof(ApplicationSyntax_t));
    application->present = ApplicationSyntax_PR_counter_value;
    application->choice.counter_value = value;

    ObjectSyntax_t* object_syntax;
    object_syntax = calloc(1, sizeof(ObjectSyntax_t));
    object_syntax->present = ObjectSyntax_PR_application_wide;
    object_syntax->choice.application_wide = *application;

    ObjectName_t* object_name;
    object_name = calloc(1, sizeof(ObjectName_t));
    object_name->buf = _oidbuffer.buf;
    object_name->size = _oidbuffer.size;

    VarBind_t* var_bind;
    var_bind = calloc(1, sizeof(VarBind_t));
    var_bind->name = *object_name;
    var_bind->choice.present = choice_PR_value;
    var_bind->choice.choice.value = *object_syntax;

    sendbuffer = snmpResponse(community,tag,_verbose_flag, _version, var_bind);

    return sendbuffer;
    
}
/*#################################################################
Response for big counter
*/
struct snmpbuffer snmpResponseBigCounter(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, Counter64_t value, int _verbose_flag, int _version) {

    struct snmpbuffer sendbuffer;

    ApplicationSyntax_t* application;
    application = calloc(1, sizeof(ApplicationSyntax_t));
    application->present = ApplicationSyntax_PR_big_counter_value;
    application->choice.big_counter_value = value;

    ObjectSyntax_t* object_syntax;
    object_syntax = calloc(1, sizeof(ObjectSyntax_t));
    object_syntax->present = ObjectSyntax_PR_application_wide;
    object_syntax->choice.application_wide = *application;

    ObjectName_t* object_name;
    object_name = calloc(1, sizeof(ObjectName_t));
    object_name->buf = _oidbuffer.buf;
    object_name->size = _oidbuffer.size;

    VarBind_t* var_bind;
    var_bind = calloc(1, sizeof(VarBind_t));
    var_bind->name = *object_name;
    var_bind->choice.present = choice_PR_value;
    var_bind->choice.choice.value = *object_syntax;

    sendbuffer = snmpResponse(community,tag,_verbose_flag, _version, var_bind);

    return sendbuffer;
    
}
/*#################################################################
Response for time ticks
*/
struct snmpbuffer snmpResponseTicks(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, TimeTicks_t value, int _verbose_flag, int _version) {

    struct snmpbuffer sendbuffer;

    ApplicationSyntax_t* application;
    application = calloc(1, sizeof(ApplicationSyntax_t));
    application->present = ApplicationSyntax_PR_timeticks_value;
    application->choice.timeticks_value = value;

    ObjectSyntax_t* object_syntax;
    object_syntax = calloc(1, sizeof(ObjectSyntax_t));
    object_syntax->present = ObjectSyntax_PR_application_wide;
    object_syntax->choice.application_wide = *application;

    ObjectName_t* object_name;
    object_name = calloc(1, sizeof(ObjectName_t));
    object_name->buf = _oidbuffer.buf;
    object_name->size = _oidbuffer.size;

    VarBind_t* var_bind;
    var_bind = calloc(1, sizeof(VarBind_t));
    var_bind->name = *object_name;
    var_bind->choice.present = choice_PR_value;
    var_bind->choice.choice.value = *object_syntax;

    sendbuffer = snmpResponse(community,tag,_verbose_flag, _version, var_bind);

    return sendbuffer;
    
}
/*#################################################################
Response for unsigned integer
*/
struct snmpbuffer snmpResponseUint(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, Unsigned32_t value, int _verbose_flag, int _version) {

    struct snmpbuffer sendbuffer;

    ApplicationSyntax_t* application;
    application = calloc(1, sizeof(ApplicationSyntax_t));
    application->present = ApplicationSyntax_PR_unsigned_integer_value;
    application->choice.unsigned_integer_value = value;

    ObjectSyntax_t* object_syntax;
    object_syntax = calloc(1, sizeof(ObjectSyntax_t));
    object_syntax->present = ObjectSyntax_PR_application_wide;
    object_syntax->choice.application_wide = *application;

    ObjectName_t* object_name;
    object_name = calloc(1, sizeof(ObjectName_t));
    object_name->buf = _oidbuffer.buf;
    object_name->size = _oidbuffer.size;

    VarBind_t* var_bind;
    var_bind = calloc(1, sizeof(VarBind_t));
    var_bind->name = *object_name;
    var_bind->choice.present = choice_PR_value;
    var_bind->choice.choice.value = *object_syntax;

    sendbuffer = snmpResponse(community,tag,_verbose_flag, _version, var_bind);

    return sendbuffer;
    
}
/*#################################################################
Response for response exceptions
*/
struct snmpbuffer snmpResponseError(OCTET_STRING_t community, int tag, OBJECT_IDENTIFIER_t _oidbuffer, char _response_error[], int _verbose_flag, int _version) {

    struct snmpbuffer sendbuffer;

    ObjectName_t* object_name;
    object_name = calloc(1, sizeof(ObjectName_t));
    object_name->buf = _oidbuffer.buf;
    object_name->size = _oidbuffer.size;

    VarBind_t* var_bind;
    var_bind = calloc(1, sizeof(VarBind_t));
    var_bind->name = *object_name;

    
    if (!strcmp(_response_error,"noSuchInstance")){
        var_bind->choice.present = choice_PR_noSuchInstance;
        var_bind->choice.choice.noSuchInstance;
    }

    else if (!strcmp(_response_error,"noSuchObject")){
        var_bind->choice.present = choice_PR_noSuchObject;
        var_bind->choice.choice.noSuchObject;
    }
    else if (!strcmp(_response_error,"endOfMibView")){
        var_bind->choice.present = choice_PR_endOfMibView;
        var_bind->choice.choice.endOfMibView;
    }
    else {
        var_bind->choice.present = choice_PR_unSpecified;
        var_bind->choice.choice.unSpecified;
    }
    
    
    sendbuffer = snmpResponse (community, tag, _verbose_flag, _version , var_bind);

    return sendbuffer;
}
/*#################################################################
Response wrapper function
*/
struct snmpbuffer snmpResponse(OCTET_STRING_t community, int tag, int _verbose_flag, int _version,VarBind_t* _var_bind) {
                               
    struct snmpbuffer sendbuffer;

    VarBindList_t* varlist;
    varlist = calloc(1, sizeof(VarBindList_t));
    int r = ASN_SEQUENCE_ADD(&varlist->list, _var_bind);

    Response_PDU_t* responsePDU;
    responsePDU = calloc(1, sizeof(Response_PDU_t));
    responsePDU->request_id = tag;
    responsePDU->error_index = 0;
    responsePDU->error_status = 0;
    responsePDU->variable_bindings = *varlist;

    PDUs_t *pdu;
    pdu = calloc(1, sizeof(PDUs_t));
    pdu->present = PDUs_PR_response;
    pdu->choice.response = *responsePDU;

    buffer = calloc(1, 1024*sizeof(uint8_t));
    buffer_size = 1024;

    asn_enc_rval_t ret = asn_encode_to_buffer(0, ATS_BER,&asn_DEF_PDUs, pdu, buffer, buffer_size);

    if (ret.encoded == -1) {
        fprintf(stderr, "Failed to encode PDU.\n");
        fprintf(stderr, "Error encoding: %s\n",ret.failed_type->name);
        exit(1);
    }

    ANY_t* data;
    data = calloc(1, sizeof(ANY_t));
    data->buf = buffer;
    data->size = ret.encoded;

    Message_t* message;
    message = calloc(1, sizeof(Message_t));
    message->version = _version;
    message->community = community;
    message->data = *data;

    if (_verbose_flag)
        xer_fprint(stdout,&asn_DEF_Message,message);

    buffer_final = calloc(MAXSNMP, sizeof(uint8_t));
    buffer_final_size = MAXSNMP;

    ret = asn_encode_to_buffer(0, ATS_BER,&asn_DEF_Message, message, buffer_final, buffer_final_size);

    if (ret.encoded == -1) {
        fprintf(stderr, "Failed to encode PDU.\n");
        fprintf(stderr, "Error encoding: %s\n",ret.failed_type->name);
        exit(1);
    }    
    if (ret.encoded > 63*1024) {
        fprintf(stderr, "Warning, PDU is too big. Few space left for UDP wrapping.\n");
    }

    sendbuffer._buffer = (uint8_t*) malloc (sizeof(uint8_t)*ret.encoded);
    sendbuffer._buffer = buffer_final;
    sendbuffer._size = ret.encoded;
    if (_verbose_flag)
        hexdump("Buffer_final:",buffer_final,ret.encoded);
    

    return sendbuffer;
    
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