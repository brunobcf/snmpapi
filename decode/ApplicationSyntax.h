/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "SNMPv2-PDU"
 * 	found in "snmpv2c.asn1"
 */

#ifndef	_ApplicationSyntax_H_
#define	_ApplicationSyntax_H_


#include <asn_application.h>

/* Including external dependencies */
#include "IpAddress.h"
#include "Counter32.h"
#include "TimeTicks.h"
#include "Opaque.h"
#include "Counter64.h"
#include "Unsigned32.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum ApplicationSyntax_PR {
	ApplicationSyntax_PR_NOTHING,	/* No components present */
	ApplicationSyntax_PR_ipAddress_value,
	ApplicationSyntax_PR_counter_value,
	ApplicationSyntax_PR_timeticks_value,
	ApplicationSyntax_PR_arbitrary_value,
	ApplicationSyntax_PR_big_counter_value,
	ApplicationSyntax_PR_unsigned_integer_value
} ApplicationSyntax_PR;

/* ApplicationSyntax */
typedef struct ApplicationSyntax {
	ApplicationSyntax_PR present;
	union ApplicationSyntax_u {
		IpAddress_t	 ipAddress_value;
		Counter32_t	 counter_value;
		TimeTicks_t	 timeticks_value;
		Opaque_t	 arbitrary_value;
		Counter64_t	 big_counter_value;
		Unsigned32_t	 unsigned_integer_value;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ApplicationSyntax_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ApplicationSyntax;
extern asn_CHOICE_specifics_t asn_SPC_ApplicationSyntax_specs_1;
extern asn_TYPE_member_t asn_MBR_ApplicationSyntax_1[6];
extern asn_per_constraints_t asn_PER_type_ApplicationSyntax_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _ApplicationSyntax_H_ */
#include <asn_internal.h>