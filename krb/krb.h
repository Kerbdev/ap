/*
 * krb.c
 *
 *  Created on: Feb 10, 2014
 *      Author: ivan
 */
#ifndef __KRB__H__
#define __KRB__H__
#define pvno 5
#define MUTUAL_AUTH 1
#define MAXDATASIZE 1024
#define	KRB5_AS_REQ	((krb5_msgtype)10) /* Req for initial authentication */
#define	KRB5_AS_REP	((krb5_msgtype)11) /* Response to KRB_AS_REQ request */
#define	KRB5_TGS_REQ	((krb5_msgtype)12) /* TGS request to server */
#define	KRB5_TGS_REP	((krb5_msgtype)13) /* Response to KRB_TGS_REQ req */
#define	KRB5_AP_REQ	((krb5_msgtype)14) /* application request to server */
#define	KRB5_AP_REP	((krb5_msgtype)15) /* Response to KRB_AP_REQ_MUTUAL */
#define	KRB5_SAFE	((krb5_msgtype)20) /* Safe application message */
#define	KRB5_PRIV	((krb5_msgtype)21) /* Private application message */
#define	KRB5_CRED	((krb5_msgtype)22) /* Credential forwarding message */
#define	KRB5_ERROR	((krb5_msgtype)30) /* Error response */
typedef	char	krb5_octet;

typedef	unsigned int krb5_boolean;
typedef	unsigned int krb5_msgtype;
typedef	unsigned int krb5_kvno;

typedef	unsigned int krb5_addrtype;
typedef unsigned int krb5_enctype;
typedef unsigned int krb5_cksumtype;
typedef unsigned int krb5_authdatatype;
typedef unsigned int krb5_keyusage;

typedef unsigned int	krb5_preauthtype;
typedef	unsigned int krb5_flags;
typedef unsigned int	krb5_timestamp;
typedef	unsigned int	krb5_error_code;
typedef unsigned int	krb5_deltat;

typedef krb5_error_code	krb5_magic;

typedef struct _krb5_data {
	krb5_magic magic;
	unsigned int length;
	char *data;
} krb5_data;

typedef struct _krb5_octet_data {
	krb5_magic magic;
	unsigned int length;
	krb5_octet *data;
} krb5_octet_data;

typedef	void * krb5_pointer;
typedef void const * krb5_const_pointer;

typedef struct krb5_principal_data {
    krb5_magic magic;
    krb5_data realm;
    krb5_data *data;		/* An array of strings */
    int length;
    int type;
} krb5_principal_data;

typedef	krb5_principal_data * krb5_principal;

#define krb5_princ_realm(context, princ) (&(princ)->realm)
#define krb5_princ_set_realm(context, princ,value) ((princ)->realm = *(value))
#define krb5_princ_set_realm_length(context, princ,value) (princ)->realm.length = (value)
#define krb5_princ_set_realm_data(context, princ,value) (princ)->realm.data = (value)
#define	krb5_princ_size(context, princ) (princ)->length
#define	krb5_princ_type(context, princ) (princ)->type
#define	krb5_princ_name(context, princ) (princ)->data
#define	krb5_princ_component(context, princ,i)		\
	    (((i) < krb5_princ_size(context, princ))	\
	     ? (princ)->data + (i)			\
	     : NULL)

/* structure for address */
typedef struct _krb5_address {
    krb5_magic magic;
    krb5_addrtype addrtype;
    unsigned int length;
    krb5_octet *contents;
} krb5_address;

/* per Kerberos v5 protocol spec */
#define	ADDRTYPE_INET		0x0002
#define	ADDRTYPE_CHAOS		0x0005
#define	ADDRTYPE_XNS		0x0006
#define	ADDRTYPE_ISO		0x0007
#define ADDRTYPE_DDP		0x0010
#define ADDRTYPE_INET6		0x0018
/* not yet in the spec... */
#define ADDRTYPE_ADDRPORT	0x0100
#define ADDRTYPE_IPPORT		0x0101

/* macros to determine if a type is a local type */
#define ADDRTYPE_IS_LOCAL(addrtype) (addrtype & 0x8000)

struct _krb5_context;
typedef struct _krb5_context * krb5_context;

struct _krb5_auth_context;
typedef struct _krb5_auth_context * krb5_auth_context;

struct _krb5_cryptosystem_entry;
typedef struct _krb5_keyblock {
    krb5_magic magic;
    krb5_enctype enctype;
    unsigned int length;
    krb5_octet *contents;
} krb5_keyblock;
typedef struct _krb5_checksum {
    krb5_magic magic;
    krb5_cksumtype checksum_type;	/* checksum type */
    unsigned int length;
    krb5_octet *contents;
} krb5_checksum;

typedef struct _krb5_enc_data {
    krb5_enctype enctype;
    krb5_kvno kvno;
    krb5_data ciphertext;
} krb5_enc_data;

/* Time set */
typedef struct _krb5_ticket_times {
    krb5_timestamp authtime; /*  should ktime in KDC_REP == authtime
				in ticket? otherwise client can't get this */
    krb5_timestamp starttime;		/* optional in ticket, if not present,
					   use authtime */
    krb5_timestamp endtime;
    krb5_timestamp renew_till;
} krb5_ticket_times;
/* structure for auth data */
typedef struct _krb5_authdata {
    krb5_magic magic;
    krb5_authdatatype ad_type;
    unsigned int length;
    krb5_octet *contents;
} krb5_authdata;

/* structure for transited encoding */
typedef struct _krb5_transited {
    krb5_magic magic;
    krb5_octet tr_type;
    krb5_data tr_contents;
} krb5_transited;

typedef struct _krb5_enc_tkt_part {
    krb5_magic magic;
    /* to-be-encrypted portion */
    krb5_flags flags;			/* flags */
    krb5_keyblock *session;		/* session key: includes enctype */
    krb5_principal client;		/* client name/realm */
    krb5_transited transited;		/* list of transited realms */
    krb5_ticket_times times;		/* auth, start, end, renew_till */
    krb5_address *caddrs;	/* array of ptrs to addresses */
    krb5_authdata *authorization_data; /* auth data */
} krb5_enc_tkt_part;

typedef struct _krb5_ticket {
    krb5_magic magic;
    /* cleartext portion */
    krb5_principal server;		/* server name/realm */
    krb5_enc_data enc_part;		/* encryption type, kvno, encrypted
					   encoding */
    krb5_enc_tkt_part *enc_part2;	/* ptr to decrypted version, if
					   available */
} krb5_ticket;

/* the unencrypted version */
typedef struct _krb5_authenticator {
    krb5_magic magic;
    krb5_principal client;		/* client name/realm */
    krb5_checksum *checksum;	/* checksum, includes type, optional */
    int cusec;			/* client usec portion */
    krb5_timestamp ctime;		/* client sec portion */
    krb5_keyblock *subkey;		/* true session key, optional */
    int seq_number;		/* sequence #, optional */
    krb5_authdata *authorization_data; /* New add by Ari, auth data */
} krb5_authenticator;

typedef struct _krb5_tkt_authent {
    krb5_magic magic;
    krb5_ticket *ticket;
    krb5_authenticator *authenticator;
    krb5_flags ap_options;
} krb5_tkt_authent;

/* credentials:	 Ticket, session key, etc. */
typedef struct _krb5_creds {
    krb5_magic magic;
    krb5_principal client;		/* client's principal identifier */
    krb5_principal server;		/* server's principal identifier */
    krb5_keyblock keyblock;		/* session encryption key info */
    krb5_ticket_times times;		/* lifetime info */
    krb5_boolean is_skey;		/* true if ticket is encrypted in
					   another ticket's skey */
    krb5_flags ticket_flags;		/* flags in ticket */
    krb5_address *addresses;	/* addrs in ticket */
    krb5_data ticket;			/* ticket string itself */
    krb5_data second_ticket;		/* second ticket, if related to
					   ticket (via DUPLICATE-SKEY or
					   ENC-TKT-IN-SKEY) */
    krb5_authdata *authdata;	/* authorization data */
} krb5_creds;

/* Last request fields */
typedef struct _krb5_last_req_entry {
    krb5_magic magic;
    int lr_type;
    krb5_timestamp value;
} krb5_last_req_entry;

/* pre-authentication data */
typedef struct _krb5_pa_data {
    krb5_magic magic;
    krb5_preauthtype  pa_type;
    unsigned int length;
    krb5_octet *contents;
} krb5_pa_data;

typedef struct _krb5_kdc_req {
    krb5_magic magic;
    krb5_msgtype msg_type;		/* AS_REQ or TGS_REQ? */
    krb5_pa_data *padata;	/* e.g. encoded AP_REQ */
    /* real body */
    krb5_flags kdc_options;		/* requested options */
    krb5_principal client;		/* includes realm; optional */
    krb5_principal server;		/* includes realm (only used if no
					   client) */
    krb5_timestamp from;		/* requested starttime */
    krb5_timestamp till;		/* requested endtime */
    krb5_timestamp rtime;		/* (optional) requested renew_till */
    int nonce;			/* nonce to match request/response */
    int nktypes;			/* # of ktypes, must be positive */
    krb5_enctype ktype;		/* requested enctype(s) */
    krb5_address *addresses;	/* requested addresses, optional */
    krb5_enc_data authorization_data;	/* encrypted auth data; OPTIONAL */
    krb5_authdata *unenc_authdata; /* unencrypted auth data,
					   if available */
    krb5_ticket *second_ticket;/* second ticket array; OPTIONAL */
} krb5_kdc_req;

typedef struct _krb5_enc_kdc_rep_part {
    krb5_magic magic;
    /* encrypted part: */
    krb5_msgtype msg_type;		/* krb5 message type */
    krb5_keyblock *session;		/* session key */
    krb5_last_req_entry *last_req; /* array of ptrs to entries */
    int nonce;			/* nonce from request */
    krb5_timestamp key_exp;		/* expiration date */
    krb5_flags flags;			/* ticket flags */
    krb5_ticket_times times;		/* lifetime info */
    krb5_principal server;		/* server's principal identifier */
    krb5_address *aaddrs;	/* array of ptrs to addresses,
					   optional */
} krb5_enc_kdc_rep_part;

typedef struct _krb5_kdc_rep {
    krb5_magic magic;
    /* cleartext part: */
    krb5_msgtype msg_type;		/* AS_REP or KDC_REP? */
    krb5_pa_data *padata;	/* preauthentication data from KDC */
    krb5_principal client;		/* client's principal identifier */
    krb5_ticket *ticket;		/* ticket */
    krb5_enc_data enc_part;		/* encryption type, kvno, encrypted
					   encoding */
    krb5_enc_kdc_rep_part *enc_part2;/* unencrypted version, if available */
} krb5_kdc_rep;

/* error message structure */
typedef struct _krb5_error {
    krb5_magic magic;
    /* some of these may be meaningless in certain contexts */
    krb5_timestamp ctime;		/* client sec portion; optional */
    int cusec;			/* client usec portion; optional */
    int susec;			/* server usec portion */
    krb5_timestamp stime;		/* server sec portion */
    int error;			/* error code (protocol error #'s) */
    krb5_principal client;		/* client's principal identifier;
					   optional */
    krb5_principal server;		/* server's principal identifier */
    krb5_data text;			/* descriptive text */
    krb5_data e_data;			/* additional error-describing data */
} krb5_error;

typedef struct _krb5_ap_req {
    krb5_magic magic;
    krb5_msgtype msg_type;
    krb5_flags ap_options;		/* requested options */
    krb5_ticket *ticket;		/* ticket */
    krb5_authenticator *authenticator;	/* authenticator (already encrypted) */
} krb5_ap_req;
typedef struct _krb5_ap_rep_enc_part {
    krb5_magic magic;
    krb5_timestamp ctime;		/* client time, seconds portion */
    int cusec;			/* client time, microseconds portion */
    krb5_keyblock *subkey;		/* true session key, optional */
    int seq_number;		/* sequence #, optional */
} krb5_ap_rep_enc_part;
typedef struct _krb5_ap_rep {
    krb5_magic magic;
    krb5_msgtype msg_type;
    krb5_ap_rep_enc_part enc_part;
} krb5_ap_rep;


typedef struct _krb5_response {
    krb5_magic magic;
    krb5_octet message_type;
    krb5_data response;
    int expected_nonce;	/* The expected nonce for KDC_REP messages */
    krb5_timestamp request_time;   /* When we made the request */
} krb5_response;

typedef struct _krb5_cred_info {
    krb5_magic magic;
    krb5_keyblock *session;		/* session key used to encrypt */
					/* ticket */
    krb5_principal client;		/* client name/realm, optional */
    krb5_principal server;		/* server name/realm, optional */
    krb5_flags flags;			/* ticket flags, optional */
    krb5_ticket_times times;		/* auth, start, end, renew_till, */
					/* optional */
    krb5_address *caddrs;	/* array of ptrs to addresses */
} krb5_cred_info;

typedef struct _krb5_cred_enc_part {
    krb5_magic magic;
    int nonce;			/* nonce, optional */
    krb5_timestamp timestamp;		/* client time */
    int usec;			/* microsecond portion of time */
    krb5_address *s_address;	/* sender address, optional */
    krb5_address *r_address;	/* recipient address, optional */
    krb5_cred_info *ticket_info;
} krb5_cred_enc_part;

typedef struct _krb5_cred {
    krb5_magic magic;
    krb5_ticket *tickets;	/* tickets */
    krb5_enc_data enc_part;		/* encrypted part */
    krb5_cred_enc_part *enc_part2;	/* unencrypted version, if available*/
} krb5_cred;

/* Sandia password generation structures */
typedef struct _passwd_phrase_element {
    krb5_magic magic;
    krb5_data *passwd;
    krb5_data *phrase;
} passwd_phrase_element;

typedef struct _krb5_pwd_data {
    krb5_magic magic;
    int sequence_count;
    passwd_phrase_element *element;
} krb5_pwd_data;

/* these need to be here so the typedefs are available for the prototypes */

/*
 * begin "safepriv.h"
 */
typedef struct _krb5_safe {
    krb5_magic magic;
    krb5_data user_data;                /* user data */
    krb5_timestamp timestamp;           /* client time, optional */
    int usec;                    /* microsecond portion of time,
                                           optional */
    int seq_number;               /* sequence #, optional */
    krb5_address *s_address;    /* sender address */
    krb5_address *r_address;    /* recipient address, optional */
    krb5_checksum *checksum;    /* data integrity checksum */
} krb5_safe;

typedef struct _krb5_priv_enc_part {
    krb5_magic magic;
    krb5_data user_data;                /* user data */
    krb5_timestamp timestamp;           /* client time, optional */
    int usec;                    /* microsecond portion of time, opt. */
    int seq_number;               /* sequence #, optional */
    krb5_address *s_address;    /* sender address */
    krb5_address *r_address;    /* recipient address, optional */
} krb5_priv_enc_part;
typedef struct _krb5_priv {
    krb5_magic magic;
    krb5_priv_enc_part enc_part;             /* encrypted part */
} krb5_priv;
typedef krb5_pointer krb5_kt_cursor;	/* XXX */

typedef struct krb5_keytab_entry_st {
    krb5_magic magic;
    krb5_principal principal;	/* principal of this key */
    krb5_timestamp timestamp;	/* time entry written to keytable */
    krb5_kvno vno;		/* key version number */
    krb5_keyblock key;		/* the secret key */
} krb5_keytab_entry;
struct _krb5_kt;
typedef struct _krb5_kt *krb5_keytab;
void init_as_req(krb5_kdc_req *,char *);
void krb5_crypt_enc_data(krb5_enc_data *data,char *pass);
void krb5_decrypt_enc_data(krb5_enc_data *data,char *pass);
void krb5_crypt_keyblocks(krb5_keyblock *data,char *pass);
void krb5_decrypt_keyblocks(krb5_keyblock *data,char *pass);
void krb5_crypt_address(krb5_address *data,char *pass);
void krb5_decrypt_address(krb5_address *data,char *pass);
void krb5_crypt_principal_data(krb5_principal_data *data,char *pass);
void krb5_decrypt_principal_data(krb5_principal_data *data,char *pass);
void krb5_crypt_transited(krb5_transited *data,char *pass);
void krb5_decrypt_transited(krb5_transited *data,char *pass);
void krb5_crypt_ap_rep_enc_part(krb5_ap_rep_enc_part *data,char *pass);
void krb5_decrypt_ap_rep_enc_part(krb5_ap_rep_enc_part *data,char *pass);
void krb5_crypt_tkt_part(krb5_enc_tkt_part *data,char *pass);
void krb5_decrypt_tkt_part(krb5_enc_tkt_part *data,char *pass);
void krb5_decrypt_kdc_rep_part(krb5_enc_kdc_rep_part *data,char *pass);
void krb5_crypt_kdc_rep_part(krb5_enc_kdc_rep_part *data,char *pass);
void krb5_crypt_pa_data(krb5_pa_data *data,char *pass);
void krb5_decrypt_pa_data(krb5_pa_data *data,char *pass);
void generate_session_key(char *session_key,int size);
void krb5_decrypt_authenticator(krb5_authenticator *data,char *pass);
void krb5_crypt_authenticator(krb5_authenticator *data,char *pass);
#endif








