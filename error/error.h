/*
 * error.h
 *
 *  Created on: Feb 11, 2014
 *      Author: ivan
 */

#ifndef ERROR_H_
#define ERROR_H_

#define KDC_ERR_NONE                    0 /* No error */
#define KDC_ERR_NAME_EXP                1 /* Client's entry in DB expired */
#define KDC_ERR_SERVICE_EXP             2 /* Server's entry in DB expired */
#define KDC_ERR_BAD_PVNO                3 /* Requested pvno not supported */
#define KDC_ERR_C_OLD_MAST_KVNO         4 /* C's key encrypted in old master */
#define KDC_ERR_S_OLD_MAST_KVNO         5 /* S's key encrypted in old master */
#define KDC_ERR_C_PRINCIPAL_UNKNOWN     6 /* Client not found in Kerberos DB */
#define KDC_ERR_S_PRINCIPAL_UNKNOWN     7 /* Server not found in Kerberos DB */
#define KDC_ERR_PRINCIPAL_NOT_UNIQUE    8 /* Multiple entries in Kerberos DB */
#define KDC_ERR_NULL_KEY                9 /* The C or S has a null key */
#define KDC_ERR_CANNOT_POSTDATE         10 /* Tkt ineligible for postdating */
#define KDC_ERR_NEVER_VALID             11 /* Requested starttime > endtime */
#define KDC_ERR_POLICY                  12 /* KDC policy rejects request */
#define KDC_ERR_BADOPTION               13 /* KDC can't do requested opt. */
#define KDC_ERR_ENCTYPE_NOSUPP          14 /* No support for encryption type */
#define KDC_ERR_SUMTYPE_NOSUPP          15 /* No support for checksum type */
#define KDC_ERR_PADATA_TYPE_NOSUPP      16 /* No support for padata type */
#define KDC_ERR_TRTYPE_NOSUPP           17 /* No support for transited type */
#define KDC_ERR_CLIENT_REVOKED          18 /* C's creds have been revoked */
#define KDC_ERR_SERVICE_REVOKED         19 /* S's creds have been revoked */
#define KDC_ERR_TGT_REVOKED             20 /* TGT has been revoked */
#define KDC_ERR_CLIENT_NOTYET           21 /* C not yet valid */
#define KDC_ERR_SERVICE_NOTYET          22 /* S not yet valid */
#define KDC_ERR_KEY_EXP                 23 /* Password has expired */
#define KDC_ERR_PREAUTH_FAILED          24 /* Preauthentication failed */
#define KDC_ERR_PREAUTH_REQUIRED        25 /* Additional preauthentication */
                                           /* required */
#define KDC_ERR_SERVER_NOMATCH          26 /* Requested server and */
                                           /* ticket don't match*/
#define KDC_ERR_MUST_USE_USER2USER      27 /* Server principal valid for */
                                           /*   user2user only */
#define KDC_ERR_PATH_NOT_ACCEPTED       28 /* KDC policy rejected transited */
                                           /*   path */
#define KDC_ERR_SVC_UNAVAILABLE         29 /* A service is not
                                            * available that is
                                            * required to process the
                                            * request */
/* Application errors */
#define KRB_AP_ERR_BAD_INTEGRITY 31     /* Decrypt integrity check failed */
#define KRB_AP_ERR_TKT_EXPIRED  32      /* Ticket expired */
#define KRB_AP_ERR_TKT_NYV      33      /* Ticket not yet valid */
#define KRB_AP_ERR_REPEAT       34      /* Request is a replay */
#define KRB_AP_ERR_NOT_US       35      /* The ticket isn't for us */
#define KRB_AP_ERR_BADMATCH     36      /* Ticket/authenticator don't match */
#define KRB_AP_ERR_SKEW         37      /* Clock skew too great */
#define KRB_AP_ERR_BADADDR      38      /* Incorrect net address */
#define KRB_AP_ERR_BADVERSION   39      /* Protocol version mismatch */
#define KRB_AP_ERR_MSG_TYPE     40      /* Invalid message type */
#define KRB_AP_ERR_MODIFIED     41      /* Message stream modified */
#define KRB_AP_ERR_BADORDER     42      /* Message out of order */
#define KRB_AP_ERR_BADKEYVER    44      /* Key version is not available */
#define KRB_AP_ERR_NOKEY        45      /* Service key not available */
#define KRB_AP_ERR_MUT_FAIL     46      /* Mutual authentication failed */
#define KRB_AP_ERR_BADDIRECTION 47      /* Incorrect message direction */
#define KRB_AP_ERR_METHOD       48      /* Alternative authentication */
                                        /* method required */
#define KRB_AP_ERR_BADSEQ       49      /* Incorrect sequence numnber */
                                        /* in message */
#define KRB_AP_ERR_INAPP_CKSUM  50      /* Inappropriate type of */
                                        /* checksum in message */
#define KRB_AP_PATH_NOT_ACCEPTED 51     /* Policy rejects transited path */
#define KRB_ERR_RESPONSE_TOO_BIG 52     /* Response too big for UDP, */
                                        /*   retry with TCP */

/* other errors */
#define KRB_ERR_GENERIC         60      /* Generic error (description */
                                        /* in e-text) */
#define KRB_ERR_FIELD_TOOLONG   61      /* Field is too long for impl. */

/* PKINIT server-reported errors */
#define KDC_ERR_CLIENT_NOT_TRUSTED              62 /* client cert not trusted */
#define KDC_ERR_KDC_NOT_TRUSTED                 63
#define KDC_ERR_INVALID_SIG                     64 /* client signature verify failed */
#define KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED  65 /* invalid Diffie-Hellman parameters */
#define KDC_ERR_CERTIFICATE_MISMATCH            66
#define KRB_AP_ERR_NO_TGT                       67
#define KDC_ERR_WRONG_REALM                     68
#define KRB_AP_ERR_USER_TO_USER_REQUIRED        69
#define KDC_ERR_CANT_VERIFY_CERTIFICATE         70 /* client cert not verifiable to */
                                                   /* trusted root cert */
#define KDC_ERR_INVALID_CERTIFICATE             71 /* client cert had invalid signature */
#define KDC_ERR_REVOKED_CERTIFICATE             72 /* client cert was revoked */
#define KDC_ERR_REVOCATION_STATUS_UNKNOWN       73 /* client cert revoked, reason unknown */
#define KDC_ERR_REVOCATION_STATUS_UNAVAILABLE   74
#define KDC_ERR_CLIENT_NAME_MISMATCH            75 /* mismatch between client cert and */
                                                   /* principal name */
#define KDC_ERR_INCONSISTENT_KEY_PURPOSE        77 /* bad extended key use */
#define KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED     78 /* bad digest algorithm in client cert */
#define KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED    79 /* missing paChecksum in PA-PK-AS-REQ */
#define KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED 80 /* bad digest algorithm in SignedData */
#define KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED 81
#define KRB_AP_ERR_IAKERB_KDC_NOT_FOUND         85 /* The IAKERB proxy could
                                                      not find a KDC */
#define KRB_AP_ERR_IAKERB_KDC_NO_RESPONSE       86 /* The KDC did not respond
                                                      to the IAKERB proxy */

#endif /* ERROR_H_ */
int decrypt_error();
