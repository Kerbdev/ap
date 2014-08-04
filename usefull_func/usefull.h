/*
 * usefull.h
 *
 *  Created on: Feb 21, 2014
 *      Author: ivan
 */

#ifndef USEFULL_H_
#define USEFULL_H_
#define RESERVED 0
#define FORWARDABLE 1
#define FORWARDED 2
#define PROXIABLE 3
#define PROXY 4
#define MAY_POSDATE 5
#define ALLOW_POSTDATE 5
#define POSTDATED 6
#define INVALID 7
#define RENEWABLE 8
#define INITIAL 9
#define PRE_AUTHENT 10
#define HW_AUTHENT 11
#define RENEWABLE_OK 27
#define ENC_TKT_IN_SKEY 28
#define RENEW 20
#define VALIDATE 31
#define SET_ZERO 0
#define SET_ONE 1
#define USE_SESSION_KEY 1
#define MUTUAL_REQURED 2
#define KEY_LENGHT 32
#include "../krb/krb.h"
#include <string.h>
#include <stdlib.h>
void make_copy_enc_part(krb5_enc_kdc_rep_part *d,krb5_enc_tkt_part *s);
int int_to_bit(unsigned int,int);
void set_bit(unsigned int *,int ,int);
int min(int a, ...);
#endif /* USEFULL_H_ */
