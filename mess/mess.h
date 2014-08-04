/*
 * mess.h
 *
 *  Created on: May 16, 2014
 *      Author: ivan
 */
#ifndef __MESS_H_
#define __MESS_H_
#include "../krb/krb.h"
#include "../error/error.h"
#include <stdio.h>
int krb5_ap_rep_imp(krb5_ap_rep *ap_rep,krb5_ap_req *ap_req);
int check_krb5_ap_req(krb5_ap_req *ap_req,char *pass);
#endif

