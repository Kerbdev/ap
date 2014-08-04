/*
 * krb5_ap_rep.c
 *
 *  Created on: May 16, 2014
 *      Author: ivan
 */

#include "mess.h"
#include "string.h"
#include "../parser//get_config_param.h"
#include "../parser/ini.h"
#include "stdlib.h"
int krb5_ap_rep_imp(krb5_ap_rep *ap_rep,krb5_ap_req *ap_req){
	ap_rep->msg_type=KRB5_AP_REP;
	configuration conf;
	conf.name=malloc(strlen(ap_req->authenticator->authorization_data->contents)+1);
	if(ap_req->authenticator->authorization_data->contents!=NULL)
	strcpy(conf.name,ap_req->authenticator->authorization_data->contents);
	get_config_param(&conf);
	ap_rep->enc_part.subkey->contents=malloc(strlen(conf.key)+1);
	ap_rep->enc_part.subkey->contents=conf.key;
	fprintf(stderr,"%s",ap_rep->enc_part.subkey->contents);
	krb5_crypt_ap_rep_enc_part(&ap_rep->enc_part,ap_req->ticket->enc_part2->session->contents);
	return 0;

}
