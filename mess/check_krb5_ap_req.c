/*
 * check_krb5_ap_req.c
 *
 *  Created on: May 16, 2014
 *      Author: ivan
 */

#include "mess.h"
int check_krb5_ap_req(krb5_ap_req *ap_req,char *pass){
	if(ap_req->msg_type!=KRB5_AP_REQ){
		perror("KRB_AP_ERR_MSG_TYPE");
		return KRB_AP_ERR_MSG_TYPE;
	}
	krb5_decrypt_tkt_part(ap_req->ticket->enc_part2,pass);
	krb5_decrypt_authenticator(ap_req->authenticator,ap_req->ticket->enc_part2->session->contents);
	return 0;


}
