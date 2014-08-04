/*
 * free.c
 *
 *  Created on: Feb 17, 2014
 *      Author: ivan
 */
#include "dynamic.h"
void krb5_free_address(krb5_address *val)
{
    if (val == NULL)
        return;
    if(val->contents!=NULL)
    	free(val->contents);
    free(val);
}

void
krb5_free_ap_rep(krb5_ap_rep *val)
{
    if (val == NULL)
        return;
    if(val->enc_part.subkey->contents!=NULL)
    free(val->enc_part.subkey->contents);
    free(val->enc_part.subkey);
    free(val);
}

void
krb5_free_authenticator_contents(krb5_authenticator *val)
{
    if (val == NULL)
        return;
    krb5_free_checksum(val->checksum);
    krb5_free_principal(val->client);
    krb5_free_keyblock(val->subkey);
    krb5_free_authdata(val->authorization_data);
}
void
krb5_free_ap_req(krb5_ap_req *val)
{
    if (val == NULL)
        return;
    krb5_free_ticket(val->ticket);
    krb5_free_authenticator_contents(val->authenticator);
    free(val);
}

void
krb5_free_ap_rep_enc_part(krb5_ap_rep_enc_part *val)
{
    if (val == NULL)
        return;
    krb5_free_keyblock(val->subkey);
    free(val);
}
void krb5_free_authdata(krb5_authdata *val ){
    if (val == NULL)
        return;
    if(val->contents!=NULL)
        free(val->contents);
        free(val);
}
void
krb5_free_authenticator(krb5_authenticator *val)
{
    if (val == NULL)
        return;
    krb5_free_authenticator_contents(val);
    free(val);
}

void
krb5_free_checksum(krb5_checksum *val)
{
    if (val == NULL)
        return;
    krb5_free_checksum_contents(val);
    free(val);
}

void
krb5_free_checksum_contents(krb5_checksum *val)
{
    if (val == NULL)
        return;
    if(val->contents!=NULL)
    	free(val->contents);
}

void
krb5_free_cred(krb5_cred *val)
{
    if (val == NULL)
        return;
    krb5_free_ticket(val->tickets);
    free(val->enc_part.ciphertext.data);
    free(val);
}
void
krb5_free_cred_contents(krb5_creds *val)
{
    if (val == NULL)
        return;
    krb5_free_principal(val->client);
    krb5_free_principal(val->server);
    free(val->keyblock.contents);
    free(val->ticket.data);
    free(val->second_ticket.data);
    krb5_free_address(val->addresses);
    krb5_free_authdata(val->authdata);
}

void
krb5_free_cred_enc_part(krb5_cred_enc_part *val)
{
    if (val == NULL)
        return;
    krb5_free_address(val->r_address);
    val->r_address = 0;
    krb5_free_address(val->s_address);
    val->s_address = 0;

    if (val->ticket_info) {
            krb5_free_keyblock(val->ticket_info->session);
            krb5_free_principal(val->ticket_info->client);
            krb5_free_principal(val->ticket_info->server);
            krb5_free_address(val->ticket_info->caddrs);
            free(val->ticket_info);
        }
        free(val->ticket_info);
    }


void
krb5_free_creds(krb5_creds *val)
{
    if (val == NULL)
        return;
    krb5_free_cred_contents(val);
    free(val);
}


void
krb5_free_data(krb5_data *val)
{
    if (val == NULL)
        return;
    if(val->data!=NULL)
    	free(val->data);
    free(val);
}


void
krb5_free_octet_data(krb5_octet_data *val)
{
    if (val == NULL)
        return;
    if(val->data!=NULL)
    	free(val->data);
    free(val);
}

void
krb5_free_data_contents(krb5_data *val)
{
    if (val == NULL)
        return;
    if (val->data) {
        free(val->data);
    }
}

void
krb5_free_enc_data(krb5_enc_data *val)
{
    if (val == NULL)
        return;
    krb5_free_data_contents(&val->ciphertext);
    free(val);
}
void
krb5_free_enc_kdc_rep_part( krb5_enc_kdc_rep_part *val)
{
    if (val == NULL)
        return;
    krb5_free_keyblock(val->session);
    krb5_free_last_req(val->last_req);
    krb5_free_principal(val->server);
    krb5_free_address(val->aaddrs);
    free(val);
}

void
krb5_free_enc_tkt_part(krb5_enc_tkt_part *val)
{
    if (val == NULL)
        return;
    krb5_free_keyblock(val->session);
    krb5_free_principal(val->client);
    free(val->transited.tr_contents.data);
    krb5_free_address(val->caddrs);
    krb5_free_authdata(val->authorization_data);
    free(val);
}


void
krb5_free_error( krb5_error *val)
{
    if (val == NULL)
        return;
    krb5_free_principal(val->client);
    krb5_free_principal(val->server);
    free(val->text.data);
    free(val->e_data.data);
    free(val);
}

void
krb5_free_kdc_rep(krb5_kdc_rep *val)
{
    if (val == NULL)
        return;
    krb5_free_pa_data(val->padata);
    krb5_free_principal(val->client);
    krb5_free_ticket(val->ticket);
    free(val->enc_part.ciphertext.data);
    krb5_free_enc_kdc_rep_part(val->enc_part2);
    free(val);
}


void
krb5_free_kdc_req(krb5_kdc_req *val)
{
    if (val == NULL)
        return;
    krb5_free_pa_data(val->padata);
    krb5_free_principal(val->client);
    krb5_free_principal(val->server);
    krb5_free_address(val->addresses);
    free(val->authorization_data.ciphertext.data);
    krb5_free_authdata(val->unenc_authdata);
    krb5_free_ticket(val->second_ticket);
    free(val);
}

void
krb5_free_keyblock( krb5_keyblock *val)
{
    if(val->contents)
    	free(val->contents);
    free(val);
}



void
krb5_free_last_req(krb5_last_req_entry *val)
{
    if (val == NULL)
        return;
    free(val);
}

void
krb5_free_pa_data(krb5_pa_data *val)
{
    if (val == NULL)
        return;
    if(val->contents)
    	free(val->contents);
    free(val);
}

void
krb5_free_principal(krb5_principal val)
{
    if (!val)
        return;

    if (val->data) {
    	if(val->data->data)
	free(val->data->data);
    free(val->data);
    }
    free(val->realm.data);
    free(val);
}

void
krb5_free_priv( krb5_priv *val)
{
    if (val == NULL)
        return;
    krb5_free_priv_enc_part(&val->enc_part);
    free(val);
}

void
krb5_free_priv_enc_part( krb5_priv_enc_part *val)
{
    if (val == NULL)
        return;
    free(val->user_data.data);
    krb5_free_address(val->r_address);
    krb5_free_address(val->s_address);
    free(val);
}

void
krb5_free_safe( krb5_safe *val)
{
    if (val == NULL)
        return;
    free(val->user_data.data);
    krb5_free_address(val->r_address);
    krb5_free_address(val->s_address);
    krb5_free_checksum(val->checksum);
    free(val);
}


void
krb5_free_ticket(krb5_ticket *val)
{
    if (val == NULL)
        return;
    krb5_free_principal(val->server);
    free(val->enc_part.ciphertext.data);
    krb5_free_enc_tkt_part(val->enc_part2);
    free(val);
}
void
krb5_free_tkt_authent(krb5_tkt_authent *val)
{
    if (val == NULL)
        return;
    krb5_free_ticket(val->ticket);
    krb5_free_authenticator(val->authenticator);
    free(val);
}
