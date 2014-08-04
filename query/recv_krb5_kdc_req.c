/*
 * request.c
 *
 *  Created on: Jan 10, 2014
 *      Author: ivan
 */
#include "request.h"
void send_principal_data(int new_fd,krb5_principal_data as_rep){
	    as_rep.length=htonl(as_rep.length);
		if (send(new_fd, &as_rep.length,sizeof(as_rep.length) , 0) == -1){
				                   perror("send");}
		send_krb5_data(new_fd,as_rep.realm);
		send_krb5_data(new_fd,*as_rep.data);

		as_rep.magic=htonl(as_rep.magic);
		if (send(new_fd, &as_rep.magic,sizeof(as_rep.magic) , 0) == -1){
						                   perror("send");}
		as_rep.type=htonl(as_rep.type);
		if (send(new_fd, &as_rep.type,sizeof(as_rep.type) , 0) == -1){
								                   perror("send");}



}

void send_krb5_data(int new_fd,krb5_data as_rep){
	as_rep.magic=htonl(as_rep.magic);
	if (send(new_fd, &as_rep.magic,sizeof(as_rep.magic) , 0) == -1){
					                   perror("send");}
	as_rep.length=0;
	if(as_rep.data)
	as_rep.length=strlen(as_rep.data)+1;
	int len=as_rep.length;
	as_rep.length=htonl(as_rep.length);
	if (send(new_fd, &as_rep.length,sizeof(as_rep.length) , 0) == -1){
						                   perror("send");}
	if(len)
	if (send(new_fd, as_rep.data,len , 0) == -1){
						                   perror("send");}

}
void recv_padata(int new_fd,krb5_pa_data *as_rep){
	if (recv(new_fd, &as_rep->length,sizeof(as_rep->length) , 0) == -1){
			                   perror("recv");}
	as_rep->length=ntohl(as_rep->length);
	if(as_rep->length){
	as_rep->contents=(krb5_octet *) malloc(as_rep->length);
	if (recv(new_fd, (char *)as_rep->contents,as_rep->length, 0) == -1){
		                   perror("recv");}}
	if (recv(new_fd, &as_rep->magic,sizeof(as_rep->magic) , 0) == -1){
			                   perror("recv");}
	as_rep->magic=ntohl(as_rep->magic);
	if (recv(new_fd, &as_rep->pa_type,sizeof(as_rep->pa_type) , 0) == -1){
			                   perror("recv");}

	as_rep->pa_type=ntohl(as_rep->pa_type);

}
void recv_principal_data(int new_fd,krb5_principal_data *as_rep){

		if (recv(new_fd, &as_rep->length,sizeof(as_rep->length) , 0) == -1){
				                   perror("recv");}
		as_rep->length=ntohl(as_rep->length);
		recv_krb5_data(new_fd,(krb5_data *) &as_rep->realm);
		recv_krb5_data(new_fd,as_rep->data);


		if (recv(new_fd, &as_rep->magic,sizeof(as_rep->magic) , 0) == -1){
						                   perror("recv");}
		as_rep->magic=ntohl(as_rep->magic);

		if (recv(new_fd, &as_rep->type,sizeof(as_rep->type) , 0) == -1){
								                   perror("recv");}
		as_rep->type=ntohl(as_rep->type);


}

void recv_krb5_data(int new_fd,krb5_data *as_rep){

	if (recv(new_fd, &as_rep->magic,sizeof(as_rep->magic) , 0) == -1){
					                   perror("recv");}
	as_rep->magic=ntohl(as_rep->magic);

	if (recv(new_fd, &as_rep->length,sizeof(as_rep->length) , 0) == -1){
						                   perror("recv");}
	as_rep->length=ntohl(as_rep->length);
	if(as_rep->length){
	as_rep->data=(char *)malloc(as_rep->length);
	if (recv(new_fd, as_rep->data,as_rep->length , 0) == -1){
						                   perror("recv1");}}
}


void recv_krb5_address(int new_fd,krb5_address *as_rep){

		if (recv(new_fd, &as_rep->magic,sizeof(as_rep->magic) , 0) == -1){
						                   perror("recv");}
		as_rep->magic=ntohl(as_rep->magic);

		if (recv(new_fd, &as_rep->addrtype,sizeof(as_rep->addrtype) , 0) == -1){
							               perror("recv3");}
		as_rep->addrtype=ntohl(as_rep->addrtype);

		if (recv(new_fd, &as_rep->length,sizeof(as_rep->length) , 0) == -1){
					                   perror("recv2");}
		as_rep->length=ntohl(as_rep->length);
		if(as_rep->length){
		as_rep->contents=(krb5_octet *)malloc(as_rep->length);
		if (recv(new_fd, (char *) as_rep->contents,as_rep->length , 0) == -1){
				                   perror("recv1");}}
}
void recv_krb5_enc_data(int new_fd,krb5_enc_data *as_rep){

		/*	if (recv(new_fd, &as_rep->magic,sizeof(as_rep->magic) , 0) == -1){
			                   perror("recv");}
			as_rep->magic=ntohl(as_rep->magic);*/

			if (recv(new_fd, &as_rep->enctype,sizeof(as_rep->enctype) , 0) == -1){
					                   perror("recv");}
			as_rep->enctype=ntohl(as_rep->enctype);
			if (recv(new_fd, &as_rep->kvno,sizeof(as_rep->kvno) , 0) == -1){
					                   perror("recv");}
			as_rep->kvno=ntohl(as_rep->kvno);

	recv_krb5_data(new_fd,&as_rep->ciphertext);

}
void recv_krb5_authdata(int new_fd,krb5_authdata *as_rep){

				if (recv(new_fd, &as_rep->magic,sizeof(as_rep->magic) , 0) == -1){
				                   perror("recv");}
				as_rep->magic=ntohl(as_rep->magic);

				if (recv(new_fd, &as_rep->ad_type,sizeof(as_rep->ad_type) , 0) == -1){
						           perror("recv");}
				as_rep->ad_type=ntohl(as_rep->ad_type);

				if (recv(new_fd, &as_rep->length,sizeof(as_rep->length) , 0) == -1){
								perror("recv");}
				as_rep->length=ntohl(as_rep->length);
				if(as_rep->length){
				as_rep->contents=(krb5_octet *)malloc(as_rep->length);
				if (recv(new_fd, (char *) as_rep->contents,as_rep->length , 0) == -1){
								perror("recv");}}


}
void recv_krb5_keyblock(int new_fd,krb5_keyblock *as_rep){

	if (recv(new_fd, &as_rep->magic,sizeof(as_rep->magic) , 0) == -1){
					                   perror("recv");}
	as_rep->magic=ntohl(as_rep->magic);

	if (recv(new_fd, &as_rep->enctype,sizeof(as_rep->enctype) , 0) == -1){
									   perror("recv");}
	as_rep->enctype=ntohl(as_rep->enctype);

	if (recv(new_fd, &as_rep->length,sizeof(as_rep->length) , 0) == -1){
									perror("recv");}
	as_rep->length=ntohl(as_rep->length);
	if(as_rep->length){
	as_rep->contents=(krb5_octet *)malloc(as_rep->length);
	if (recv(new_fd, (char *) as_rep->contents,as_rep->length , 0) == -1){
										perror("recv");}}

}
void recv_krb5_ticket_times(int new_fd,krb5_ticket_times *as_rep){

			if (recv(new_fd, &as_rep->authtime,sizeof(as_rep->authtime) , 0) == -1){
			                   perror("recv");}
			as_rep->authtime=ntohl(as_rep->authtime);
			if (recv(new_fd, &as_rep->starttime,sizeof(as_rep->starttime) , 0) == -1){
					                   perror("recv");}
			as_rep->starttime=ntohl(as_rep->starttime);

			if (recv(new_fd, &as_rep->endtime,sizeof(as_rep->endtime) , 0) == -1){
					                   perror("recv");}
			as_rep->endtime=ntohl(as_rep->endtime);
			if (recv(new_fd, &as_rep->renew_till,sizeof(as_rep->renew_till) , 0) == -1){
							                   perror("recv");}
			as_rep->renew_till=ntohl(as_rep->renew_till);


}
void recv_krb5_transited(int new_fd,krb5_transited *as_rep){

		if (recv(new_fd, &as_rep->magic,sizeof(as_rep->magic) , 0) == -1){
						                   perror("recv");}
		as_rep->magic=ntohl(as_rep->magic);

		if (recv(new_fd, &as_rep->tr_type,sizeof(as_rep->tr_type) , 0) == -1){
							               perror("recv");}
		as_rep->tr_type=ntohl(as_rep->tr_type);
	recv_krb5_data(new_fd,&as_rep->tr_contents);
}
void recv_krb5_enc_tkt_part(int new_fd,krb5_enc_tkt_part *as_rep){
	if (recv(new_fd, &as_rep->magic,sizeof(as_rep->magic) , 0) == -1){
					                   perror("recv");}
	as_rep->magic=ntohl(as_rep->magic);
	if (recv(new_fd, &as_rep->flags,sizeof(as_rep->flags) , 0) == -1){
									   perror("recv");}
	as_rep->flags=ntohl(as_rep->flags);

	recv_krb5_keyblock(new_fd,as_rep->session);
	recv_principal_data(new_fd,as_rep->client);
	recv_krb5_transited(new_fd,&as_rep->transited);
	recv_krb5_ticket_times(new_fd,&as_rep->times);
	recv_krb5_address(new_fd,as_rep->caddrs);
	recv_krb5_authdata(new_fd,as_rep->authorization_data);


}


void recv_krb5_ticket(int new_fd,krb5_ticket *as_rep){

	if (recv(new_fd, &as_rep->magic,sizeof(as_rep->magic) , 0) == -1){
				                   perror("recv");}
	as_rep->magic=ntohl(as_rep->magic);
	recv_principal_data(new_fd,as_rep->server);
	recv_krb5_enc_data(new_fd,&as_rep->enc_part);
	recv_krb5_enc_tkt_part(new_fd,as_rep->enc_part2);

}


void recv_krb5_kdc_req(int new_fd,krb5_kdc_req *as_rep,krb5_error *error){
//date sync

	if (recv(new_fd, &as_rep->magic,sizeof(as_rep->magic) , 0) == -1){
	                   perror("recv1");}
	as_rep->magic=ntohl(as_rep->magic);

	if (recv(new_fd, &as_rep->msg_type,sizeof(as_rep->msg_type) , 0) == -1){
		                   perror("recv2");}
	as_rep->msg_type=ntohl(as_rep->msg_type);
	if(as_rep->msg_type==KRB5_ERROR){
				recv_krb5_error(new_fd,error);
				error->magic=as_rep->magic;}
		else{
	recv_padata(new_fd,as_rep->padata);
	if (recv(new_fd, &as_rep->kdc_options,sizeof(as_rep->kdc_options) , 0) == -1){
			                   perror("recv3");}
	as_rep->kdc_options=ntohl(as_rep->kdc_options);

	recv_principal_data(new_fd,as_rep->client);
	recv_principal_data(new_fd,as_rep->server);

	if (recv(new_fd, &as_rep->from,sizeof(as_rep->from) , 0) == -1){
							                   perror("recv5");}
	as_rep->from=ntohl(as_rep->from);

	if (recv(new_fd, &as_rep->till,sizeof(as_rep->till) , 0) == -1){
									           perror("recv6");}
	as_rep->till=ntohl(as_rep->till);

	if (recv(new_fd, &as_rep->rtime,sizeof(as_rep->rtime) , 0) == -1){
											   perror("recv1");}

	as_rep->rtime=ntohl(as_rep->rtime);

	if (recv(new_fd, &as_rep->nonce,sizeof(as_rep->nonce) , 0) == -1){
											perror("recv2");}
	as_rep->nonce=ntohl(as_rep->nonce);

	if (recv(new_fd, &as_rep->nktypes,sizeof(as_rep->nktypes) , 0) == -1){
											perror("recv3");}
	as_rep->nktypes=ntohl(as_rep->nktypes);

	if (recv(new_fd, &as_rep->ktype,sizeof(as_rep->ktype) , 0) == -1){
											perror("recv4");}
	as_rep->ktype=ntohl(as_rep->ktype);

	recv_krb5_address(new_fd,as_rep->addresses);
	recv_krb5_authdata(new_fd,as_rep->unenc_authdata);
	recv_krb5_enc_data(new_fd ,&as_rep->authorization_data);
	recv_krb5_ticket(new_fd,as_rep->second_ticket);}}
