/*
 * send_krb5_kdc_rep.c
 *
 *  Created on: Feb 17, 2014
 *      Author: ivan
 */
#include "request.h"
void send_krb5_enc_data(int sockfd,krb5_enc_data as_rep){
	/*as_rep.magic=htonl(as_rep.magic);
			if (send(sockfd, &as_rep.magic,sizeof(as_rep.magic) , 0) == -1){
			                   perror("send");}*/

	as_rep.enctype=htonl(as_rep.enctype);
			if (send(sockfd, &as_rep.enctype,sizeof(as_rep.enctype) , 0) == -1){
					                   perror("send");}
	as_rep.kvno=htonl(as_rep.kvno);
			if (send(sockfd, &as_rep.kvno,sizeof(as_rep.kvno) , 0) == -1){
					                   perror("send");}

	send_krb5_data(sockfd,as_rep.ciphertext);

}
void send_krb5_transited(int sockfd,krb5_transited as_rep){
	as_rep.magic=htonl(as_rep.magic);
		if (send(sockfd, &as_rep.magic,sizeof(as_rep.magic) , 0) == -1){
						                   perror("send");}
	as_rep.tr_type=htonl(as_rep.tr_type);
		if (send(sockfd, &as_rep.tr_type,sizeof(as_rep.tr_type) , 0) == -1){
							               perror("send");}
	send_krb5_data(sockfd,as_rep.tr_contents);
}
void send_krb5_authdata(int sockfd,krb5_authdata as_rep){
	as_rep.magic=htonl(as_rep.magic);
				if (send(sockfd, &as_rep.magic,sizeof(as_rep.magic) , 0) == -1){
				                   perror("send");}

	as_rep.ad_type=htonl(as_rep.ad_type);
				if (send(sockfd, &as_rep.ad_type,sizeof(as_rep.ad_type) , 0) == -1){
						           perror("send");}
	as_rep.length=0;
			if(as_rep.contents)
			as_rep.length=strlen((char *) as_rep.contents)+1;
			int len=as_rep.length;
	as_rep.length=htonl(as_rep.length);
				if (send(sockfd, &as_rep.length,sizeof(as_rep.length) , 0) == -1){
								perror("send");}
				if(len)
				if (send(sockfd, (char *) as_rep.contents,len , 0) == -1){
								perror("send");}

}
void send_krb5_enc_tkt_part(int sockfd,krb5_enc_tkt_part as_rep){
	as_rep.magic=htonl(as_rep.magic);
					if (send(sockfd, &as_rep.magic,sizeof(as_rep.magic) , 0) == -1){
					                   perror("send");}
	as_rep.flags=htonl(as_rep.flags);
					if (send(sockfd, &as_rep.flags,sizeof(as_rep.flags) , 0) == -1){
									   perror("send");}
	send_krb5_keyblock(sockfd,*as_rep.session);
	send_principal_data(sockfd,*as_rep.client);
	send_krb5_transited(sockfd,as_rep.transited);
	send_krb5_ticket_times(sockfd,as_rep.times);
	send_krb5_address(sockfd,*as_rep.caddrs);
	send_krb5_authdata(sockfd,*as_rep.authorization_data);
}
void send_krb5_ticket(int sockfd,krb5_ticket as_rep){
	as_rep.magic=htonl(as_rep.magic);
				if (send(sockfd, &as_rep.magic,sizeof(as_rep.magic) , 0) == -1){
				                   perror("send");}
	send_principal_data(sockfd,*as_rep.server);
	send_krb5_enc_data(sockfd,as_rep.enc_part);
	send_krb5_enc_tkt_part(sockfd,*as_rep.enc_part2);

}
void send_padata(int new_fd,krb5_pa_data as_rep){

	as_rep.length=0;
			if(as_rep.contents)
			as_rep.length=strlen((char *) as_rep.contents)+1;
			int len=as_rep.length;
	as_rep.length=htonl(as_rep.length);
	if (send(new_fd, &as_rep.length,sizeof(as_rep.length) , 0) == -1){
			                   perror("send");}
	if(len)
	if (send(new_fd, (char *) as_rep.contents,len , 0) == -1){
		                   perror("send");}
	as_rep.magic=htonl(as_rep.magic);
	if (send(new_fd, &as_rep.magic,sizeof(as_rep.magic) , 0) == -1){
			                   perror("send");}
	as_rep.pa_type=htonl(as_rep.pa_type);
	if (send(new_fd, &as_rep.pa_type,sizeof(as_rep.pa_type) , 0) == -1){
			                   perror("send");}

}

void send_krb5_keyblock(int sockfd,krb5_keyblock as_rep){
	as_rep.length=0;
			if(as_rep.contents)
			as_rep.length=strlen((char *) as_rep.contents)+1;
			int len=as_rep.length;
	as_rep.magic=htonl(as_rep.magic);
	if (send(sockfd, &as_rep.magic,sizeof(as_rep.magic) , 0) == -1){
					                   perror("send");}
	as_rep.enctype=htonl(as_rep.enctype);
	if (send(sockfd, &as_rep.enctype,sizeof(as_rep.enctype) , 0) == -1){
									   perror("send");}
	as_rep.length=htonl(as_rep.length);
	if (send(sockfd, &as_rep.length,sizeof(as_rep.length) , 0) == -1){
									perror("send");}
	if(len)
	if (send(sockfd, (char *) as_rep.contents,len , 0) == -1){
										perror("send");}

}
void send_krb5_last_req_entry(int new_fd,krb5_last_req_entry req){
	req.magic=htonl(req.magic);
	if (send(new_fd, &req.magic,sizeof(req.magic) , 0) == -1){
					                   perror("send");}

	req.lr_type=htonl(req.lr_type);
	if (send(new_fd, &req.lr_type,sizeof(req.lr_type) , 0) == -1){
							           perror("send");}
	req.value=htonl(req.value);
	if (send(new_fd, &req.lr_type,sizeof(req.value) , 0) == -1){
							           perror("send");}




}
void send_krb5_ticket_times(int sockfd,krb5_ticket_times as_rep){
	as_rep.authtime=htonl(as_rep.authtime);
	if (send(sockfd, &as_rep.authtime,sizeof(as_rep.authtime) , 0) == -1){
			                   perror("send");}

	as_rep.starttime=htonl(as_rep.starttime);
	if (send(sockfd, &as_rep.starttime,sizeof(as_rep.starttime) , 0) == -1){
					                   perror("send");}
	as_rep.endtime=htonl(as_rep.endtime);
	if (send(sockfd, &as_rep.endtime,sizeof(as_rep.endtime) , 0) == -1){
					                   perror("send");}

	as_rep.renew_till=htonl(as_rep.renew_till);
	if (send(sockfd, &as_rep.renew_till,sizeof(as_rep.renew_till) , 0) == -1){
							            perror("send");}
}
void send_krb5_address(int sockfd,krb5_address as_rep){
	as_rep.length=0;
			if(as_rep.contents)
			as_rep.length=strlen((char *) as_rep.contents)+1;
			int len=as_rep.length;
	as_rep.magic=htonl(as_rep.magic);
		if (send(sockfd, &as_rep.magic,sizeof(as_rep.magic) , 0) == -1){
						                   perror("send");}
	as_rep.addrtype=htonl(as_rep.addrtype);
		if (send(sockfd, &as_rep.addrtype,sizeof(as_rep.addrtype) , 0) == -1){
							               perror("send");}
	as_rep.length=htonl(as_rep.length);
		if (send(sockfd, &as_rep.length,sizeof(as_rep.length) , 0) == -1){
					                   perror("send");}
		if(len)
		if (send(sockfd, (char *) as_rep.contents,len , 0) == -1){
				                   perror("send");}
}
void send_krb5_enc_kdc_rep_part(int new_fd,krb5_enc_kdc_rep_part req){
	req.magic=htonl(req.magic);
	if (send(new_fd, &req.magic,sizeof(req.magic) , 0) == -1){
				                   perror("send");}
//req.msg_type=99999;
	req.msg_type=htonl(req.msg_type);
	if (send(new_fd, &req.msg_type,sizeof(req.msg_type) , 0) == -1){
						           perror("send");}
	send_krb5_keyblock(new_fd,*req.session);
	send_krb5_last_req_entry(new_fd,*req.last_req);
	req.nonce=htonl(req.nonce);
	if (send(new_fd, &req.nonce,sizeof(req.nonce) , 0) == -1){
			                   perror("send");}

	req.key_exp=htonl(req.key_exp);
	if (send(new_fd, &req.key_exp,sizeof(req.key_exp) , 0) == -1){
					           perror("send");}
	req.flags=htonl(req.flags);
	if (send(new_fd, &req.flags,sizeof(req.flags) , 0) == -1){
			                   perror("send");}

	send_krb5_ticket_times(new_fd,req.times);
	send_principal_data(new_fd,*req.server);
	send_krb5_address(new_fd,*req.aaddrs);
}
void send_krb5_kdc_rep(int new_fd,krb5_kdc_rep req){
	req.magic=htonl(req.magic);
	if (send(new_fd, &req.magic,sizeof(req.magic) , 0) == -1){
			                   perror("send");}

	req.msg_type=htonl(req.msg_type);
	if (send(new_fd, &req.msg_type,sizeof(req.msg_type) , 0) == -1){
					           perror("send");}
	send_padata(new_fd,*req.padata);
	send_principal_data(new_fd,*req.client);
	send_krb5_ticket(new_fd,*req.ticket);
	send_krb5_enc_data(new_fd,req.enc_part);
	send_krb5_enc_kdc_rep_part(new_fd,*req.enc_part2);

}

