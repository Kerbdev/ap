/*
 * send_krb_ap_rep.c
 *
 *  Created on: Feb 17, 2014
 *      Author: ivan
 */
#include "request.h"

void send_krb5_ap_rep_enc_part(int sockfd,krb5_ap_rep_enc_part req){
	req.magic=ntohl(req.magic);
	if (send(sockfd, &req.magic,sizeof(req.magic) , 0) == -1){
				                   perror("send");}
	req.ctime=ntohl(req.ctime);
		if (send(sockfd, &req.ctime,sizeof(req.ctime) , 0) == -1){
				                   perror("send");}

		req.cusec=ntohl(req.cusec);
		if (send(sockfd, &req.cusec,sizeof(req.cusec) , 0) == -1){
						                   perror("send");}



		send_krb5_keyblock(sockfd,*req.subkey);
		req.seq_number=ntohl(req.seq_number);
		if (send(sockfd, &req.seq_number,sizeof(req.seq_number) , 0) == -1){
						                   perror("send");}

}


void send_krb5_ap_rep(int sockfd,krb5_ap_rep req){
	req.magic=ntohl(req.magic);

	if (send(sockfd, &req.magic,sizeof(req.magic) , 0) == -1){
			                   perror("send");}
	req.msg_type=ntohl(req.msg_type);
	if (send(sockfd, &req.msg_type,sizeof(req.msg_type) , 0) == -1){
			                   perror("send");}

	send_krb5_ap_rep_enc_part(sockfd,req.enc_part);

}
