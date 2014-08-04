/*
 * send_recv_krb5_cred.c
 *
 *  Created on: Feb 17, 2014
 *      Author: ivan
 */
#include "request.h"
void send_krb5_cred_info(int sockfd,krb5_cred_info cred_info){
	cred_info.magic=htonl(cred_info.magic);
	if (send(sockfd, &cred_info.magic,sizeof(cred_info.magic) , 0) == -1){
					                   perror("send");}
	send_krb5_keyblock(sockfd,*cred_info.session);
	send_principal_data(sockfd,*cred_info.client);
	send_principal_data(sockfd,*cred_info.server);
	cred_info.flags=htonl(cred_info.flags);
	if (send(sockfd, &cred_info.flags,sizeof(cred_info.flags) , 0) == -1){
						                perror("send");}
	send_krb5_ticket_times(sockfd,cred_info.times);
	send_krb5_address(sockfd,*cred_info.caddrs);
}
void send_krb5_cred_enc_part(int sockfd,krb5_cred_enc_part enc_part){
	enc_part.magic=htonl(enc_part.magic);
	if (send(sockfd, &enc_part.magic,sizeof(enc_part.magic) , 0) == -1){
				                   perror("send");}
	enc_part.nonce=htonl(enc_part.nonce);
	if (send(sockfd, &enc_part.nonce,sizeof(enc_part.nonce) , 0) == -1){
				                   perror("send");}
	enc_part.timestamp=htonl(enc_part.timestamp);
	if (send(sockfd, &enc_part.timestamp,sizeof(enc_part.timestamp) , 0) == -1){
				                   perror("send");}
	send_krb5_address(sockfd,*enc_part.r_address);
	send_krb5_address(sockfd,*enc_part.s_address);

}
void recv_krb5_cred_info(int sockfd,krb5_cred_info *cred_info){

	if (recv(sockfd, &cred_info->magic,sizeof(cred_info->magic) , 0) == -1){
					                   perror("recv");}
	cred_info->magic=ntohl(cred_info->magic);
	recv_krb5_keyblock(sockfd,cred_info->session);
	recv_principal_data(sockfd,cred_info->client);
	recv_principal_data(sockfd,cred_info->server);

	if (recv(sockfd, &cred_info->flags,sizeof(cred_info->flags) , 0) == -1){
						                perror("recv");}
	cred_info->flags=ntohl(cred_info->flags);
	recv_krb5_ticket_times(sockfd,&cred_info->times);
	recv_krb5_address(sockfd,cred_info->caddrs);
}
void recv_krb5_cred_enc_part(int sockfd,krb5_cred_enc_part *enc_part){

	if (recv(sockfd, &enc_part->magic,sizeof(enc_part->magic) , 0) == -1){
				                   perror("recv");}
	enc_part->magic=ntohl(enc_part->magic);

	if (recv(sockfd, &enc_part->nonce,sizeof(enc_part->nonce) , 0) == -1){
				                   perror("recv");}
	enc_part->nonce=ntohl(enc_part->nonce);

	if (recv(sockfd, &enc_part->timestamp,sizeof(enc_part->timestamp) , 0) == -1){
				                   perror("recv");}
	enc_part->timestamp=ntohl(enc_part->timestamp);
	recv_krb5_address(sockfd,enc_part->r_address);
	recv_krb5_address(sockfd,enc_part->s_address);

}




void send_krb5_cred(int sockfd,krb5_cred cred){
	cred.magic=htonl(cred.magic);
	if (send(sockfd, &cred.magic,sizeof(cred.magic) , 0) == -1){
			                   perror("send");}
	send_krb5_ticket(sockfd,*cred.tickets);
	send_krb5_enc_data(sockfd,cred.enc_part);
	send_krb5_cred_enc_part(sockfd,*cred.enc_part2);
}
void recv_krb5_cred(int sockfd,krb5_cred *cred){
	if (send(sockfd, &cred->magic,sizeof(cred->magic) , 0) == -1){
			                   perror("send");}
	cred->magic=ntohl(cred->magic);
	recv_krb5_ticket(sockfd,cred->tickets);
	recv_krb5_enc_data(sockfd,&cred->enc_part);
	recv_krb5_cred_enc_part(sockfd,cred->enc_part2);

}


