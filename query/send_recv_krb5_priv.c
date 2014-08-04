/*
 * send&recv_krb5_priv.c
 *
 *  Created on: Feb 17, 2014
 *      Author: ivan
 */

#include "request.h"
#include "request.h"
void recv_krb5_priv_enc_part(int sockfd,krb5_priv_enc_part *priv_part);
void send_krb5_priv_enc_part(int sockfd,krb5_priv_enc_part priv_part);
void send_krb5_priv(int sockfd,krb5_priv priv){
	priv.magic=htonl(priv.magic);
	if (send(sockfd, &priv.magic,sizeof(priv.magic) , 0) == -1){
			                   perror("send");}
	send_krb5_priv_enc_part(sockfd,priv.enc_part);

}
void recv_krb5_priv(int sockfd,krb5_priv *priv){
	if (send(sockfd, &priv->magic,sizeof(priv->magic) , 0) == -1){
			                   perror("send");}
	priv->magic=ntohl(priv->magic);
	recv_krb5_priv_enc_part(sockfd,&priv->enc_part);

}

void send_krb5_priv_enc_part(int sockfd,krb5_priv_enc_part priv_part){
	priv_part.magic=htonl(priv_part.magic);
		if (send(sockfd, &priv_part.magic,sizeof(priv_part.magic) , 0) == -1){
				                   perror("send");}
	send_krb5_data(sockfd,priv_part.user_data);
	priv_part.timestamp=htonl(priv_part.timestamp);
		if (send(sockfd, &priv_part.timestamp,sizeof(priv_part.timestamp) , 0) == -1){
					                perror("send");}
	priv_part.usec=htonl(priv_part.usec);
		if (send(sockfd, &priv_part.usec,sizeof(priv_part.usec) , 0) == -1){
							        perror("send");}
	priv_part.seq_number=htonl(priv_part.seq_number);
		if (send(sockfd, &priv_part.seq_number,sizeof(priv_part.seq_number) , 0) == -1){
									perror("send");}
	send_krb5_address(sockfd,*priv_part.r_address);
	send_krb5_address(sockfd,*priv_part.s_address);
}
void recv_krb5_priv_enc_part(int sockfd,krb5_priv_enc_part *priv_part){

		if (recv(sockfd, &priv_part->magic,sizeof(priv_part->magic) , 0) == -1){
				                   perror("recv");}
		priv_part->magic=htonl(priv_part->magic);
	recv_krb5_data(sockfd,&priv_part->user_data);

		if (recv(sockfd, &priv_part->timestamp,sizeof(priv_part->timestamp) , 0) == -1){
					                perror("recv");}
		priv_part->timestamp=htonl(priv_part->timestamp);

		if (recv(sockfd, &priv_part->usec,sizeof(priv_part->usec) , 0) == -1){
							        perror("recv");}
		priv_part->usec=htonl(priv_part->usec);

		if (recv(sockfd, &priv_part->seq_number,sizeof(priv_part->seq_number) , 0) == -1){
									perror("recv");}
		priv_part->seq_number=htonl(priv_part->seq_number);
		recv_krb5_address(sockfd,priv_part->r_address);
		recv_krb5_address(sockfd,priv_part->s_address);
}
