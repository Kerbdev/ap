/*
 * recv_krb5_authenticator.c
 *
 *  Created on: Feb 17, 2014
 *      Author: ivan
 */
#include "request.h"
void recv_krb5_checksum(int sockfd,krb5_checksum *check){

	if (recv(sockfd, &check->magic,sizeof(check->magic) , 0) == -1){
			                   perror("recv");}
	check->magic=ntohl(check->magic);

	if (recv(sockfd, &check->checksum_type,sizeof(check->checksum_type) , 0) == -1){
			                   perror("recv");}
	check->checksum_type=ntohl(check->checksum_type);

	if (recv(sockfd, &check->length,sizeof(check->length) , 0) == -1){
									perror("recv");}
	check->length=ntohl(check->length);
	if(check->length){
	check->contents=(krb5_octet *) malloc(check->length);
	if (recv(sockfd, (char *) check->contents,check->length , 0) == -1){
										perror("recv");}}
}
void recv_krb5_authenticator(int sockfd,krb5_authenticator *auth){

	if (recv(sockfd, &auth->magic,sizeof(auth->magic) , 0) == -1){
			                   perror("recv");}
	auth->magic=ntohl(auth->magic);
	recv_principal_data(sockfd,auth->client);
	recv_krb5_checksum(sockfd,auth->checksum);

	if (recv(sockfd, &auth->cusec,sizeof(auth->cusec) , 0) == -1){
				               perror("recv");}
	auth->cusec=ntohl(auth->cusec);

	if (recv(sockfd, &auth->ctime,sizeof(auth->ctime) , 0) == -1){
				               perror("recv");}
	auth->ctime=ntohl(auth->ctime);
	recv_krb5_keyblock(sockfd,auth->subkey);

	if (recv(sockfd, &auth->seq_number,sizeof(auth->seq_number) , 0) == -1){
			                   perror("recv");}
	auth->seq_number=ntohl(auth->seq_number);
	recv_krb5_authdata(sockfd,auth->authorization_data);
}

