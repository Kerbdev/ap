/*
 * recv_krb5_ap_req.c
 *
 *  Created on: Feb 17, 2014
 *      Author: ivan
 */
#include "request.h"
void recv_krb5_ap_req(int sockfd,krb5_ap_req *req,krb5_error *error){

	if (recv(sockfd, &req->magic,sizeof(req->magic) , 0) == -1){
			                   perror("recv");}
	req->magic=ntohl(req->magic);
	if (recv(sockfd, &req->msg_type,sizeof(req->msg_type) , 0) == -1){
			                   perror("recv2");}
		req->msg_type=ntohl(req->msg_type);
	if (recv(sockfd, &req->ap_options,sizeof(req->ap_options) , 0) == -1){
					                   perror("recv");}
	if(req->msg_type==KRB5_ERROR){
			recv_krb5_error(sockfd,error);
			error->magic=req->magic;}
	else{
	req->ap_options=ntohl(req->ap_options);
	recv_krb5_ticket(sockfd,req->ticket);
	recv_krb5_authenticator(sockfd,req->authenticator);}

}

