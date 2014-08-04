/*
 * sendKRBERROR.c
 *
 *  Created on: Feb 16, 2014
 *      Author: ivan
 */
#include "request.h"

void send_krb5_error(int new_fd,krb5_error err){
	    err.magic=htonl(err.magic);
		if (send(new_fd, &err.magic,sizeof(err.magic) , 0) == -1){
						                   perror("send");}
		err.ctime=htonl(err.ctime);
				if (send(new_fd, &err.ctime,sizeof(err.ctime) , 0) == -1){
					perror("send");}
		err.cusec=htonl(err.cusec);
				if (send(new_fd, &err.cusec,sizeof(err.cusec) , 0) == -1){
											perror("send");}
		err.susec=htonl(err.susec);
				if (send(new_fd, &err.susec,sizeof(err.susec) , 0) == -1){
											perror("send");}
		err.stime=htonl(err.stime);
				if (send(new_fd, &err.stime,sizeof(err.stime) , 0) == -1){
											perror("send");}
		send_principal_data(new_fd,*err.server);
		send_principal_data(new_fd,*err.client);
		send_krb5_data(new_fd,err.text);
		send_krb5_data(new_fd,err.e_data);
				}
void recv_krb5_error(int sockfd,krb5_error *err){

		//if (recv(sockfd, &err->magic,sizeof(err->magic) , 0) == -1){
		//				                   perror("recv");}
		//err->magic=htonl(err->magic);

				if (recv(sockfd, &err->ctime,sizeof(err->ctime) , 0) == -1){
					perror("recv");}
				err->ctime=htonl(err->ctime);

				if (recv(sockfd, &err->cusec,sizeof(err->cusec) , 0) == -1){
											perror("recv");}
				err->cusec=htonl(err->cusec);

				if (recv(sockfd, &err->susec,sizeof(err->susec) , 0) == -1){
											perror("recv");}
				err->susec=htonl(err->susec);

				if (recv(sockfd, &err->stime,sizeof(err->stime) , 0) == -1){
											perror("recv");}
				err->stime=htonl(err->stime);
		recv_principal_data(sockfd,err->server);
		recv_principal_data(sockfd,err->client);
		recv_krb5_data(sockfd,&err->text);
		recv_krb5_data(sockfd,&err->e_data);
				}
