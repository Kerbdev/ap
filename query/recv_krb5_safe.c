/*
 * recv_krb5_safe.c
 *
 *  Created on: Feb 17, 2014
 *      Author: ivan
 */
#include "request.h"
void send_krb5_checksum(int sockfd,krb5_checksum check){

	if (send(sockfd, &check.magic,sizeof(check.magic) , 0) == -1){
			                   perror("send");}
	check.magic=htonl(check.magic);

	if (send(sockfd, &check.checksum_type,sizeof(check.checksum_type) , 0) == -1){
			                   perror("send");}
	check.checksum_type=htonl(check.checksum_type);
	check.length=0;
			if(check.contents)
			check.length=strlen((char *) check.contents)+1;
			int len=check.length;
	check.length=htonl(check.length);
	if (send(sockfd, &check.length,sizeof(check.length) , 0) == -1){
									perror("send");}

	if(len)
	if (send(sockfd, (char *) check.contents,check.length , 0) == -1){
										perror("send");}
}
void recv_krb5_safe(int sockfd,krb5_safe *safe){

	if (recv(sockfd, &safe->magic,sizeof(safe->magic) , 0) == -1){
			                   perror("recv");}
	safe->magic=ntohl(safe->magic);
	recv_krb5_data(sockfd,&safe->user_data);

	if (recv(sockfd, &safe->timestamp,sizeof(safe->timestamp) , 0) == -1){
					                   perror("recv");}
	safe->timestamp=ntohl(safe->timestamp);

	if (recv(sockfd, &safe->usec,sizeof(safe->usec) , 0) == -1){
					                   perror("recv");}
	safe->usec=ntohl(safe->usec);

	if (recv(sockfd, &safe->seq_number,sizeof(safe->seq_number) , 0) == -1){
					                   perror("recv");}
	safe->seq_number=ntohl(safe->seq_number);
	recv_krb5_address(sockfd,safe->s_address);
	recv_krb5_address(sockfd,safe->r_address);
	recv_krb5_checksum(sockfd,safe->checksum);

}

