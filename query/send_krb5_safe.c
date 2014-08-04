/*
 * send_krb5_safe.c
 *
 *  Created on: Feb 17, 2014
 *      Author: ivan
 */
#include "request.h"
void send_krb5_safe(int sockfd,krb5_safe safe){
	safe.magic=htonl(safe.magic);
	if (send(sockfd, &safe.magic,sizeof(safe.magic) , 0) == -1){
			                   perror("send");}
	send_krb5_data(sockfd,safe.user_data);
	safe.timestamp=htonl(safe.timestamp);
	if (send(sockfd, &safe.timestamp,sizeof(safe.timestamp) , 0) == -1){
					                   perror("send");}
	safe.usec=htonl(safe.usec);
	if (send(sockfd, &safe.usec,sizeof(safe.usec) , 0) == -1){
					                   perror("send");}
	safe.seq_number=htonl(safe.seq_number);
	if (send(sockfd, &safe.seq_number,sizeof(safe.seq_number) , 0) == -1){
					                   perror("send");}
	send_krb5_address(sockfd,*safe.s_address);
	send_krb5_address(sockfd,*safe.r_address);
	send_krb5_checksum(sockfd,*safe.checksum);

}
