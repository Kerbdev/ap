/*
 * ap.c
 *
 *  Created on: Apr 11, 2014
 *      Author: ivan
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include "krb/krb.h"
#include "dynamic/dynamic.h"
#include "query/request.h"
#include "mess/mess.h"
#define BACKLOG 10
#define PORT "3491"  // порт, на который будут приходить соединения


void sigchld_handler(int s)
{
    while(waitpid(-1, NULL, WNOHANG) > 0);
}

// получаем адрес сокета, ipv4 или ipv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(void)
{char key_ap[]="Hell";
    int sockfd, new_fd;  // слушаем на sock_fd, новые соединения - на new_fd
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr; // информация об адресе клиента
    socklen_t sin_size;
    struct sigaction sa;
    int yes=1;
    char s[INET6_ADDRSTRLEN];
    int rv;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP
    if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }


    // цикл через все результаты, чтобы забиндиться на первом возможном
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
                sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    if (p == NULL)  {
        fprintf(stderr, "server: failed to bind\n");
        return 2;
    }

    freeaddrinfo(servinfo); // всё, что можно, с этой структурой мы сделали

    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

    sa.sa_handler = sigchld_handler; // обрабатываем мёртвые процессы
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    printf("server: waiting for connections...\n");

    while(1) {  // главный цикл accept()
        sin_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if (new_fd == -1) {
            perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family,
            get_in_addr((struct sockaddr *)&their_addr),
            s, sizeof s);
        printf("server: got connection from %s", s);

        if (!fork()) { // тут начинается дочерний процесс
        	close(sockfd);// дочернему процессу не нужен слушающий сокет

        	krb5_ap_req *ap_req=calloc(1,sizeof(krb5_ap_req));
        	malloc_krb5_ap_req(ap_req);
        	krb5_error *error=calloc(1,sizeof(krb5_error));
        	malloc_krb5_error(error);
        	recv_krb5_ap_req(new_fd,ap_req,error);
        	check_krb5_ap_req(ap_req,key_ap);
        	krb5_ap_rep *ap_rep=calloc(1,sizeof(krb5_ap_rep));
        		malloc_krb5_ap_rep(ap_rep);
        	krb5_ap_rep_imp(ap_rep,ap_req);
        	send_krb5_ap_rep(new_fd,*ap_rep);




        	close(new_fd);
        	        	exit(0);
        	        }
        	        close(new_fd);  // а этот сокет больше не нужен родителю
        	    }
        	    return 0;
        	}



