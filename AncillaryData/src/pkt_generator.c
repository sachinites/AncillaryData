
#include <stdio.h>
#include <stdlib.h>
#include "../include/msghdr.h"
#include <sys/types.h> 
#include <sys/socket.h>
#include <pthread.h>
#include "../include/pkt_generator.h"
#include <memory.h>
#include <netdb.h>
#include <unistd.h> // for sleep

#define DEST_ADDR	"127.0.0.1"
#define NOT_REQ		 2000


static void*
_generate_pkt(void *arg){
	thread_arg_t *_arg = (thread_arg_t *)arg;
	unsigned int seqno = 0;
	int rc = 0;
	pthread_mutex_t igmp_sock_mutex, pim_sock_mutex;
	pthread_mutex_init(&igmp_sock_mutex, NULL);
	pthread_mutex_init(&pim_sock_mutex, NULL);

	while(1){
	switch(_arg->protocol){
	case _IPPROTO_IGMP:
	{
		igmp_hdr_t igmphdr;
		struct iovec iov;
		struct msghdr msg;
		const char ancillary_data_igmp1[4] = "AN1\0";
		const char ancillary_data_igmp2[4] = "AN2\0";
		struct cmsghdr *anc_data = NULL;
		
		memset(&igmphdr, 0 , IGMP_TP_HEADER_SIZE);
		igmphdr.type = _arg->pkt_type;
		igmphdr.seqno = seqno++;
		
		/* Wrap the transpot header into struct msghdr in order to send Ancillary data.
		   On recieving side, you should use recvmsg() to recv ancillary data. Simple recv()
		   would get you only socket payload (transport header) but not the ancillary data
		*/
		memset(&msg, 0, sizeof(struct msghdr));
	        msg.msg_name    = (void *)&_arg->dest_addr;       // ptr to struct sockaddr_in
		msg.msg_namelen = sizeof(struct sockaddr_in); // size of dest addr structure
		iov.iov_base    = (void *)&igmphdr;
		iov.iov_len     = IGMP_TP_HEADER_SIZE;
		msg.msg_iov     = &iov;
		msg.msg_iovlen  = 1;

		/* Adding Ancillary Data*/
#if 0
	{		
		/* cmsg_buffersize = Total size of Ancillary data inclusing headers
		 see diag 14.12 , page 492
		 cmsg_buffersize = space of two Ancillary data objects
		*/
		int cmsg_buffersize = CMSG_ALIGN(
					CMSG_SPACE(sizeof(ancillary_data_igmp1)) +
				      	CMSG_SPACE(sizeof(ancillary_data_igmp2))
				      );	   

		/* reserve total ancillary space*/      	
		msg.msg_control = calloc(1, cmsg_buffersize);
		msg.msg_controllen = cmsg_buffersize;

		/* Filling First Ancillary object*/
		anc_data = CMSG_FIRSTHDR(&msg);
		anc_data->cmsg_level = _IPPROTO_IGMP;
		anc_data->cmsg_type = IGMP_CMSG_DATA_TYPE;
		anc_data->cmsg_len = CMSG_LEN(sizeof(ancillary_data_igmp1));
		memcpy(CMSG_DATA(anc_data), ancillary_data_igmp1, sizeof(ancillary_data_igmp1));

		/* Filling Second Ancillary Data Object*/
		anc_data = CMSG_NXTHDR(&msg, anc_data);
		anc_data->cmsg_level = _IPPROTO_IGMP;
		anc_data->cmsg_type = IGMP_CMSG_DATA_TYPE;
		anc_data->cmsg_len = CMSG_LEN(sizeof(ancillary_data_igmp2));
		memcpy(CMSG_DATA(anc_data), ancillary_data_igmp2, sizeof(ancillary_data_igmp2));
	}
#endif

		//dump_msghdr(&msg);

		pthread_mutex_lock(&igmp_sock_mutex);
		rc = sendmsg(_arg->sockfd, &msg, 0);
		printf("protocol = %-20s pkt_type = %-15s seqno = %-7d bytes send = %d\n", 
			get_string(_arg->protocol), get_string(_arg->pkt_type), seqno, rc);
		pthread_mutex_unlock(&igmp_sock_mutex);
	}
	break;
	case _IPPROTO_PIM:
	{
		pim_hdr_t pimhdr;
		memset(&pimhdr, 0 , PIM_TP_HEADER_SIZE);
		pimhdr.type = _arg->pkt_type;
		pimhdr.seqno = seqno++;
		pthread_mutex_lock(&pim_sock_mutex);
		rc = sendto(_arg->sockfd, &pimhdr, PIM_TP_HEADER_SIZE, 0, 
			(struct sockaddr *)&_arg->dest_addr, sizeof(struct sockaddr));
		printf("protocol = %-20s pkt_type = %-15s seqno = %-7d bytes send = %d\n", 
			get_string(_arg->protocol), get_string(_arg->pkt_type), seqno, rc);
		pthread_mutex_unlock(&pim_sock_mutex);
	}
	break;
	}

	sleep(2);
	//break;
	}
	printf("%s(): Exiting ....\n", __FUNCTION__);
	free(arg);
	return NULL;
}

int 
generate_pkt(int sock, int protocol,  
		unsigned int type, 
		void *dest_addr){

	int rc = 0;		   
	pthread_t thread; 
	pthread_attr_t attr;	
	thread_arg_t *arg = NULL;
	dest_addr = (struct sockaddr_in *)dest_addr;

	if(!sock || !dest_addr){
		printf("Invalid argument : %s()", __FUNCTION__);
		return FAILURE;
	}

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	arg = calloc(1, sizeof(thread_arg_t)); // this memory should reside in heap

	arg->sockfd = sock;
	arg->protocol = protocol;
	arg->pkt_type = type;
	memcpy(&arg->dest_addr, dest_addr, sizeof(struct sockaddr_in));

	rc = pthread_create(&thread, &attr, _generate_pkt, (void *)arg);
	if (rc) {
		printf("ERROR; return code from pthread_create() is %d\n", rc);
	}
	return SUCCESS;
}


int
igmp_pim_pkt_generator(void){
	int igmp_sockfd, pim_sockfd;
	struct sockaddr_in dest;
	int halt;
	dest.sin_family = AF_INET;
	dest.sin_port = NOT_REQ;
	struct hostent *host = (struct hostent *)gethostbyname(DEST_ADDR);
	dest.sin_addr = *((struct in_addr *)host->h_addr);
	
	igmp_sockfd = socket(AF_INET, SOCK_RAW, _IPPROTO_IGMP);
	if(igmp_sockfd == FAILURE){
		printf("igmp socket creation failed\n");
		return FAILURE;
	}
	printf("igmp socket creation success\n");

	pim_sockfd = socket(AF_INET, SOCK_RAW, _IPPROTO_PIM);
	if(pim_sockfd == FAILURE){
		printf("pim socket creation failed\n");
		return FAILURE;
	}
	printf("pim socket creation success\n");
	
	generate_pkt(igmp_sockfd, _IPPROTO_IGMP, IGMP_REPORTS, (void *)&dest);
#if 0
	generate_pkt(pim_sockfd,  _IPPROTO_PIM, PIM_REGISTER, (void *)&dest);
	generate_pkt(igmp_sockfd, _IPPROTO_IGMP, IGMP_LEAVE,   (void *)&dest);		 	
	generate_pkt(igmp_sockfd, _IPPROTO_IGMP, IGMP_QUERY,   (void *)&dest);		 	
	generate_pkt(pim_sockfd,  _IPPROTO_PIM, PIM_HELLO,    (void *)&dest);
	generate_pkt(pim_sockfd,  _IPPROTO_PIM, PIM_JOIN,     (void *)&dest);
#endif
	scanf("%d", &halt);	
	return 0;
}

int
main(int argc, char **argv){
	igmp_pim_pkt_generator();
	return 0;
}
