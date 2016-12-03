/* Author : Abhishek Sagar*/

#include <stdlib.h>
#include <stdio.h>
#include "../include/msghdr.h"
#include <memory.h>
#include <arpa/inet.h>
#include <assert.h>

char*
get_string(unsigned int arg){
	switch(arg){
		case _IPPROTO_IGMP:
			return "_IPPROTO_IGMP"; 
		case _IPPROTO_PIM:
			return "_IPPROTO_PIM";
		case IGMP_REPORTS:
			return "IGMP_REPORTS";
		case IGMP_QUERY:
			return "IGMP_QUERY";
		case IGMP_LEAVE:
			return "IGMP_LEAVE";
		case PIM_HELLO:
			return "PIM_HELLO";
		case  PIM_JOIN:
			return "PIM_JOIN";
		case PIM_REGISTER:
			return "PIM_REGISTER";
		default:
			break;
	}
	return NULL;
}

void
dump_msghdr(struct msghdr *data){
	printf("\nDumping \"struct msghdr\"\n");
	unsigned int i = 0;
	struct iovec *iov = NULL;
	struct msghdr *msg = (struct msghdr *)data;
	struct cmsghdr *cmsg = NULL;
        struct sockaddr_in *dest = msg->msg_name;
	unsigned int dest_ip = dest->sin_addr.s_addr;
	char ipv4_str[16];
	inet_ntop(AF_INET, &dest_ip, ipv4_str, 16);
	printf("	dest ip address = %s\n", ipv4_str);
        printf("	No of IOV : %d\n", msg->msg_iovlen);
	for(i = 0; i < msg->msg_iovlen; i++){
		iov = msg->msg_iov + i;
		printf("		iov[%u].base = 0x%x, iov[%u].iov_len = %d\n", 
			i, (unsigned int)iov->iov_base, i, iov->iov_len);
	}	

	printf("	Ancillary Data : \n");
	printf("		msg->msg_control    = 0x%x\n",  (unsigned int)msg->msg_control);
	printf("                msg->msg_controllen = %d\n", msg->msg_controllen);

	print_ancillary_data(data);
	return;
}




void
initialise_msghdr(struct msghdr *msg, unsigned int tp_hdr_size, 
		  unsigned int cmsg_payload_size){
	struct iovec *iov = NULL;
	char *control_buf = NULL;
	if(!msg) assert(0);
	memset(msg, 0 , sizeof(struct msghdr));
	msg->msg_name       = calloc(1, sizeof(struct sockaddr));
        msg->msg_namelen    = sizeof(struct sockaddr);
	iov = calloc(1, sizeof(struct iovec));
	iov->iov_base = calloc(1, tp_hdr_size);
	iov->iov_len  = tp_hdr_size;
	msg->msg_iov  = iov;
	msg->msg_iovlen = 1;
	if(cmsg_payload_size)
		control_buf     = calloc(1, CMSG_SPACE(cmsg_payload_size));
	msg->msg_control    = control_buf;
	if(cmsg_payload_size)
		msg->msg_controllen = CMSG_SPACE(cmsg_payload_size);
	return;
}

void insert_cmsg_elements(struct msghdr *msg, unsigned int cmsg_payload_size[]){
	if(!msg) assert(0);
	struct cmsghdr *cmsg = NULL; 
	char *control_buf = NULL;
	int i = 0, total_ancillary_data = 0, size = 0;

	if(CMSG_FIRSTHDR(msg)) {
		printf("Already cmsg element present\n");
		return;
	}

	size = (int)(sizeof(cmsg_payload_size)/sizeof(unsigned int));
	for(i = 0; i < size; i++)
		total_ancillary_data += CMSG_SPACE(cmsg_payload_size[i]);
	
	control_buf     = calloc(1, total_ancillary_data);	
	msg->msg_control    = control_buf;
	msg->msg_controllen = total_ancillary_data;
	return;
}


char *
get_cmsg_level_as_string(unsigned int cmsg_level){
	switch(cmsg_level)
	{
		case IPPROTO_IP:
			return "IPPROTO_IP";
		default:
			return "UNKNOWN_TYPE";
	}
}


char *
get_cmsg_type_as_string(unsigned int cmsg_type){
	switch(cmsg_type)
	{
		case IP_PKTINFO:
			return "IP_PKTINFO";
		default:
			return "UNKNOWN_TYPE";
	}
}

void
print_ancillary_data(struct msghdr *msg){
	if(!msg) return;
	struct cmsghdr *cmsg = NULL;
	int i = 0;
	for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL;
                      cmsg = CMSG_NXTHDR(msg, cmsg)){
			
		printf("cmsg data %d : \n", i);
		printf("	cmsg->cmsg_level	= %s\n", 
					get_cmsg_level_as_string(cmsg->cmsg_level));
		printf("        cmsg->cmsg_len          = %d\n", cmsg->cmsg_len);

		printf("        cmsg->cmsg_type         = %s\n", 
					get_cmsg_type_as_string(cmsg->cmsg_type));

			switch(cmsg->cmsg_type)
			{
				case IP_PKTINFO:
				{
					struct in_pktinfo *pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);
					char ip_str[16];
					printf("	pktinfo->ipi_ifindex = %d\n", pktinfo->ipi_ifindex);
					inet_ntop(AF_INET, &pktinfo->ipi_spec_dst, ip_str, 16);
					printf("        pktinfo->ipi_spec_dst = %s\n", ip_str);
					memset(ip_str, 0 , 16);
					inet_ntop(AF_INET, &pktinfo->ipi_addr, ip_str, 16);
					printf("        pktinfo->ipi_addr      = %s\n", ip_str);
					break;
				}
			}
		i++;
		printf("\n");
	}

	return;
}


void
free_msghdr(struct msghdr *msg){
	if(!msg) assert(0);
	struct iovec *iov = NULL;
	iov = msg->msg_iov;
	free(msg->msg_name);
	free(iov->iov_base);
	free(iov);
	free(msg->msg_control);
	/* free the struct msghdr in the caller*/
	return;
}

void
refresh_msghdr(struct msghdr *msg, unsigned int tp_hdr_size){
	free_msghdr(msg);
	initialise_msghdr(msg, tp_hdr_size, 0);
	return;
}
