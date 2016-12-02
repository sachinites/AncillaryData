
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "../include/msghdr.h"
#include <linux/ip.h>

int main(int argc, char **argv){
        int igmp_sock_fd = 0, len = 0, 
		acillary_on = 1;

	char rec_buff[256];
	struct msghdr msg;
	struct cmsghdr *cmsg = NULL;
	igmp_hdr_t *igmphdr = NULL;
	struct sockaddr_in server_addr,
			   client_addr;

	if ((igmp_sock_fd = socket(AF_INET, SOCK_RAW, _IPPROTO_IGMP )) == -1)
	{

		printf("socket creation failed\n");
		exit(1);
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = 0;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	if (bind(igmp_sock_fd,(struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1)
        {
            printf("socket bind failed\n");
            exit(1);
        }
	/* using recvmsg() for Ancillary data*/
	memset(&msg, 0, sizeof(msg));
	initialise_msghdr(&msg, 
		          sizeof(rec_buff),     		 // size of buffer for recieving the socket payload
			  sizeof(struct in_pktinfo));            // size of buffer for recieving the ancillary data
	cmsg = CMSG_FIRSTHDR(&msg);
	/* Fill the Ancillary data for Recieving the incoming interface information*/
	cmsg->cmsg_level = IPPROTO_IP;
	cmsg->cmsg_len = CMSG_LEN(CMSG_ALIGN(sizeof(struct in_pktinfo))); // msg.msg_controllen
	/*struct in_pktinfo defined in linux/in.h*/
	//cmsg->cmsg_type = IP_PKTINFO; // set using socket option below
	
	/* What other data we can request from kernel is listed here : http://docs.oracle.com/cd/E19253-01/816-5173/6mbb8ae1j/index.html */
        /* Set the socket option/cmsg->cmsg_type to enable the kernel to fill the ancillary data requested*/
	setsockopt(igmp_sock_fd, IPPROTO_IP, IP_PKTINFO /* OR more flags here for more information*/, &acillary_on, sizeof(acillary_on)); 
	/* IP_PKTINFO and other defined in include/uapi/linux/in.h*/
	
READ:
	len = recvmsg(igmp_sock_fd, &msg, MSG_WAITALL );
	if(len < 0)
		printf("recvmsg error : %d", len);
	igmphdr = (igmp_hdr_t *)((char *)msg.msg_iov->iov_base + sizeof(struct iphdr)) ;
	printf("protocol = %-15s  pkt_type = %-15s  seqno = %d, bytes_recvd = %d\n",
                get_string(_IPPROTO_IGMP), get_string(igmphdr->type), igmphdr->seqno, len);
	dump_msghdr(&msg);
	goto READ;
	free_msghdr(&msg);
	return 0;
}
