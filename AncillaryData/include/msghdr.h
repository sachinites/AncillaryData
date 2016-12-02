
#include <sys/socket.h>

#define SUCCESS	0
#define FAILURE -1


typedef enum{
	FALSE,
	TRUE
} bool_t;


typedef enum{
	_IPPROTO_IGMP = 140,
	_IPPROTO_PIM
} protocol;

typedef enum{
	IGMP_REPORTS = 0,
	IGMP_QUERY,
	IGMP_LEAVE,
	PIM_HELLO,
	PIM_JOIN,
	PIM_REGISTER
} pkt_type;

typedef struct igmp_hdr{
	pkt_type type;
	unsigned int seqno;
} igmp_hdr_t;;


typedef enum{
	IGMP_CMSG_DATA_TYPE,
	PIM_CMSG_DATA_TYPE
} cmsg_data_type_t;

#define IGMP_TP_HEADER_SIZE	(sizeof(igmp_hdr_t))

typedef struct pim_hdr{
	pkt_type type;
	unsigned int seqno;
} pim_hdr_t;;

#define PIM_TP_HEADER_SIZE	(sizeof(pim_hdr_t))

char*
get_string(unsigned int arg);

void
dump_msghdr(struct msghdr *data);

void
initialise_msghdr(struct msghdr *msg, unsigned int buff_size, unsigned int cmsg_payload_size);

void
free_msghdr(struct msghdr *msg);

void
refresh_msghdr(struct msghdr *msg, unsigned int tp_hdr_size);

void insert_cmsg_elements(struct msghdr *msg, unsigned int cmsg_payload_size[]);
void print_ancillary_data(struct msghdr *msg);
