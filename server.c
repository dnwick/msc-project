#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/poll.h>
#include <sys/sysctl.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>
#include <string.h>
#include <stdbool.h>
#include <poll.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <net/netmap.h>
#include <libnetmap.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <pthread.h>
#include <semaphore.h>


#define VIRT_HDR_2	12	/* length of the extenede vnet-hdr */
#define VIRT_HDR_MAX	VIRT_HDR_2
#define MAX_BODYSIZE	65536

volatile int curGlobalStatus;
int numOfPacketsToResend;
int currentSeqNumber;
sem_t process_access;
sem_t global_status_access;



#define ITERATIONS (10 * 1024 )

const char *netmap_port_value = "netmap:enp1s0";

#define	PKT(p, f, af)	\
    (p)->ipv4.f

const char *SERVER_IP = "192.168.1.1";

const long long FILE_BUFFER_SIZE = 60 * 1024 * 1024;

int recievedPacketsToReplay;

struct mmaped_data {
    char *data;
	int length;
    long int start_buf_index;     
    TAILQ_ENTRY(mmaped_data) entries;    
};

struct seq_file_length_data{
    int sequence_num;
	int file_length; 
    long int cur_byte_read_location; 
    struct seq_file_length_data *next;    
    // TAILQ_ENTRY(seq_file_length_data) entries;    
};

struct resend_pkt_data {
    int sequence_num;
    TAILQ_ENTRY(resend_pkt_data) entries; 
};

struct hash_table {
    int size;
    struct seq_file_length_data **seq_file_size_list;
};

struct file_chunk_data {
    uint8_t data[MAX_BODYSIZE];
	int length;     
    TAILQ_ENTRY(file_chunk_data) entries;    
};

struct dropped_packet_data {
	int sequenceNumber;     
    TAILQ_ENTRY(dropped_packet_data) entries;    
};

TAILQ_HEAD(, mmaped_data) tailq_head_mmap;
TAILQ_HEAD(, file_chunk_data) tailq_head_file_chunk;
TAILQ_HEAD(, dropped_packet_data) tailq_dropped_packet_data;
TAILQ_HEAD(, seq_file_length_data) tailq_seq_file_length_data;
TAILQ_HEAD(, resend_pkt_data) tailq_head_resend_pkt_data;


struct virt_header {
	uint8_t fields[VIRT_HDR_MAX];
};

struct pktMeta {
    int sequence_num;
	int req_type;
    int status;         
    int size;
};

struct sequence {
    int sequence_num;
};

enum req_type { FILE_META, FILE_CONTENT, FILE_RESEND , FILE_SYNC, FILE_SYNC_ACK, FILE_SYNC_COMPLETE, FILE_MISSED_SEQ_SEND_COMPLETE, FILE_RESEND_COMPLETE, 
FILE_PROCESS};


struct pkt {
	//struct virt_header vh;
	struct ether_header eh;
	union {
		struct {
			struct ip ip;
            struct pktMeta pktMeta;
			struct udphdr udp;  
			uint8_t body[MAX_BODYSIZE];	/* hardwired */
		} ipv4;
	};
} __attribute__((__packed__));

struct ip_range {
	char *name;
	union {
		struct {
			uint32_t start, end; /* same as struct in_addr */
		} ipv4;
		struct {
			struct in6_addr start, end;
			uint8_t sgroup, egroup;
		} ipv6;
	};
	uint16_t port0, port1;
};

struct mac_range {
	char *name;
	struct ether_addr start, end;
};

struct arguments {
    struct nmport_d *nmd;
    struct glob_meta_info *gmi;
};

static uint16_t
wrapsum(uint32_t sum)
{
	sum = ~sum & 0xFFFF;
	return (htons(sum));
}

/* Compute the checksum of the given ip header. */
static uint32_t
checksum(const void *data, uint16_t len, uint32_t sum)
{
	const uint8_t *addr = (uint8_t const*)data;
	uint32_t i;

	/* Checksum all the pairs of bytes first... */
	for (i = 0; i < (len & ~1U); i += 2) {
		sum += (u_int16_t)ntohs(*((u_int16_t *)(addr + i)));
		if (sum > 0xFFFF)
			sum -= 0xFFFF;
	}
	/*
	 * If there's a single byte left over, checksum it, too.
	 * Network byte order is big-endian, so the remaining byte is
	 * the high byte.
	 */
	if (i < len) {
		sum += addr[i] << 8;
		if (sum > 0xFFFF)
			sum -= 0xFFFF;
	}
	return sum;
}

static int
extract_mac_range(struct mac_range *r)
{
	struct ether_addr *e;

	e = ether_aton(r->name);
	if (e == NULL) {
		D("invalid MAC address '%s'", r->name);
		return 1;
	}
	bcopy(e, &r->start, 6);
	bcopy(e, &r->end, 6);
	return 0;
}

double now() {
    struct timeval timevalue;
    gettimeofday(&timevalue, NULL);
    return timevalue.tv_sec + timevalue.tv_usec / 1000000.;
}



/*
 * Global attributes
 */
struct glob_meta_info {
	struct pkt pkt;
    int pkt_size;
    int pkt_payload_size;
    struct ip_range src_ip;
	struct ip_range dst_ip;
    struct mac_range dst_mac;
	struct mac_range src_mac;
    int virt_header;
    struct nmport_d *nmd;
    char *file_name;
    FILE *fileDesc;
    long int fileSize;
    long int readBytes;
    long int curMmappedSize;
    off_t curFileChunkIndex;
    char *curProcessingMmappedData;

};

static struct pkt* create_and_get_req_pkt(struct glob_meta_info *gmi){
    gmi->pkt_size = 1500;
    gmi->pkt_payload_size = 1400;
    gmi->src_ip.name = "192.168.1.105";
    gmi->src_ip.port0 = 1234;
	gmi->dst_ip.name = "192.168.1.103";
    gmi->dst_ip.port0 = 8000;
    gmi->dst_mac.name = "f0:de:f1:9a:16:ef";
    gmi->src_mac.name = "b4:a9:fc:78:63:b1";
    
    extract_mac_range(&gmi->src_mac);
    extract_mac_range(&gmi->dst_mac);
    uint16_t paylen;
    void *udp_ptr;
    struct udphdr udp;

    struct pkt *pktdata;
    pktdata = (struct pkt*)malloc(sizeof(struct pkt));
    struct ether_header *eh;
    struct ip ip;
    struct pktMeta *pktMeta;

    paylen = gmi->pkt_size - sizeof(*eh) - sizeof(ip) - sizeof(pktMeta);

    eh = &pktdata->eh;

    bcopy(&gmi->src_mac.start, eh->ether_shost, 6);
	bcopy(&gmi->dst_mac.start, eh->ether_dhost, 6);

    eh->ether_type = htons(ETHERTYPE_IP);
    udp_ptr = &pktdata->ipv4.udp;
    ip.ip_v = IPVERSION;
    ip.ip_hl = sizeof(ip) >> 2;
    ip.ip_id = 0;
    ip.ip_tos = IPTOS_LOWDELAY;
    ip.ip_len = htons(gmi->pkt_size - sizeof(*eh));
    ip.ip_id = 0;
    ip.ip_off = htons(IP_DF); /* Don't fragment */
    ip.ip_ttl = IPDEFTTL;
    ip.ip_p = IPPROTO_UDP;

    ip.ip_dst.s_addr = htonl(gmi->dst_ip.ipv4.start);
    ip.ip_src.s_addr = htonl(gmi->src_ip.ipv4.start);
    ip.ip_sum = wrapsum(checksum(&ip, sizeof(ip), 0));


    memcpy(&udp, udp_ptr, sizeof(udp));

    udp.uh_sport = htons(gmi->src_ip.port0);
	udp.uh_dport = htons(gmi->dst_ip.port0);
	udp.uh_ulen = htons(paylen);
    udp.uh_sum = wrapsum(
    checksum(&udp, sizeof(udp),	/* udp header */
    checksum(pktdata->ipv4.body,	/* udp payload */
    gmi->pkt_payload_size,
    checksum(&pktdata->ipv4.ip.ip_src, /* pseudo header */
    2 * sizeof(pktdata->ipv4.ip.ip_src),
    IPPROTO_UDP + (u_int32_t)ntohs(udp.uh_ulen)))));
    memcpy(&pktdata->ipv4.ip, &ip, sizeof(ip));

     //Construct pkt type portion
    pktMeta = &pktdata->ipv4.pktMeta;
    pktMeta->req_type = FILE_CONTENT;
    memcpy(udp_ptr, &udp, sizeof(udp));
    return pktdata;
}

struct hash_table *createHashTable(int size) {
    struct hash_table *tbl = (struct hash_table*)malloc(sizeof(struct hash_table));
    tbl->size = size;
    tbl->seq_file_size_list = (struct seq_file_length_data**)malloc(sizeof(struct seq_file_length_data*)*size);
    for(int i = 0; i<size;i++) {
        tbl->seq_file_size_list[i] = NULL;
    }
    return tbl;
}

int getHashCode(struct hash_table *tbl, int key) {
    if(key < 0) {
        return -(key % tbl->size);
    }
    return key % tbl->size;
}

struct seq_file_length_data *getObjUsingSeqFromHashMap(struct hash_table *tbl, int sequence_num) {
    int position = getHashCode(tbl, sequence_num);
    struct seq_file_length_data *list = tbl->seq_file_size_list[position];
    struct seq_file_length_data *temp = list;
    while (temp) {
        if (temp->sequence_num == sequence_num) {
            return temp;
        }
        temp = temp->next;
    }
    return NULL;
}

void insertValueToHashMap(struct hash_table *tbl, int sequence_num, int file_length, long int bytes_read_location) {
    int position = getHashCode(tbl, sequence_num);
    struct seq_file_length_data *list = tbl->seq_file_size_list[position];
    struct seq_file_length_data *seqFileLengthData;
    seqFileLengthData = malloc(sizeof(*seqFileLengthData));
    struct seq_file_length_data *temp = list;
    while (temp) {
        if (temp->sequence_num == sequence_num) {
            temp->file_length = file_length;
            temp->cur_byte_read_location = bytes_read_location;
            return;
        }
        temp = temp->next;
    }
    seqFileLengthData->sequence_num = sequence_num;
    seqFileLengthData->file_length = file_length;
    seqFileLengthData->cur_byte_read_location = bytes_read_location;
    seqFileLengthData->next = list;
    tbl->seq_file_size_list[position] = seqFileLengthData;
}

void create_seq_file_length_data(int fileBytes, int pktBytes, int chunkSize, struct hash_table *tbl) {

    int pkt_seq_num = 0;
    int bytes_read_location = 0;
    for (int w = 0; w < fileBytes; w += chunkSize) {

        int allowedChunckSize = chunkSize;
        if (fileBytes - w < chunkSize) {
            allowedChunckSize = fileBytes - w;
        }

        for (int j=0; j < allowedChunckSize; j += pktBytes) {
            int allowedPktReadBytes = pktBytes;
            if (allowedChunckSize - j < pktBytes) {
                allowedPktReadBytes = allowedChunckSize - j;
            }
            pkt_seq_num++;
            insertValueToHashMap(tbl, pkt_seq_num, allowedPktReadBytes, bytes_read_location);
            bytes_read_location += allowedPktReadBytes;
        }
    }
}

void *sendSyncAckPacket(void *vargp) {

    struct arguments *args = vargp;
    struct nmport_d *nmd = args->nmd;
    struct glob_meta_info *gmi = args->gmi;
    curGlobalStatus = FILE_SYNC_ACK;

    while (curGlobalStatus == FILE_SYNC_ACK) {
        struct netmap_if *nifp = nmd->nifp;
        struct netmap_ring *txring = NULL;
        txring = NETMAP_TXRING(nifp, nmd->first_tx_ring);
        u_int tx_head = txring->head;
        struct netmap_slot *tx_slot = &txring->slot[tx_head];
        struct pkt* tx_filePacket = create_and_get_req_pkt(gmi);
        tx_filePacket->ipv4.pktMeta.req_type = FILE_SYNC_ACK;

        tx_slot = &txring->slot[tx_head];
        char *tx_p = NETMAP_BUF(txring, tx_slot->buf_idx);
        
        tx_slot->flags = 0;
        struct pkt* tx_sendPkt = (struct pkt*)tx_p;

        tx_sendPkt->eh = tx_filePacket->eh;
        tx_sendPkt->ipv4.ip = tx_filePacket->ipv4.ip;
        tx_sendPkt->ipv4.pktMeta = tx_filePacket->ipv4.pktMeta;
        tx_sendPkt->ipv4.udp = tx_filePacket->ipv4.udp;

        tx_slot->len = gmi->pkt_size;
        txring->cur = tx_head;

        struct sequence *seq;
        seq = malloc(sizeof(*seq));
        seq->sequence_num = currentSeqNumber;
        memcpy(tx_sendPkt->ipv4.body, (char*)seq, sizeof(int));

        tx_head = nm_ring_next(txring, tx_head);
        tx_slot->flags |= NS_REPORT;
        txring->head = txring->cur = tx_head;
        tx_head = txring->head;

        if (txring != NULL) {
            ioctl(nmd->fd, NIOCTXSYNC, NULL);
            //usleep(180);
        }

        while (nm_tx_pending(txring)) {
            //printf("################################################# still pending \n");
            ioctl(nmd->fd, NIOCTXSYNC, NULL);
            usleep(1); /* wait 1 tick */
        }
        free(seq);
        usleep(3);
    }
    printf("FILE_SYNC_ACK Loop exited \n");
    return 0;
    
}

void *sendFileResendCompletePkt(void *vargp) {
    struct arguments *args = vargp;
    struct nmport_d *nmd = args->nmd;
    struct glob_meta_info *gmi = args->gmi;
    curGlobalStatus = FILE_RESEND_COMPLETE;
    while (curGlobalStatus == FILE_RESEND_COMPLETE) {
        struct netmap_if *nifp = nmd->nifp;
        struct netmap_ring *txring = NULL;
        txring = NETMAP_TXRING(nifp, nmd->first_tx_ring);
        u_int tx_head = txring->head;
        struct netmap_slot *tx_slot = &txring->slot[tx_head];
        struct pkt* tx_filePacket = create_and_get_req_pkt(gmi);
        tx_filePacket->ipv4.pktMeta.req_type = FILE_RESEND_COMPLETE;

        tx_slot = &txring->slot[tx_head];
        char *tx_p = NETMAP_BUF(txring, tx_slot->buf_idx);
        
        tx_slot->flags = 0;
        struct pkt* tx_sendPkt = (struct pkt*)tx_p;

        tx_sendPkt->eh = tx_filePacket->eh;
        tx_sendPkt->ipv4.ip = tx_filePacket->ipv4.ip;
        tx_sendPkt->ipv4.pktMeta = tx_filePacket->ipv4.pktMeta;
        tx_sendPkt->ipv4.udp = tx_filePacket->ipv4.udp;

        tx_slot->len = gmi->pkt_size;

        tx_head = nm_ring_next(txring, tx_head);
        tx_slot->flags |= NS_REPORT;
        txring->head = txring->cur = tx_head;
        tx_head = txring->head;

        if (txring != NULL) {
            ioctl(nmd->fd, NIOCTXSYNC, NULL);
            //usleep(180);
        }

        while (nm_tx_pending(txring)) {
            //printf("################################################# still pending \n");
            ioctl(nmd->fd, NIOCTXSYNC, NULL);
            usleep(1); /* wait 1 tick */
        }
        usleep(1);
    }
    printf("FILE_RESEND_COMPLETE Loop exited \n");
    return 0;
    
}

void sendMissedPackets(struct nmport_d *nmd, struct glob_meta_info *gmi, struct hash_table *tbl) {
    
    struct netmap_if *nifp = nmd->nifp;
    struct netmap_ring *txring = NULL;
    txring = NETMAP_TXRING(nifp, nmd->first_tx_ring);

    while (nm_tx_pending(txring)) {
        //printf("################################################# still pending \n");
        ioctl(nmd->fd, NIOCTXSYNC, NULL);
        usleep(1); /* wait 1 tick */
    }


    u_int tx_n, tx_head = txring->head;
    struct netmap_slot *tx_slot = &txring->slot[tx_head];
    tx_n = nm_ring_space(txring);
    struct pkt* tx_filePacket = create_and_get_req_pkt(gmi);
    tx_filePacket->ipv4.pktMeta.req_type = FILE_RESEND;

    struct resend_pkt_data *resendPktData;
    printf("Trying to send missed packets -- \n");

    TAILQ_FOREACH(resendPktData, &tailq_head_resend_pkt_data, entries) {

        struct seq_file_length_data* seqFileObj = getObjUsingSeqFromHashMap(tbl, resendPktData->sequence_num);
        
        if (NULL == seqFileObj) {
            printf("HASHMAP does not have the valie -- ");
        }

        tx_slot = &txring->slot[tx_head];
        char *tx_p = NETMAP_BUF(txring, tx_slot->buf_idx);

        tx_slot->flags = 0;
        struct pkt* tx_sendPkt = (struct pkt*)tx_p;

        tx_sendPkt->eh = tx_filePacket->eh;
        tx_sendPkt->ipv4.ip = tx_filePacket->ipv4.ip;
        tx_sendPkt->ipv4.pktMeta = tx_filePacket->ipv4.pktMeta;
        tx_sendPkt->ipv4.udp = tx_filePacket->ipv4.udp;
        tx_sendPkt->ipv4.pktMeta.sequence_num = resendPktData->sequence_num;
        //printf("status number : %d -- ", tx_sendPkt->ipv4.pktMeta.req_type);

        tx_slot->len = gmi->pkt_size;

        int fseeked = fseek(gmi->fileDesc, seqFileObj->cur_byte_read_location, SEEK_SET);
        if (fseeked != 0) {
            printf("fseek failed \n");
        }
       // printf("fseek success \n");
        size_t readCount = fread(tx_sendPkt->ipv4.body, seqFileObj->file_length, 1, gmi->fileDesc);
       // printf("freed success \n");
        (void)readCount;

        tx_head = nm_ring_next(txring, tx_head);
        tx_slot->flags |= NS_REPORT;
        txring->head = txring->cur = tx_head;
        tx_head = txring->head;

        tx_n--;

        TAILQ_REMOVE(&tailq_head_resend_pkt_data, resendPktData, entries);
        

        if (tx_n == 0) {
            tx_slot->flags |= NS_REPORT;
            txring->head = tx_head;
            txring->cur = tx_head;
            do {
                tx_n = nm_ring_space(txring);
                if (txring != NULL) {
                    ioctl(nmd->fd, NIOCTXSYNC, NULL);
                    //usleep(180);
                }     
            } while (tx_n == 0);
            
            txring = NETMAP_TXRING(nifp, nmd->first_tx_ring);
            tx_head = txring->head;
        }
    }

    while (nm_tx_pending(txring)) {
        //printf("################################################# still pending \n");
        ioctl(nmd->fd, NIOCTXSYNC, NULL);
        usleep(1); /* wait 1 tick */
    }

    if (TAILQ_EMPTY(&tailq_head_resend_pkt_data)) {
        printf("Sending send complete message \n");
        pthread_t flowcontrolMissedResendCompId;
        struct arguments args;
        args.nmd = nmd;
        args.gmi = gmi;
        int val = pthread_create(&flowcontrolMissedResendCompId, NULL, sendFileResendCompletePkt, (void *)&args);
        if (val == -1) {
            printf("Unable to create the thread");
        }
        (void)val;
        //sendFileResendCompletePkt(nmd, gmi);
    } else {
        printf("tailq is not empty-- \n");
    }

    
}


void *handle_packet_sync(void *vargp) {


    struct arguments *args = vargp;
    struct nmport_d *nmd = args->nmd;
    struct glob_meta_info *gmi = args->gmi;
    printf("gmi->file_name : %s \n", gmi->file_name);
    TAILQ_INIT(&tailq_head_resend_pkt_data);

    struct stat sb;
    if(fstat(fileno(gmi->fileDesc), &sb) == -1) {
        printf("Failed to get file size \n");
        exit(1);
    }


    int i;
    struct netmap_ring *rxring;
    
    //TAILQ_INIT(&tailq_seq_file_length_data);
    long int fileSize = sb.st_size;
    int pkt_payload_size = 1400;
    long int chunkSize = 60 * 1024 * 1024;
    uint64_t hashTblSize = fileSize / pkt_payload_size;

    if (fileSize % pkt_payload_size != 0) {
        hashTblSize++;
    }

    struct hash_table *tbl = createHashTable(hashTblSize);

    create_seq_file_length_data(fileSize, pkt_payload_size, chunkSize, tbl);

    struct pollfd pfd = { .fd = nmd->fd, .events = POLLIN };
    static bool stopReceiving = false;

    struct netmap_if *nifp = nmd->nifp;
    

    while (!stopReceiving) {

        i = poll(&pfd, 1, 1 * 1000);
        
        if (i < 0) {
            //printf("numOfPacketsToResend : %d \n", numOfPacketsToResend);
			D("poll error \n");
		} else if (i == 0) {
            RD(1, "waiting for initial packets, poll returns %d %d",
			i, pfd.revents);
        }

		if (pfd.revents & POLLERR) {
			D("poll err here");
			
		}

        uint64_t cur_space = 0;
        for (i = nmd->first_rx_ring; i <= nmd->last_rx_ring; i++) {
            int m;
			rxring = NETMAP_RXRING(nifp, i);
            if (nm_ring_empty(rxring)){
                printf("Recieve packets empty \n");
                continue;
            }

			m = rxring->head + rxring->num_slots - rxring->tail;
			if (m >= (int) rxring->num_slots){
                m -= rxring->num_slots;
            }
				
			cur_space += m;
            u_int head, rx, n;
            u_int limit = 512;

            head = rxring->head;
            n = nm_ring_space(rxring);
			
            if (n < limit){
                limit = n;
            }

            for (rx = 0; rx < limit; rx++) {
                struct netmap_slot *slot = &rxring->slot[head];
				char *p = NETMAP_BUF(rxring, slot->buf_idx);

				struct ether_header *ethh;
                struct ip *iph;
                struct udphdr *udph;
                struct pktMeta *pktMeta;

				ethh = (struct ether_header *)p;
                if (ethh->ether_type != htons(ETHERTYPE_IP)) {
                    /* Filter out non-IP traffic. */
                    //return 0;
                }
                iph = (struct ip *)(ethh + 1);
                
                if (iph->ip_p != IPPROTO_UDP) {
                    /* Filter out non-UDP traffic. */
                    //return 0;
                }
                pktMeta = (struct pktMeta *)(iph + 1);
                udph = (struct udphdr *)(pktMeta + 1);
                //printf("udph->uh_dport : %d \n", udph->uh_dport);

                if (udph->uh_dport == htons(8000)) {
                    char *restOfPayload = (char*)(udph + 1);
                    
                    //(void)restOfPayload;
                    if (pktMeta->req_type == FILE_SYNC) {
                        sem_wait(&global_status_access);
                        if (curGlobalStatus == -1) {
                            curGlobalStatus = FILE_SYNC;
                            sem_post(&global_status_access);
                            printf("received a sync packet \n");
                            sem_wait(&process_access);

                            pthread_t flowcontrolThreadId;
                            struct arguments args;
                            args.nmd = nmd;
                            args.gmi = gmi;
                            int val = pthread_create(&flowcontrolThreadId, NULL, sendSyncAckPacket, (void *)&args);
                            if (val == -1) {
                                printf("Unable to create the thread");
                            }
                            (void)val;
                            //pthread_join(flowcontrolThreadId, NULL);
                            //sendSyncAckPacket(nmd, gmi);
                            printf("sent sync ack message \n"); 
                        }
                        sem_post(&global_status_access);
                    } else if (pktMeta->req_type == FILE_META) {
                        
                        struct sequence *seq;
                        seq = (struct sequence*)restOfPayload;
                        numOfPacketsToResend++;

                        struct resend_pkt_data *resendPktData;
                        resendPktData = malloc(sizeof(*resendPktData));

                        if (resendPktData == NULL) {
                            perror("malloc failed");
                            exit(EXIT_FAILURE);
                        }
                        resendPktData->sequence_num = seq->sequence_num;
                        TAILQ_INSERT_TAIL(&tailq_head_resend_pkt_data, resendPktData, entries);
                    } else if (pktMeta->req_type == FILE_SYNC_COMPLETE){
                        sem_wait(&global_status_access);
                        if (curGlobalStatus == FILE_RESEND_COMPLETE || curGlobalStatus == FILE_SYNC_ACK) {
                            curGlobalStatus = FILE_SYNC_COMPLETE;
                            sem_post(&global_status_access);
                            printf("received a sync complete message \n");
                            sem_post(&process_access);
                        }
                        sem_post(&global_status_access);
                    } else if (pktMeta->req_type == FILE_MISSED_SEQ_SEND_COMPLETE){
                        sem_wait(&global_status_access);
                        if (curGlobalStatus == FILE_SYNC_ACK) {
                            curGlobalStatus = FILE_MISSED_SEQ_SEND_COMPLETE;
                            sem_post(&global_status_access);
                            printf("received a missed seq complete message \n");
                            sendMissedPackets(nmd, gmi, tbl);
                        }  
                        sem_post(&global_status_access);
                    }
                }
                head = nm_ring_next(rxring, head);
            }
            rxring->head = rxring->cur = head;
        }
    }
    return 0;
}

static void loadFileChunkQueue(long int bytesToRead, struct glob_meta_info *gmi) {
    long int allowedFileChunkReadBytes;

    if (gmi->curFileChunkIndex < bytesToRead) {
        //printf("we can chunk data \n");
        allowedFileChunkReadBytes = gmi->pkt_payload_size;
        if (bytesToRead - gmi->curFileChunkIndex < gmi->pkt_payload_size) {
            allowedFileChunkReadBytes = bytesToRead - gmi->curFileChunkIndex;
        }
        struct file_chunk_data *fileChunkData;
        fileChunkData = malloc(sizeof(*fileChunkData));
        if (fileChunkData == NULL) {
            perror("malloc failed");
            exit(EXIT_FAILURE);
        }
        //printf("going to mem cpy with %lu \n", gmi->curFileChunkIndex);
        //printf("&gmi->curProcessingMmappedData[gmi->curFileChunkIndex] : %s", &gmi->curProcessingMmappedData[gmi->curFileChunkIndex]);
        memcpy(fileChunkData->data, &gmi->curProcessingMmappedData[gmi->curFileChunkIndex], allowedFileChunkReadBytes);
        //printf("after mem cpy \n");
        fileChunkData->length = allowedFileChunkReadBytes;
        TAILQ_INSERT_TAIL(&tailq_head_file_chunk, fileChunkData, entries);
        gmi->curFileChunkIndex += allowedFileChunkReadBytes;   
    } 
}

static int mmapAndLoadQueue(struct glob_meta_info *gmi) {

    int fileDesc = fileno(gmi->fileDesc);
    long int bytesToRead;
    long int mmapLimit = 120 * 1024 * 1024;
   // printf("gmi->fileSize : %lu\n", gmi->fileSize);
   // printf("gmi->readBytes : %lu\n", gmi->readBytes);

    if (gmi->fileSize == gmi->readBytes) {
        //printf("Done mmaping the file \n");
        return 0;
    } else {
        if (gmi->curMmappedSize < mmapLimit) {
            bytesToRead = FILE_BUFFER_SIZE;
            if (gmi->fileSize - gmi->readBytes < FILE_BUFFER_SIZE){
                bytesToRead = gmi->fileSize - gmi->readBytes;
            }

            struct mmaped_data *mmapedData;
            mmapedData = malloc(sizeof(*mmapedData));
            if (mmapedData == NULL) {
                perror("malloc failed");
                exit(EXIT_FAILURE);
            }
            mmapedData->data = mmap(NULL, bytesToRead, PROT_READ, MAP_PRIVATE, fileDesc, gmi->readBytes);
            if (mmapedData->data == MAP_FAILED) {
                perror("mmap");
                printf("Failed to map data \n");
                exit(1);
            }
            mmapedData->length = bytesToRead;
            mmapedData->start_buf_index = gmi->readBytes;
            TAILQ_INSERT_TAIL(&tailq_head_mmap, mmapedData, entries);
            gmi->readBytes += bytesToRead; 
            gmi->curMmappedSize += bytesToRead;
        }   
        return 1;
    }   
}

 static void read_and_send(struct nmport_d *nmd, struct glob_meta_info *gmi)
{
    struct pkt* filePacket = create_and_get_req_pkt(gmi);

    int fileDesc = fileno(gmi->fileDesc);

    struct stat sb;
    if(fstat(fileDesc, &sb) == -1) {
        printf("Failed to get file size \n");
        exit(1);
    }
    gmi->fileSize = sb.st_size;
    printf("File size is %ld\n", sb.st_size);

    struct netmap_if *nifp;
	struct netmap_ring *txring = NULL;

    gmi->nmd = nmd;
    
    double start_time = now();
    double elapsed_time;
    TAILQ_INIT(&tailq_head_mmap);
    TAILQ_INIT(&tailq_head_file_chunk);
    
    int sequenceNum = 1;
    nifp = gmi->nmd->nifp;
    long int processedFileSize = 0;
    u_int wakeupLimit = 170;

    uint64_t allPacketCount = 0;
    
    while(mmapAndLoadQueue(gmi)) {
        struct mmaped_data *mmapedData;
        long int bytesToRead = 0;

        TAILQ_FOREACH(mmapedData, &tailq_head_mmap, entries) {

            int allowedPktReadBytes;
            bytesToRead = mmapedData->length;
            int pkt_payload_size = gmi->pkt_payload_size;
            uint64_t numOfPacketsToSend = bytesToRead / pkt_payload_size;
            processedFileSize += bytesToRead;
            
            if(bytesToRead % pkt_payload_size != 0) {
                numOfPacketsToSend++;
            }
	        uint64_t sent = 0;
            printf("numOfPacketsToSend %ld\n", numOfPacketsToSend);
            allPacketCount += numOfPacketsToSend;
            
        
            txring = NETMAP_TXRING(nifp, gmi->nmd->first_tx_ring);
            u_int n, head = txring->head;
            struct netmap_slot *slot = &txring->slot[head];
            n = nm_ring_space(txring);
            gmi->curProcessingMmappedData = mmapedData->data;
            long int actualMemCpyCount = 0;
            long int fileChunkCpyCount = 0;

            for (off_t w = 0; w < bytesToRead && sent < numOfPacketsToSend; w += pkt_payload_size) { //todo
                sem_wait(&process_access);
                if (curGlobalStatus == FILE_SYNC_COMPLETE) {
                    printf("Process resumed after sync !!!!! \n");
                    n = nm_ring_space(txring);
                }
                
                u_int tosend = gmi->pkt_size;
                allowedPktReadBytes = pkt_payload_size;
                if (bytesToRead - w < pkt_payload_size) {
                    allowedPktReadBytes = bytesToRead - w;
                
                }

                slot = &txring->slot[head];
                char *p = NETMAP_BUF(txring, slot->buf_idx);
                slot->flags = 0;
                struct pkt* sendPkt = (struct pkt*)p;
                sendPkt->eh = filePacket->eh;
                sendPkt->ipv4.ip = filePacket->ipv4.ip;
                sendPkt->ipv4.pktMeta = filePacket->ipv4.pktMeta;
                sendPkt->ipv4.udp = filePacket->ipv4.udp;
                sendPkt->ipv4.pktMeta.sequence_num = sequenceNum;

                
                currentSeqNumber = sequenceNum;

                if (sequenceNum == 1 && w == 0) {
                    sendPkt->ipv4.pktMeta.status = 1;
                    printf("Startingggggggg \n");
                } else {
                    sendPkt->ipv4.pktMeta.status = 2;
                }

                if (sent == numOfPacketsToSend - 1 && processedFileSize == gmi->fileSize ) {
                    printf("Enddddddddddd \n");
                    sendPkt->ipv4.pktMeta.status = 3;
                }
                curGlobalStatus = -1; 
                
                slot->len = tosend;
                
                sendPkt->ipv4.pktMeta.size = allowedPktReadBytes;
                struct file_chunk_data *fileChunk = TAILQ_FIRST(&tailq_head_file_chunk);
                //memset(filePacket->ipv4.body, 0x00, sizeof(filePacket->ipv4.body));
                if (w != 0 && NULL != fileChunk) {
                    //printf("From additional chinking \n");
                    memcpy(sendPkt->ipv4.body, fileChunk->data, fileChunk->length);
                    fileChunkCpyCount++;
                    TAILQ_REMOVE(&tailq_head_file_chunk, fileChunk, entries);
                    free(fileChunk);
                } else {
                    memcpy(sendPkt->ipv4.body, &gmi->curProcessingMmappedData[w], allowedPktReadBytes);
                    actualMemCpyCount++;
                }
                //printf("################################################# filePacket->ipv4.body %s \n", filePacket->ipv4.body);
                
                head = nm_ring_next(txring, head);
                txring->cur = head;
                if (sent == numOfPacketsToSend - 1) {
                    if (txring != NULL) {
                        //printf("################################################# flushing the ring \n");
                        ioctl(gmi->nmd->fd, NIOCTXSYNC, NULL);
                    }
                
                    //printf("Now n 566 value : %d \n", nm_ring_space(txring));
                    slot->flags |= NS_REPORT;
                    txring->head = txring->cur = head;
                    n = nm_ring_space(txring);
                    // printf("Now n 570 value : %d \n", n);
                    txring = NETMAP_TXRING(nifp, gmi->nmd->first_tx_ring);
                    head = txring->head;

                }
                n--;
                sent++;
                sequenceNum++;

                if ((sent < numOfPacketsToSend && n == 0)) {
                    slot->flags |= NS_REPORT;
                    txring->head = head;
                    txring->cur = head;
                    

                    if (sent < numOfPacketsToSend - 1) {
                        if (n == 0) {
                             //printf("ITS ZERO \n");
                            if (n < 1) {
                                txring->cur = txring->tail;
                            }
                            //printf("w value is : %lu \n", w);
                            gmi->curFileChunkIndex = w + allowedPktReadBytes;
                            //float percentage;
                            do {
                                //printf("Doing again \n");
                                n = nm_ring_space(txring);
                                if (txring != NULL) {
                                    ioctl(gmi->nmd->fd, NIOCTXSYNC, NULL);
                                    //usleep(180);
                                }
                                if (n < wakeupLimit) {
                                    //printf("Still less\n");
                                    mmapAndLoadQueue(gmi);
                                    loadFileChunkQueue(bytesToRead, gmi);

                                }

                                //percentage = ((bytesToRead - gmi->curFileChunkIndex) / bytesToRead) * 100 ;
                                //printf("Now percentage value : %f \n", percentage);
                                //printf("Still n value is : %d \n", nm_ring_space(txring)      
                            } while (n < wakeupLimit);
                        } 
                    }
                    //printf("Now n value : %d \n", n);
                
                    //printf("Now n value 623 : %d \n", n);
                    txring = NETMAP_TXRING(nifp, gmi->nmd->first_tx_ring);
                    head = txring->head;
                }   
                sem_post(&process_access);
            }
            //sync_commit(mmapedData, sequenceNum);
            //printf("Actual memcpy count is :  %lu \n", actualMemCpyCount);
            //printf("File chunk memcpy count is :  %lu \n", fileChunkCpyCount);
            if (munmap(mmapedData->data, bytesToRead) == -1) {
                printf("Failed to un-map the file \n");
                exit(1);
            }
            gmi->curMmappedSize -= bytesToRead;
            TAILQ_REMOVE(&tailq_head_mmap, mmapedData, entries);
            free(mmapedData);
        }
    }
    while (nm_tx_pending(txring)) {
        //printf("################################################# still pending \n");
        ioctl(gmi->nmd->fd, NIOCTXSYNC, NULL);
        usleep(1); /* wait 1 tick */
    }
   // close(fileDesc);
    

    double end_time = now();
    elapsed_time = end_time - start_time;
    printf("It took %f seconds to read 25GB \n", elapsed_time);
    printf("last seq num is %d \n", sequenceNum);
    printf("Num of all packets sent %lu \n", allPacketCount);
}


int main()
{
    printf("initiating client ...");
    printf("\n");
    printf("Using server ip as %s", SERVER_IP);
    printf("\n");

    struct nmport_d *nmd = nmport_prepare(netmap_port_value);
    sem_init(&process_access, 0 , 1);
    sem_init(&global_status_access, 0 , 1);

    if (nmd == NULL){
		printf("something is wrong ...");
    	printf("\n");
	}

	if (nmport_open_desc(nmd) < 0){
		printf("something is wrong ...");
    	printf("\n");
	} else{
		printf("Netmap opened ...");
    	printf("\n");
	}

	D("Wait %d secs for phy reset", 2);
	sleep(2);
	D("Ready to send data through netmap");


    //char filePath[] = "/home/damith/workspace/files/client.c";
    //char filePath[] = "/home/damith/workspace/files/file1.txt";
    //char filePath[] = "/home/damith/workspace/files/file2.txt";
    //char filePath[] = "/home/damith/workspace/files/cpyFile9-400mb";
   // char filePath[] = "/home/damith/finalProj/fileRepo/cpyFile11-200mb-out";
    //char filePath[] = "/home/damith/finalProj/fileRepo/netmapClientPsudoCode";
   // char filePath[] = "/home/damith/finalProj/fileRepo/netmapClientPsudoCode-4kb";
   //char filePath[] = "/home/damith/finalProj/fileRepo/output9.txt";
   //char filePath[] = "/home/damith/finalProj/fileRepo/cpyFile14-400mb";
   
   
    
    //char filePath[] = "/home/damith/finalProj/fileRepo/file1.txt-out";
    char filePath[] = "/home/damith/finalProj/fileRepo/cpyFile13-1gb.txt";
    //char filePath[] = "/home/damith/finalProj/fileRepo/file1.txt-out";

    struct glob_meta_info *gmi = calloc(1, sizeof(*gmi));
    FILE *file_write_desc = fopen(filePath, "r+");

    if (file_write_desc == NULL) {
        printf("Failed to open file \n");
        perror("fopen()");
        exit(1);
    }

    struct stat buf;
    fstat(fileno(file_write_desc), &buf);
    gmi->fileSize = buf.st_size;
    gmi->fileDesc = file_write_desc;

    pthread_t thread_id;
    numOfPacketsToResend = 0;
    struct arguments args;
    args.nmd = nmd;
    args.gmi = gmi;

    int val = pthread_create(&thread_id, NULL, handle_packet_sync, (void *)&args);
    if (val == -1) {
       printf("Unable to create the thread");
    }
    (void)val;
    read_and_send(nmd, gmi);
    pthread_join(thread_id, NULL);
}
/* end of file */