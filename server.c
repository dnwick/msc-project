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
#include <net/netmap_user.h>
#include <net/netmap.h>
#include <libnetmap.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/queue.h>


#define VIRT_HDR_2	12	/* length of the extenede vnet-hdr */
#define VIRT_HDR_MAX	VIRT_HDR_2
#define MAX_BODYSIZE	65536


#define ITERATIONS (10 * 1024 )

#define	PKT(p, f, af)	\
    (p)->ipv4.f

const char *SERVER_IP = "192.168.1.1";

const long long FILE_BUFFER_SIZE = 60 * 1024 * 1024;

struct mmaped_data {
    char *data;
	int length;
    long int start_buf_index;     
    TAILQ_ENTRY(mmaped_data) entries;    
};

TAILQ_HEAD(, mmaped_data) tailq_head;

struct virt_header {
	uint8_t fields[VIRT_HDR_MAX];
};

struct pktMeta {
    int sequence_num;
	int req_type;
    int status;         
    int size;
};

enum req_type { FILE_META, FILE_CONTENT };


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
    int fileDesc;
    long int fileSize;
    long int readBytes;

};

static struct pkt* create_and_get_req_pkt(struct glob_meta_info *gmi){
    gmi->pkt_size = 1500;
    gmi->pkt_payload_size = 1400;
    gmi->src_ip.name = "192.168.1.103";
    gmi->src_ip.port0 = 1234;
	gmi->dst_ip.name = "192.168.1.105";
    gmi->dst_ip.port0 = 8000;
    gmi->dst_mac.name = "b4:a9:fc:78:63:b1";
    gmi->src_mac.name = "f0:de:f1:9a:16:ef";
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

const int STEPSIZE = 100;

static int mmapAndLoadQueue(struct glob_meta_info *gmi) {

    int fileDesc = gmi->fileDesc;
    long int bytesToRead;
   // printf("gmi->fileSize : %lu\n", gmi->fileSize);
   // printf("gmi->readBytes : %lu\n", gmi->readBytes);

    if (gmi->fileSize == gmi->readBytes) {
        //printf("Done mmaping the file \n");
        return 0;
    } else {
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

        mmapedData->data = mmap(NULL, bytesToRead, MAP_PRIVATE | MAP_POPULATE, MAP_PRIVATE, fileDesc, gmi->readBytes);
        if (mmapedData->data == MAP_FAILED) {
            perror("mmap");
            printf("Failed to map data \n");
            exit(1);
        }
        mmapedData->length = bytesToRead;
        mmapedData->start_buf_index = gmi->readBytes;
        TAILQ_INSERT_TAIL(&tailq_head, mmapedData, entries);
        gmi->readBytes += bytesToRead; 
        return 1;
    }   
}

 static void read_and_send()
{

    //char filePath[] = "/home/damith/workspace/files/client.c";
    //char filePath[] = "/home/damith/workspace/files/file1.txt";
    //char filePath[] = "/home/damith/workspace/files/file2.txt";
    //char filePath[] = "/home/damith/workspace/files/cpyFile9-400mb";
    char filePath[] = "/home/damith/workspace/files/cpyFile11-200mb";

    struct glob_meta_info *gmi = calloc(1, sizeof(*gmi));
    struct pkt* filePacket = create_and_get_req_pkt(gmi);
    gmi->file_name = filePath;

    int fileDesc = gmi->fileDesc = open(gmi->file_name, O_RDONLY);
    if (!fileDesc) {
        printf("Failed to read \n");
        exit(1);
    }

    struct stat sb;
    if(fstat(fileDesc, &sb) == -1) {
        printf("Failed to get file size \n");
        exit(1);
    }
    gmi->fileSize = sb.st_size;
    printf("File size is %ld\n", sb.st_size);

    struct netmap_if *nifp;
	struct netmap_ring *txring = NULL;

    gmi->nmd = nmport_prepare("netmap:enp0s25");

    if (gmi->nmd == NULL){
		printf("something is wrong ...");
    	printf("\n");
	}

	if (nmport_open_desc(gmi->nmd) < 0){
		printf("something is wrong ...");
    	printf("\n");
	} else{
		printf("Netmap opened ...");
    	printf("\n");
	}

	D("Wait %d secs for phy reset", 2);
	sleep(2);
	D("Ready to send data through netmap");
    
    double start_time = now();
    double elapsed_time;
    TAILQ_INIT(&tailq_head);
    int sequenceNum = 1;
    nifp = gmi->nmd->nifp;
    long int processedFileSize = 0;
    u_int wakeupLimit = 100;
    while(mmapAndLoadQueue(gmi)) {
        struct mmaped_data *mmapedData;
        long int bytesToRead = 0;
        TAILQ_FOREACH(mmapedData, &tailq_head, entries) {
            long int allowedPktReadBytes;
            bytesToRead = mmapedData->length;
            int pkt_payload_size = gmi->pkt_payload_size;
            uint64_t numOfPacketsToSend = bytesToRead / pkt_payload_size;
            processedFileSize += bytesToRead;
            
            if(bytesToRead % pkt_payload_size != 0) {
                numOfPacketsToSend++;
            }
	        uint64_t sent = 0;
            printf("numOfPacketsToSend %ld\n", numOfPacketsToSend);

        
            txring = NETMAP_TXRING(nifp, gmi->nmd->first_tx_ring);
            u_int n, head = txring->head;
            struct netmap_slot *slot = &txring->slot[head];
            n = nm_ring_space(txring);

            for (off_t w = 0; w < bytesToRead && sent < numOfPacketsToSend; w += pkt_payload_size) { //todo 

                u_int tosend = gmi->pkt_size;
                allowedPktReadBytes = pkt_payload_size;
                if (bytesToRead - w < pkt_payload_size) {
                    allowedPktReadBytes = bytesToRead - w;
                
                }
                filePacket->ipv4.pktMeta.sequence_num = sequenceNum;
                //printf("allowedPktReadBytes %lu \n", allowedPktReadBytes);
                slot = &txring->slot[head];
                char *p = NETMAP_BUF(txring, slot->buf_idx);
                slot->flags = 0;
                struct pkt* sendPkt = (struct pkt*)p;
                //sendPkt->vh = filePacket->vh;
                sendPkt->eh = filePacket->eh;
                sendPkt->ipv4.ip = filePacket->ipv4.ip;
                sendPkt->ipv4.pktMeta = filePacket->ipv4.pktMeta;
                sendPkt->ipv4.udp = filePacket->ipv4.udp;

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
                
                slot->len = tosend;
                
                sendPkt->ipv4.pktMeta.size = allowedPktReadBytes;
                memcpy(filePacket->ipv4.body, &mmapedData->data[w], allowedPktReadBytes);
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
                            // printf("ITS ZERO \n");
                            if (n < 1) {
                                txring->cur = txring->tail;
                            }
                        
                            do {
                                //printf("Doing again \n");
                                n = nm_ring_space(txring);
                                if (txring != NULL) {
                                    ioctl(gmi->nmd->fd, NIOCTXSYNC, NULL);
                                    //usleep(180);
                                }
                                if (n < wakeupLimit) {
                                   // printf("Still less\n");
                                    mmapAndLoadQueue(gmi);
                                }
                                //printf("Now n value : %d \n", n);
                                //printf("Still n value is : %d \n", nm_ring_space(txring)      
                            } while (n < wakeupLimit);
                        } 
                    }
                    //printf("Now n value : %d \n", n);
                
                    //printf("Now n value 623 : %d \n", n);
                    txring = NETMAP_TXRING(nifp, gmi->nmd->first_tx_ring);
                    head = txring->head;
                }   
            }
            if (munmap(mmapedData->data, bytesToRead) == -1) {
                printf("Failed to un-map the file \n");
                exit(1);
            }
            TAILQ_REMOVE(&tailq_head, mmapedData, entries);
            free(mmapedData);
        }
    }
    while (nm_tx_pending(txring)) {
        //printf("################################################# still pending \n");
        ioctl(gmi->nmd->fd, NIOCTXSYNC, NULL);
        usleep(1); /* wait 1 tick */
    }

    double end_time = now();
    elapsed_time = end_time - start_time;
    printf("It took %f seconds to read 25GB \n", elapsed_time);
    printf("last seq num is %d \n", sequenceNum);
}


int main()
{
    printf("initiating client ...");
    printf("\n");
    printf("Using server ip as %s", SERVER_IP);
    printf("\n");

    read_and_send();
    printf("Afterrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr");
    printf("\n");
}
/* end of file */