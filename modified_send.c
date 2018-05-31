#include "nfv.h"
#include "fan.h"

#define GTP_U_V1_PORT        2152

#define SHOW_CPU_TIME	1
#define CHECK_CPU_FREQUENCY		1000

struct ndpi_iphdr * packet_preprocess(const u_int16_t pktlen, const u_char * packet);



int main() {
	/*initialization about mqueue*/
	char proname[] = "send0";
	struct timeval begin;
	struct timeval end;
	
	
	setcpu(SEND0_CPU);

	printf("Now is in packet_sending!\n");

	struct mq_attr attr;
	attr.mq_maxmsg = MAXMSG;//maximum is 382.
	attr.mq_msgsize = 2048;
	attr.mq_flags = 0;
	int flags = O_CREAT | O_RDWR;
	//int flags_ctrl = O_CREAT | O_RDWR | O_NONBLOCK;

	mqd_t mqd_send0top0;
	int mq_return = 0;
	char send0top0[]="/send0top0";

	mqd_send0top0 = mq_open(send0top0, flags, PERM, &attr);
	check_return(mqd_send0top0, proname, "mq_open");

	struct timeval old_time = {0, 0};
	struct timeval now_time = {0, 0};

	system("cp ../posix/traffic_sample.pcap /tmp/traffic_sample0.pcap");   //转移到tmpfs
	char errbuf[100];  //error buf for pcapReader

	pcap_t *pfile = pcap_open_offline("/tmp/traffic_sample0.pcap", errbuf);  //head
	if (pfile == NULL) {
		printf("%s\n", errbuf);
		return -1;
	} 
	//printf("file opened\n");

	struct pcap_pkthdr *pkthdr = 0;
	const u_char *pktdata = 0;

	//pfile = pcap_open_offline("/tmp/traffic_sample.pcap", errbuf);  //head

	long long int i = 0;
	struct ndpi_iphdr * iph;

	int delay = SEND_SLEEP_TIME;

	for(i = 0; i < PACKETS; i++){//9715
		getPkt(pfile, &pkthdr, &pktdata);
		iph = packet_preprocess(pkthdr->caplen, pktdata);
		mq_return = mq_send(mqd_send0top0, (char *) iph, /*pkthdr->caplen*/40, 0);
		if(mq_return == -1) {
			printf("%s:send %lld times fails:%s, errno = %d \n", proname, i, strerror(errno), errno);
		}
		if(i % SEND_SHOW_FREQUENCY == 0 || i < SHOW_THRESHOLD) {
			printf("%s:%s packet_sending has sent %lld packets \n", proname, send0top0, i);
			if(i == START_TIME) {
				if(gettimeofday(&begin, NULL) != 0) {
					printf("gettimeofday for begin failed \n");
					return 1;
				}
			}
			if(i == END_TIME) {
				if(gettimeofday(&end, NULL) != 0) {
					printf("gettimeofday for end failed \n");
					return 1;
				}
			}
		}
		if(i % CHECK_CPU_FREQUENCY == 0) {
			gettimeofday(&now_time, 0);
			if(now_time.tv_usec - old_time.tv_usec + (now_time.tv_sec - old_time.tv_sec) * 1000000 >= SHOW_CPU_TIME * 1000000) {
				old_time = now_time;
				char catchcpu[] = "cat /sys/devices/system/cpu/online";
				FILE* cmd_catchcpu = popen(catchcpu, "r");
				pclose(cmd_catchcpu);
			}
		
		}
		if(i % DELAY_CHANGE_FREQ == 0){
			//delay = (int)gendelay(MAX_DELAY, MIN_DELAY);
			delay = (delay == 10)?100:10;
			printf("%s: delay: %d  *****\n", proname, delay);			
		}
		//let the packet_sending.o works more slowly.
		else if(i%SEND_SLEEP_FREQUENCY == 0) {
			//printf("packet_sending has sent %lld packets \n", i);
			usleep(delay);
		}
		/*int idle_i = 0;
		for(idle_i = 0;idle_i < 1000;idle_i++) {
			while(0);
			;
		}*/
	}

	printstar();
	
	
	long long int period = 0;
	period = ((long long int) (end.tv_sec - begin.tv_sec)) * 1000000 + end.tv_usec - begin.tv_usec;
	printf("begin.tv_sec = %ld, begin.tv_usec = %ld \n", begin.tv_sec, begin.tv_usec);
	printf("end.tv_sec = %ld, end.tv_usec = %ld \n", end.tv_sec, end.tv_usec);
	printf("period = %lld \n", period);
	printf("send0 has sent %lld packets and is closing.\n", i);
	mq_return = mq_close(mqd_send0top0);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(send0top0);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");

	func_quit(proname);
	exit(0);

}




/////////////////parser////////////////
struct ndpi_iphdr * packet_preprocess(const u_int16_t pktlen, const u_char * packet)
{
	//const struct ndpi_ethhdr *ethernet = (struct ndpi_ethhdr *) packet;
	struct ndpi_iphdr *iph = (struct ndpi_iphdr *) &packet[sizeof(struct ndpi_ethhdr)];
	//u_int64_t time;
	//static u_int64_t lasttime = 0;
	u_int16_t ip_offset;
	u_int16_t frag_off = 0;


	ip_offset = sizeof(struct ndpi_ethhdr);
	if(decode_tunnels && (iph->protocol == IPPROTO_UDP) && ((frag_off & 0x3FFF) == 0)) {
		u_short ip_len = ((u_short)iph->ihl * 4);
		struct ndpi_udphdr *udp = (struct ndpi_udphdr *)&packet[sizeof(struct ndpi_ethhdr)+ip_len];
		u_int16_t sport = ntohs(udp->source), dport = ntohs(udp->dest);

		if((sport == GTP_U_V1_PORT) || (dport == GTP_U_V1_PORT)) {
		/* Check if it's GTPv1 */
		u_int offset = sizeof(struct ndpi_ethhdr)+ip_len+sizeof(struct ndpi_udphdr);
		u_int8_t flags = packet[offset];
		u_int8_t message_type = packet[offset+1];

			if((((flags & 0xE0) >> 5) == 1 /* GTPv1 */) && (message_type == 0xFF /* T-PDU */)) {
				ip_offset = sizeof(struct ndpi_ethhdr)+ip_len+sizeof(struct ndpi_udphdr)+8 /* GTPv1 header len */;

				if(flags & 0x04) ip_offset += 1; /* next_ext_header is present */
				if(flags & 0x02) ip_offset += 4; /* sequence_number is present (it also includes next_ext_header and pdu_number) */
				if(flags & 0x01) ip_offset += 1; /* pdu_number is present */

				iph = (struct ndpi_iphdr *) &packet[ip_offset];

				if (iph->version != 4) {
					 printf("WARNING: not good !\n");
					//goto v4_warning;
				}
			}
		}

	}
	/////////////////////process
	return iph;
}




