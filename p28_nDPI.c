#include"nfv.h"
#include "../posix/ndpi_api.h" //iphdr
#include <pcap.h>

#include "fan.h"

int main() {
	/*initialization about mqueue*/
	char proname[] = "p28_nDPI";
	setcpu(P28_STARTING_CPU);

	struct mq_attr attr, attr_ctrl;
	attr.mq_maxmsg = MAXMSG;//maximum is 382.
	attr.mq_msgsize = 2048;
	attr.mq_flags = 0;

	attr_ctrl.mq_maxmsg = MAXMSGCTOP;
	attr_ctrl.mq_msgsize = 2048;
	attr_ctrl.mq_flags = 0;


	int flags = O_CREAT | O_RDWR;
	int flags_ctrl = O_CREAT | O_RDWR | O_NONBLOCK;
	mqd_t mqd_p25top28, mqd_p28top29;
	int mq_return = 0;
	char p25top28[] = "/p25top28";
	char p28top29[] = "/p28top29";

	mqd_p25top28 = mq_open(p25top28, flags, PERM, &attr);
	check_return(mqd_p25top28, p25top28, "mq_open");

	mqd_p28top29 = mq_open(p28top29, flags, PERM, &attr);
	check_return(mqd_p28top29, p28top29, "mq_open");


	/*control part*/
	mqd_t mqd_ctrltop28, mqd_p28toctrl;
	char ctrltop28[] = "/ctrltop28";
	char p28toctrl[] = "/p28toctrl";
	mqd_ctrltop28 = mq_open(ctrltop28, flags_ctrl, PERM, &attr_ctrl);
	check_return(mqd_ctrltop28, ctrltop28, "mq_open");
	mqd_p28toctrl = mq_open(p28toctrl, flags_ctrl, PERM, &attr_ctrl);
	check_return(mqd_p28toctrl, p28toctrl, "mq_open");


	char buffer[2048];
	struct ndpi_iphdr * iph;
	long long int i = 0;

	/*pthread*/
	struct transfer noti_tran;
	noti_tran.mqd_ctop = mqd_ctrltop28;
	noti_tran.mqd_ptoc = mqd_p28toctrl;
	//noti_tran.mqd_p[0] = mqd_p25top28;
	noti_tran.qds = 1;
	noti_tran.i[0] = &i;
	notifysetup(&noti_tran);




	//int port = 0;
//////////////////////////////////////////////////////////////////////////
    setupDetection();    //ndpi setup
	struct timeval timestamp;
	gettimeofday( &timestamp, NULL);
//////////////////////////////////////////////////////////////////////


	for(i = 0;i < PACKETS*10;i++) {//PACKETS = 5000 now.
		mq_return = mq_receive(mqd_p25top28, buffer, 2048, 0);
		if(mq_return == -1) {
			printf("%s:%s receive %lld times fails:%s, errno = %d \n", proname, p25top28, i, strerror(errno), errno);
			return -1;
		}

		iph = (struct ndpi_iphdr *) buffer;
/////////////////////////////////////////////////////////////////////////////
		u_int16_t proto = ProtoDtect(timestamp, mq_return, iph);

///////////////////////////////////////////////////////////////////////		
		if((i%SHOW_FREQUENCY == 0) || (i < SHOW_THRESHOLD)) {
			printf("%s:%s i = %lld, packet length = %d, pid = %d , working on CPU %d, proto : %d \n", proname, p25top28, i, mq_return, getpid(), getcpu(), proto);
		}
		if(i%CHECKQUEUE_FREQUENCY == 0) {
			checkqueue(mqd_p25top28, p25top28, &noti_tran);
		}
		
		mq_return = mq_send(mqd_p28top29, (char *) iph, mq_return, 0);
		if(mq_return == -1) {
			printf("%s:%s send %lld times fails:%s, errno = %d \n", proname, p28top29, i, strerror(errno), errno);
			return -1;
		}

	}
	
	printf("%s has transfered %lld packets. \n", proname, i);

	//p25top28
	mq_return = mq_close(mqd_p25top28);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(p25top28);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");

	//ctrltop28
	mq_return = mq_close(mqd_ctrltop28);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(ctrltop28);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");
	//p28toctrl
	mq_return = mq_close(mqd_p28toctrl);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(p28toctrl);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");


	exit(0);

}

