#include"nfv.h"
#include "../posix/ndpi_api.h" //iphdr
#include <pcap.h>

#include "fan.h"

int main() {
	/*initialization about mqueue*/
	char proname[] = "p4_nDPI";
	setcpu(P4_STARTING_CPU);

	struct mq_attr attr, attr_ctrl;
	attr.mq_maxmsg = MAXMSG;//maximum is 382.
	attr.mq_msgsize = 2048;
	attr.mq_flags = 0;

	attr_ctrl.mq_maxmsg = MAXMSGCTOP;
	attr_ctrl.mq_msgsize = 2048;
	attr_ctrl.mq_flags = 0;


	int flags = O_CREAT | O_RDWR;
	int flags_ctrl = O_CREAT | O_RDWR | O_NONBLOCK;
	mqd_t mqd_p1top4, mqd_p4top5;
	int mq_return = 0;
	char p1top4[] = "/p1top4";
	char p4top5[] = "/p4top5";

	mqd_p1top4 = mq_open(p1top4, flags, PERM, &attr);
	check_return(mqd_p1top4, p1top4, "mq_open");

	mqd_p4top5 = mq_open(p4top5, flags, PERM, &attr);
	check_return(mqd_p4top5, p4top5, "mq_open");


	/*control part*/
	mqd_t mqd_ctrltop4, mqd_p4toctrl;
	char ctrltop4[] = "/ctrltop4";
	char p4toctrl[] = "/p4toctrl";
	mqd_ctrltop4 = mq_open(ctrltop4, flags_ctrl, PERM, &attr_ctrl);
	check_return(mqd_ctrltop4, ctrltop4, "mq_open");
	mqd_p4toctrl = mq_open(p4toctrl, flags_ctrl, PERM, &attr_ctrl);
	check_return(mqd_p4toctrl, p4toctrl, "mq_open");


	char buffer[2048];
	struct ndpi_iphdr * iph;
	long long int i = 0;

	/*pthread*/
	struct transfer noti_tran;
	noti_tran.mqd_ctop = mqd_ctrltop4;
	noti_tran.mqd_ptoc = mqd_p4toctrl;
	//noti_tran.mqd_p[0] = mqd_p1top4;
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
		mq_return = mq_receive(mqd_p1top4, buffer, 2048, 0);
		if(mq_return == -1) {
			printf("%s:%s receive %lld times fails:%s, errno = %d \n", proname, p1top4, i, strerror(errno), errno);
			return -1;
		}

		iph = (struct ndpi_iphdr *) buffer;
/////////////////////////////////////////////////////////////////////////////
		u_int16_t proto = ProtoDtect(timestamp, mq_return, iph);

///////////////////////////////////////////////////////////////////////		
		if((i%SHOW_FREQUENCY == 0) || (i < SHOW_THRESHOLD)) {
			printf("%s:%s i = %lld, packet length = %d, pid = %d , working on CPU %d, proto : %d \n", proname, p1top4, i, mq_return, getpid(), getcpu(), proto);
		}
		if(i%CHECKQUEUE_FREQUENCY == 0) {
			checkqueue(mqd_p1top4, p1top4, &noti_tran);
		}
		
		mq_return = mq_send(mqd_p4top5, (char *) iph, mq_return, 0);
		if(mq_return == -1) {
			printf("%s:%s send %lld times fails:%s, errno = %d \n", proname, p4top5, i, strerror(errno), errno);
			return -1;
		}

	}
	
	printf("%s has transfered %lld packets. \n", proname, i);

	//p1top4
	mq_return = mq_close(mqd_p1top4);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(p1top4);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");

	//ctrltop4
	mq_return = mq_close(mqd_ctrltop4);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(ctrltop4);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");
	//p4toctrl
	mq_return = mq_close(mqd_p4toctrl);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(p4toctrl);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");


	exit(0);

}

