#include"nfv.h"
#include "../posix/ndpi_api.h" //iphdr
#include <pcap.h>

#include "fan.h"

int main() {
	/*initialization about mqueue*/
	char proname[] = "p12_nDPI";
	setcpu(P12_STARTING_CPU);

	struct mq_attr attr, attr_ctrl;
	attr.mq_maxmsg = MAXMSG;//maximum is 382.
	attr.mq_msgsize = 2048;
	attr.mq_flags = 0;

	attr_ctrl.mq_maxmsg = MAXMSGCTOP;
	attr_ctrl.mq_msgsize = 2048;
	attr_ctrl.mq_flags = 0;


	int flags = O_CREAT | O_RDWR;
	int flags_ctrl = O_CREAT | O_RDWR | O_NONBLOCK;
	mqd_t mqd_p9top12, mqd_p12top13;
	int mq_return = 0;
	char p9top12[] = "/p9top12";
	char p12top13[] = "/p12top13";

	mqd_p9top12 = mq_open(p9top12, flags, PERM, &attr);
	check_return(mqd_p9top12, p9top12, "mq_open");

	mqd_p12top13 = mq_open(p12top13, flags, PERM, &attr);
	check_return(mqd_p12top13, p12top13, "mq_open");


	/*control part*/
	mqd_t mqd_ctrltop12, mqd_p12toctrl;
	char ctrltop12[] = "/ctrltop12";
	char p12toctrl[] = "/p12toctrl";
	mqd_ctrltop12 = mq_open(ctrltop12, flags_ctrl, PERM, &attr_ctrl);
	check_return(mqd_ctrltop12, ctrltop12, "mq_open");
	mqd_p12toctrl = mq_open(p12toctrl, flags_ctrl, PERM, &attr_ctrl);
	check_return(mqd_p12toctrl, p12toctrl, "mq_open");


	char buffer[2048];
	struct ndpi_iphdr * iph;
	long long int i = 0;

	/*pthread*/
	struct transfer noti_tran;
	noti_tran.mqd_ctop = mqd_ctrltop12;
	noti_tran.mqd_ptoc = mqd_p12toctrl;
	//noti_tran.mqd_p[0] = mqd_p9top12;
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
		mq_return = mq_receive(mqd_p9top12, buffer, 2048, 0);
		if(mq_return == -1) {
			printf("%s:%s receive %lld times fails:%s, errno = %d \n", proname, p9top12, i, strerror(errno), errno);
			return -1;
		}

		iph = (struct ndpi_iphdr *) buffer;
/////////////////////////////////////////////////////////////////////////////
		u_int16_t proto = ProtoDtect(timestamp, mq_return, iph);

///////////////////////////////////////////////////////////////////////		
		if((i%SHOW_FREQUENCY == 0) || (i < SHOW_THRESHOLD)) {
			printf("%s:%s i = %lld, packet length = %d, pid = %d , working on CPU %d, proto : %d \n", proname, p9top12, i, mq_return, getpid(), getcpu(), proto);
		}
		if(i%CHECKQUEUE_FREQUENCY == 0) {
			checkqueue(mqd_p9top12, p9top12, &noti_tran);
		}
		
		mq_return = mq_send(mqd_p12top13, (char *) iph, mq_return, 0);
		if(mq_return == -1) {
			printf("%s:%s send %lld times fails:%s, errno = %d \n", proname, p12top13, i, strerror(errno), errno);
			return -1;
		}

	}
	
	printf("%s has transfered %lld packets. \n", proname, i);

	//p9top12
	mq_return = mq_close(mqd_p9top12);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(p9top12);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");

	//ctrltop12
	mq_return = mq_close(mqd_ctrltop12);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(ctrltop12);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");
	//p12toctrl
	mq_return = mq_close(mqd_p12toctrl);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(p12toctrl);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");


	exit(0);

}

