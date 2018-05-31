#include "nfv.h"
#include "fan.h"
#include "../posix/ndpi_api.h" //iphdr
#include <pcap.h>

int main() {
	/*initialization about mqueue*/
	char proname[] = "p1_IDS";
	setcpu(P1_STARTING_CPU);

	struct mq_attr attr, attr_ctrl;
	attr.mq_maxmsg = MAXMSG;//maximum is 382.
	attr.mq_msgsize = 2048;
	attr.mq_flags = 0;

	attr_ctrl.mq_maxmsg = MAXMSGCTOP;
	attr_ctrl.mq_msgsize = 2048;
	attr_ctrl.mq_flags = 0;


	int flags = O_CREAT | O_RDWR;
	int flags_ctrl = O_CREAT | O_RDWR | O_NONBLOCK;
	mqd_t mqd_p0top1, mqd_p1top4, mqd_p1top3;
	int mq_return = 0;
	char p0top1[] = "/p0top1";
	char p1top4[] = "/p1top4";
	char p1top3[] = "/p1top3";
	
	mqd_p0top1 = mq_open(p0top1, flags, PERM, &attr);
	check_return(mqd_p0top1, p0top1, "mq_open");

	mqd_p1top4 = mq_open(p1top4, flags, PERM, &attr);
	check_return(mqd_p0top1, p1top4, "mq_open");

	mqd_p1top3 = mq_open(p1top3, flags, PERM, &attr);
	check_return(mqd_p0top1, p1top3, "mq_open");


	/*control part*/
	mqd_t mqd_ctrltop1, mqd_p1toctrl;
	char ctrltop1[] = "/ctrltop1";
	char p1toctrl[] = "/p1toctrl";
	mqd_ctrltop1 = mq_open(ctrltop1, flags_ctrl, PERM, &attr_ctrl);
	check_return(mqd_ctrltop1, ctrltop1, "mq_open");
	mqd_p1toctrl = mq_open(p1toctrl, flags_ctrl, PERM, &attr_ctrl);
	check_return(mqd_p1toctrl, p1toctrl, "mq_open");


	char buffer[2048];
	struct ndpi_iphdr * iph;
	long long int i = 0;

	/*pthread*/
	struct transfer noti_tran;
	noti_tran.mqd_ctop = mqd_ctrltop1;
	noti_tran.mqd_ptoc = mqd_p1toctrl;
	//noti_tran.mqd_p[0] = mqd_p0top1;
	noti_tran.qds = 1;
	noti_tran.i[0] = &i;
	notifysetup(&noti_tran);


//////////////////////////////////////////fw///////////////////////////
    setupDetection();    //ndpi setup
/////////////////////////////////////////////////////////////////////	

	

	writeAcl(15);
	struct timeval timestamp;
	gettimeofday( &timestamp, NULL);

	FILE *filp = NULL; 
	char fileDir[] = "./log_IDS1.txt";
	filp = fopen(fileDir,"w");

/////////////////////////////////////////////////////////////////////


	//int port = 0;

	for(i = 0;i < PACKETS*10;i += 2) {
		mq_return = mq_receive(mqd_p0top1, buffer, 2048, 0);
		if(mq_return == -1) {
			printf("%s:%s receive %lld times fails:%s, errno = %d \n", proname, p0top1, i, strerror(errno), errno);
			return -1;
		}
		iph = (struct ndpi_iphdr *) buffer;
		if((i%SHOW_FREQUENCY == 0) || (i < SHOW_THRESHOLD)) {
			printf("%s:%s i = %lld, packet length = %d, iph->daddr = %8X, pid = %d , working on CPU %d \n", proname, p0top1, i, mq_return, iph->daddr, getpid(), getcpu());
		}
		if(i%CHECKQUEUE_FREQUENCY == 0) {
			checkqueue(mqd_p0top1, p0top1, &noti_tran);
		}

		/////////////////////////////////////IDS
		IDS(timestamp, mq_return, iph, filp, i);
		mq_return = mq_send(mqd_p1top4, (char *) iph, mq_return, 0);
		if(mq_return == -1) {
			printf("%s:%s send %lld times fails:%s, errno = %d \n", proname, p1top4, i, strerror(errno), errno);
			return -1;
		}		

		mq_return = mq_receive(mqd_p0top1, buffer, 2048, 0);
		if(mq_return == -1) {
			printf("%s:%s receive %lld times fails:%s, errno = %d \n", proname, p0top1, i, strerror(errno), errno);
			return -1;
		}
		iph = (struct ndpi_iphdr *) buffer;
		if((i%SHOW_FREQUENCY == 0) || (i < SHOW_THRESHOLD)) {
			printf("%s:%s i = %lld, packet length = %d, iph->daddr = %8X, pid = %d , working on CPU %d \n", proname, p0top1, i, mq_return, iph->daddr, getpid(), getcpu());
		}
		if(i%CHECKQUEUE_FREQUENCY == 0) {
			checkqueue(mqd_p0top1, p0top1, &noti_tran);
		}
		
		/////////////////////////////////////IDS
		IDS(timestamp, mq_return, iph, filp, i);
		mq_return = mq_send(mqd_p1top3, (char *) iph, mq_return, 0);
		if(mq_return == -1) {
			printf("%s:%s send %lld times fails:%s, errno = %d \n", proname, p1top3, i, strerror(errno), errno);
			return -1;
		}	


		

	}
	printf("%s has transfered %lld packets. \n", proname, i);

	//p0top1
	mq_return = mq_close(mqd_p0top1);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(p0top1);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");

	//p1top4
	mq_return = mq_close(mqd_p1top4);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(p1top4);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");

	//p1top3
	mq_return = mq_close(mqd_p1top3);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(p1top3);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");

	//ctrltop1
	mq_return = mq_close(mqd_ctrltop1);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(ctrltop1);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");
	//p1toctrl
	mq_return = mq_close(mqd_p1toctrl);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(p1toctrl);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");


	exit(0);

}

