#include "nfv.h"
#include "fan.h"
#include "../posix/ndpi_api.h" //iphdr
#include <pcap.h>

int main() {
	/*initialization about mqueue*/
	char proname[] = "p25_IDS";
	setcpu(P25_STARTING_CPU);

	struct mq_attr attr, attr_ctrl;
	attr.mq_maxmsg = MAXMSG;//maximum is 382.
	attr.mq_msgsize = 2048;
	attr.mq_flags = 0;

	attr_ctrl.mq_maxmsg = MAXMSGCTOP;
	attr_ctrl.mq_msgsize = 2048;
	attr_ctrl.mq_flags = 0;


	int flags = O_CREAT | O_RDWR;
	int flags_ctrl = O_CREAT | O_RDWR | O_NONBLOCK;
	mqd_t mqd_p24top25, mqd_p25top28, mqd_p25top27;
	int mq_return = 0;
	char p24top25[] = "/p24top25";
	char p25top28[] = "/p25top28";
	char p25top27[] = "/p25top27";
	
	mqd_p24top25 = mq_open(p24top25, flags, PERM, &attr);
	check_return(mqd_p24top25, p24top25, "mq_open");

	mqd_p25top28 = mq_open(p25top28, flags, PERM, &attr);
	check_return(mqd_p24top25, p25top28, "mq_open");

	mqd_p25top27 = mq_open(p25top27, flags, PERM, &attr);
	check_return(mqd_p24top25, p25top27, "mq_open");


	/*control part*/
	mqd_t mqd_ctrltop25, mqd_p25toctrl;
	char ctrltop25[] = "/ctrltop25";
	char p25toctrl[] = "/p25toctrl";
	mqd_ctrltop25 = mq_open(ctrltop25, flags_ctrl, PERM, &attr_ctrl);
	check_return(mqd_ctrltop25, ctrltop25, "mq_open");
	mqd_p25toctrl = mq_open(p25toctrl, flags_ctrl, PERM, &attr_ctrl);
	check_return(mqd_p25toctrl, p25toctrl, "mq_open");


	char buffer[2048];
	struct ndpi_iphdr * iph;
	long long int i = 0;

	/*pthread*/
	struct transfer noti_tran;
	noti_tran.mqd_ctop = mqd_ctrltop25;
	noti_tran.mqd_ptoc = mqd_p25toctrl;
	//noti_tran.mqd_p[0] = mqd_p24top25;
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
	char fileDir[] = "./log_IDS25.txt";
	filp = fopen(fileDir,"w");

/////////////////////////////////////////////////////////////////////


	//int port = 0;

	for(i = 0;i < PACKETS*10;i += 2) {
		mq_return = mq_receive(mqd_p24top25, buffer, 2048, 0);
		if(mq_return == -1) {
			printf("%s:%s receive %lld times fails:%s, errno = %d \n", proname, p24top25, i, strerror(errno), errno);
			return -1;
		}
		iph = (struct ndpi_iphdr *) buffer;
		if((i%SHOW_FREQUENCY == 0) || (i < SHOW_THRESHOLD)) {
			printf("%s:%s i = %lld, packet length = %d, iph->daddr = %8X, pid = %d , working on CPU %d \n", proname, p24top25, i, mq_return, iph->daddr, getpid(), getcpu());
		}
		if(i%CHECKQUEUE_FREQUENCY == 0) {
			checkqueue(mqd_p24top25, p24top25, &noti_tran);
		}

		/////////////////////////////////////IDS
		IDS(timestamp, mq_return, iph, filp, i);
		mq_return = mq_send(mqd_p25top28, (char *) iph, mq_return, 0);
		if(mq_return == -1) {
			printf("%s:%s send %lld times fails:%s, errno = %d \n", proname, p25top28, i, strerror(errno), errno);
			return -1;
		}		

		mq_return = mq_receive(mqd_p24top25, buffer, 2048, 0);
		if(mq_return == -1) {
			printf("%s:%s receive %lld times fails:%s, errno = %d \n", proname, p24top25, i, strerror(errno), errno);
			return -1;
		}
		iph = (struct ndpi_iphdr *) buffer;
		if((i%SHOW_FREQUENCY == 0) || (i < SHOW_THRESHOLD)) {
			printf("%s:%s i = %lld, packet length = %d, iph->daddr = %8X, pid = %d , working on CPU %d \n", proname, p24top25, i, mq_return, iph->daddr, getpid(), getcpu());
		}
		if(i%CHECKQUEUE_FREQUENCY == 0) {
			checkqueue(mqd_p24top25, p24top25, &noti_tran);
		}
		
		/////////////////////////////////////IDS
		IDS(timestamp, mq_return, iph, filp, i);
		mq_return = mq_send(mqd_p25top27, (char *) iph, mq_return, 0);
		if(mq_return == -1) {
			printf("%s:%s send %lld times fails:%s, errno = %d \n", proname, p25top27, i, strerror(errno), errno);
			return -1;
		}	


		

	}
	printf("%s has transfered %lld packets. \n", proname, i);

	//p24top25
	mq_return = mq_close(mqd_p24top25);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(p24top25);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");

	//p25top28
	mq_return = mq_close(mqd_p25top28);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(p25top28);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");

	//p25top27
	mq_return = mq_close(mqd_p25top27);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(p25top27);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");

	//ctrltop25
	mq_return = mq_close(mqd_ctrltop25);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(ctrltop25);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");
	//p25toctrl
	mq_return = mq_close(mqd_p25toctrl);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(p25toctrl);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");


	exit(0);

}

