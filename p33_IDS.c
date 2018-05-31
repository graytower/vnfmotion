#include "nfv.h"
#include "fan.h"
#include "../posix/ndpi_api.h" //iphdr
#include <pcap.h>

int main() {
	/*initialization about mqueue*/
	char proname[] = "p33_IDS";
	setcpu(P33_STARTING_CPU);

	struct mq_attr attr, attr_ctrl;
	attr.mq_maxmsg = MAXMSG;//maximum is 382.
	attr.mq_msgsize = 2048;
	attr.mq_flags = 0;

	attr_ctrl.mq_maxmsg = MAXMSGCTOP;
	attr_ctrl.mq_msgsize = 2048;
	attr_ctrl.mq_flags = 0;


	int flags = O_CREAT | O_RDWR;
	int flags_ctrl = O_CREAT | O_RDWR | O_NONBLOCK;
	mqd_t mqd_p32top33, mqd_p33top36, mqd_p33top35;
	int mq_return = 0;
	char p32top33[] = "/p32top33";
	char p33top36[] = "/p33top36";
	char p33top35[] = "/p33top35";
	
	mqd_p32top33 = mq_open(p32top33, flags, PERM, &attr);
	check_return(mqd_p32top33, p32top33, "mq_open");

	mqd_p33top36 = mq_open(p33top36, flags, PERM, &attr);
	check_return(mqd_p32top33, p33top36, "mq_open");

	mqd_p33top35 = mq_open(p33top35, flags, PERM, &attr);
	check_return(mqd_p32top33, p33top35, "mq_open");


	/*control part*/
	mqd_t mqd_ctrltop33, mqd_p33toctrl;
	char ctrltop33[] = "/ctrltop33";
	char p33toctrl[] = "/p33toctrl";
	mqd_ctrltop33 = mq_open(ctrltop33, flags_ctrl, PERM, &attr_ctrl);
	check_return(mqd_ctrltop33, ctrltop33, "mq_open");
	mqd_p33toctrl = mq_open(p33toctrl, flags_ctrl, PERM, &attr_ctrl);
	check_return(mqd_p33toctrl, p33toctrl, "mq_open");


	char buffer[2048];
	struct ndpi_iphdr * iph;
	long long int i = 0;

	/*pthread*/
	struct transfer noti_tran;
	noti_tran.mqd_ctop = mqd_ctrltop33;
	noti_tran.mqd_ptoc = mqd_p33toctrl;
	//noti_tran.mqd_p[0] = mqd_p32top33;
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
	char fileDir[] = "./log_IDS33.txt";
	filp = fopen(fileDir,"w");

/////////////////////////////////////////////////////////////////////


	//int port = 0;

	for(i = 0;i < PACKETS*10;i += 2) {
		mq_return = mq_receive(mqd_p32top33, buffer, 2048, 0);
		if(mq_return == -1) {
			printf("%s:%s receive %lld times fails:%s, errno = %d \n", proname, p32top33, i, strerror(errno), errno);
			return -1;
		}
		iph = (struct ndpi_iphdr *) buffer;
		if((i%SHOW_FREQUENCY == 0) || (i < SHOW_THRESHOLD)) {
			printf("%s:%s i = %lld, packet length = %d, iph->daddr = %8X, pid = %d , working on CPU %d \n", proname, p32top33, i, mq_return, iph->daddr, getpid(), getcpu());
		}
		if(i%CHECKQUEUE_FREQUENCY == 0) {
			checkqueue(mqd_p32top33, p32top33, &noti_tran);
		}

		/////////////////////////////////////IDS
		IDS(timestamp, mq_return, iph, filp, i);
		mq_return = mq_send(mqd_p33top36, (char *) iph, mq_return, 0);
		if(mq_return == -1) {
			printf("%s:%s send %lld times fails:%s, errno = %d \n", proname, p33top36, i, strerror(errno), errno);
			return -1;
		}		

		mq_return = mq_receive(mqd_p32top33, buffer, 2048, 0);
		if(mq_return == -1) {
			printf("%s:%s receive %lld times fails:%s, errno = %d \n", proname, p32top33, i, strerror(errno), errno);
			return -1;
		}
		iph = (struct ndpi_iphdr *) buffer;
		if((i%SHOW_FREQUENCY == 0) || (i < SHOW_THRESHOLD)) {
			printf("%s:%s i = %lld, packet length = %d, iph->daddr = %8X, pid = %d , working on CPU %d \n", proname, p32top33, i, mq_return, iph->daddr, getpid(), getcpu());
		}
		if(i%CHECKQUEUE_FREQUENCY == 0) {
			checkqueue(mqd_p32top33, p32top33, &noti_tran);
		}
		
		/////////////////////////////////////IDS
		IDS(timestamp, mq_return, iph, filp, i);
		mq_return = mq_send(mqd_p33top35, (char *) iph, mq_return, 0);
		if(mq_return == -1) {
			printf("%s:%s send %lld times fails:%s, errno = %d \n", proname, p33top35, i, strerror(errno), errno);
			return -1;
		}	


		

	}
	printf("%s has transfered %lld packets. \n", proname, i);

	//p32top33
	mq_return = mq_close(mqd_p32top33);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(p32top33);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");

	//p33top36
	mq_return = mq_close(mqd_p33top36);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(p33top36);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");

	//p33top35
	mq_return = mq_close(mqd_p33top35);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(p33top35);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");

	//ctrltop33
	mq_return = mq_close(mqd_ctrltop33);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(ctrltop33);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");
	//p33toctrl
	mq_return = mq_close(mqd_p33toctrl);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(p33toctrl);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");


	exit(0);

}

