#include "nfv.h"
#include "fan.h"
#include "../posix/ndpi_api.h" //iphdr
#include <pcap.h>

int main() {
	/*initialization about mqueue*/
	char proname[] = "p10_IDS";
	setcpu(P10_STARTING_CPU);

	struct mq_attr attr, attr_ctrl;
	attr.mq_maxmsg = MAXMSG;//maximum is 382.
	attr.mq_msgsize = 2048;
	attr.mq_flags = 0;

	attr_ctrl.mq_maxmsg = MAXMSGCTOP;
	attr_ctrl.mq_msgsize = 2048;
	attr_ctrl.mq_flags = 0;


	int flags = O_CREAT | O_RDWR;
	int flags_ctrl = O_CREAT | O_RDWR | O_NONBLOCK;
	mqd_t mqd_p8top10, mqd_p10top11, mqd_p10top14;
	int mq_return = 0;
	char p8top10[] = "/p8top10";
	char p10top11[] = "/p10top11";
	char p10top14[] = "/p10top14";
	
	mqd_p8top10 = mq_open(p8top10, flags, PERM, &attr);
	check_return(mqd_p8top10, p8top10, "mq_open");

	mqd_p10top11 = mq_open(p10top11, flags, PERM, &attr);
	check_return(mqd_p8top10, p10top11, "mq_open");

	mqd_p10top14 = mq_open(p10top14, flags, PERM, &attr);
	check_return(mqd_p8top10, p10top14, "mq_open");


	/*control part*/
	mqd_t mqd_ctrltop10, mqd_p10toctrl;
	char ctrltop10[] = "/ctrltop10";
	char p10toctrl[] = "/p10toctrl";
	mqd_ctrltop10 = mq_open(ctrltop10, flags_ctrl, PERM, &attr_ctrl);
	check_return(mqd_ctrltop10, ctrltop10, "mq_open");
	mqd_p10toctrl = mq_open(p10toctrl, flags_ctrl, PERM, &attr_ctrl);
	check_return(mqd_p10toctrl, p10toctrl, "mq_open");


	char buffer[2048];
	struct ndpi_iphdr * iph;
	long long int i = 0;

	/*pthread*/
	struct transfer noti_tran;
	noti_tran.mqd_ctop = mqd_ctrltop10;
	noti_tran.mqd_ptoc = mqd_p10toctrl;
	//noti_tran.mqd_p[0] = mqd_p8top10;
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
	char fileDir[] = "./log_IDS10.txt";
	filp = fopen(fileDir,"w");

/////////////////////////////////////////////////////////////////////


	//int port = 0;

	for(i = 0;i < PACKETS*10;i++) {//PACKETS = 5000 now.
		mq_return = mq_receive(mqd_p8top10, buffer, 2048, 0);
		if(mq_return == -1) {
			printf("%s:%s receive %lld times fails:%s, errno = %d \n", proname, p8top10, i, strerror(errno), errno);
		}
		iph = (struct ndpi_iphdr *) buffer;
		if((i%SHOW_FREQUENCY == 0) || (i < SHOW_THRESHOLD)) {
			printf("%s:%s i = %lld, packet length = %d, iph->daddr = %8X, pid = %d , working on CPU %d \n", proname, p8top10, i, mq_return, iph->daddr, getpid(), getcpu());
		}
		if(i%CHECKQUEUE_FREQUENCY == 0) {
			checkqueue(mqd_p8top10, p8top10, &noti_tran);
		}
		
		//////////////////////////////////////IDS
		IDS(timestamp, mq_return, iph, filp, i);
		mq_return = mq_send(mqd_p10top11, (char *) iph, mq_return, 0);
		if(mq_return == -1) {
			printf("%s:%s send %lld times fails:%s, errno = %d \n", proname, p10top11, i, strerror(errno), errno);
			return -1;
		}
		
		i++;
		
		mq_return = mq_receive(mqd_p8top10, buffer, 2048, 0);
		if(mq_return == -1) {
			printf("%s:%s receive %lld times fails:%s, errno = %d \n", proname, p8top10, i, strerror(errno), errno);
			return -1;
		}
		iph = (struct ndpi_iphdr *) buffer;
		if((i%SHOW_FREQUENCY == 0) || (i < SHOW_THRESHOLD)) {
			printf("%s:%s i = %lld, packet length = %d, iph->daddr = %8X, pid = %d , working on CPU %d \n", proname, p8top10, i, mq_return, iph->daddr, getpid(), getcpu());
		}
		if(i%CHECKQUEUE_FREQUENCY == 0) {
			checkqueue(mqd_p8top10, p8top10, &noti_tran);
		}
		
		//////////////////////////////////////IDS
		IDS(timestamp, mq_return, iph, filp, i);
		mq_return = mq_send(mqd_p10top14, (char *) iph, mq_return, 0);
		if(mq_return == -1) {
			printf("%s:%s send %lld times fails:%s, errno = %d \n", proname, p10top14, i, strerror(errno), errno);
			return -1;
		}
				
		

		

	}
	printf("%s has transfered %lld packets. \n", proname, i);

	//p8top10
	mq_return = mq_close(mqd_p8top10);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(p8top10);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");

	//p10top11
	mq_return = mq_close(mqd_p10top11);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(p10top11);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");

	//p10top14
	mq_return = mq_close(mqd_p10top14);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(p10top14);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");

	//ctrltop10
	mq_return = mq_close(mqd_ctrltop10);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(ctrltop10);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");
	//p10toctrl
	mq_return = mq_close(mqd_p10toctrl);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(p10toctrl);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");


	exit(0);

}

