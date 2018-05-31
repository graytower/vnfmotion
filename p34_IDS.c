#include "nfv.h"
#include "fan.h"
#include "../posix/ndpi_api.h" //iphdr
#include <pcap.h>

int main() {
	/*initialization about mqueue*/
	char proname[] = "p34_IDS";
	setcpu(P34_STARTING_CPU);

	struct mq_attr attr, attr_ctrl;
	attr.mq_maxmsg = MAXMSG;//maximum is 382.
	attr.mq_msgsize = 2048;
	attr.mq_flags = 0;

	attr_ctrl.mq_maxmsg = MAXMSGCTOP;
	attr_ctrl.mq_msgsize = 2048;
	attr_ctrl.mq_flags = 0;


	int flags = O_CREAT | O_RDWR;
	int flags_ctrl = O_CREAT | O_RDWR | O_NONBLOCK;
	mqd_t mqd_p32top34, mqd_p34top35, mqd_p34top38;
	int mq_return = 0;
	char p32top34[] = "/p32top34";
	char p34top35[] = "/p34top35";
	char p34top38[] = "/p34top38";
	
	mqd_p32top34 = mq_open(p32top34, flags, PERM, &attr);
	check_return(mqd_p32top34, p32top34, "mq_open");

	mqd_p34top35 = mq_open(p34top35, flags, PERM, &attr);
	check_return(mqd_p32top34, p34top35, "mq_open");

	mqd_p34top38 = mq_open(p34top38, flags, PERM, &attr);
	check_return(mqd_p32top34, p34top38, "mq_open");


	/*control part*/
	mqd_t mqd_ctrltop34, mqd_p34toctrl;
	char ctrltop34[] = "/ctrltop34";
	char p34toctrl[] = "/p34toctrl";
	mqd_ctrltop34 = mq_open(ctrltop34, flags_ctrl, PERM, &attr_ctrl);
	check_return(mqd_ctrltop34, ctrltop34, "mq_open");
	mqd_p34toctrl = mq_open(p34toctrl, flags_ctrl, PERM, &attr_ctrl);
	check_return(mqd_p34toctrl, p34toctrl, "mq_open");


	char buffer[2048];
	struct ndpi_iphdr * iph;
	long long int i = 0;

	/*pthread*/
	struct transfer noti_tran;
	noti_tran.mqd_ctop = mqd_ctrltop34;
	noti_tran.mqd_ptoc = mqd_p34toctrl;
	//noti_tran.mqd_p[0] = mqd_p32top34;
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
	char fileDir[] = "./log_IDS34.txt";
	filp = fopen(fileDir,"w");

/////////////////////////////////////////////////////////////////////


	//int port = 0;

	for(i = 0;i < PACKETS*10;i++) {//PACKETS = 5000 now.
		mq_return = mq_receive(mqd_p32top34, buffer, 2048, 0);
		if(mq_return == -1) {
			printf("%s:%s receive %lld times fails:%s, errno = %d \n", proname, p32top34, i, strerror(errno), errno);
		}
		iph = (struct ndpi_iphdr *) buffer;
		if((i%SHOW_FREQUENCY == 0) || (i < SHOW_THRESHOLD)) {
			printf("%s:%s i = %lld, packet length = %d, iph->daddr = %8X, pid = %d , working on CPU %d \n", proname, p32top34, i, mq_return, iph->daddr, getpid(), getcpu());
		}
		if(i%CHECKQUEUE_FREQUENCY == 0) {
			checkqueue(mqd_p32top34, p32top34, &noti_tran);
		}
		
		//////////////////////////////////////IDS
		IDS(timestamp, mq_return, iph, filp, i);
		mq_return = mq_send(mqd_p34top35, (char *) iph, mq_return, 0);
		if(mq_return == -1) {
			printf("%s:%s send %lld times fails:%s, errno = %d \n", proname, p34top35, i, strerror(errno), errno);
			return -1;
		}
		
		i++;
		
		mq_return = mq_receive(mqd_p32top34, buffer, 2048, 0);
		if(mq_return == -1) {
			printf("%s:%s receive %lld times fails:%s, errno = %d \n", proname, p32top34, i, strerror(errno), errno);
			return -1;
		}
		iph = (struct ndpi_iphdr *) buffer;
		if((i%SHOW_FREQUENCY == 0) || (i < SHOW_THRESHOLD)) {
			printf("%s:%s i = %lld, packet length = %d, iph->daddr = %8X, pid = %d , working on CPU %d \n", proname, p32top34, i, mq_return, iph->daddr, getpid(), getcpu());
		}
		if(i%CHECKQUEUE_FREQUENCY == 0) {
			checkqueue(mqd_p32top34, p32top34, &noti_tran);
		}
		
		//////////////////////////////////////IDS
		IDS(timestamp, mq_return, iph, filp, i);
		mq_return = mq_send(mqd_p34top38, (char *) iph, mq_return, 0);
		if(mq_return == -1) {
			printf("%s:%s send %lld times fails:%s, errno = %d \n", proname, p34top38, i, strerror(errno), errno);
			return -1;
		}
				
		

		

	}
	printf("%s has transfered %lld packets. \n", proname, i);

	//p32top34
	mq_return = mq_close(mqd_p32top34);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(p32top34);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");

	//p34top35
	mq_return = mq_close(mqd_p34top35);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(p34top35);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");

	//p34top38
	mq_return = mq_close(mqd_p34top38);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(p34top38);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");

	//ctrltop34
	mq_return = mq_close(mqd_ctrltop34);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(ctrltop34);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");
	//p34toctrl
	mq_return = mq_close(mqd_p34toctrl);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(p34toctrl);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");


	exit(0);

}

