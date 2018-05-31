#include "nfv.h"
#include "fan.h"
#include "../posix/ndpi_api.h" //iphdr
#include <pcap.h>

int main() {
	/*initialization about mqueue*/
	char proname[] = "p26_IDS";
	setcpu(P26_STARTING_CPU);

	struct mq_attr attr, attr_ctrl;
	attr.mq_maxmsg = MAXMSG;//maximum is 382.
	attr.mq_msgsize = 2048;
	attr.mq_flags = 0;

	attr_ctrl.mq_maxmsg = MAXMSGCTOP;
	attr_ctrl.mq_msgsize = 2048;
	attr_ctrl.mq_flags = 0;


	int flags = O_CREAT | O_RDWR;
	int flags_ctrl = O_CREAT | O_RDWR | O_NONBLOCK;
	mqd_t mqd_p24top26, mqd_p26top27, mqd_p26top30;
	int mq_return = 0;
	char p24top26[] = "/p24top26";
	char p26top27[] = "/p26top27";
	char p26top30[] = "/p26top30";
	
	mqd_p24top26 = mq_open(p24top26, flags, PERM, &attr);
	check_return(mqd_p24top26, p24top26, "mq_open");

	mqd_p26top27 = mq_open(p26top27, flags, PERM, &attr);
	check_return(mqd_p24top26, p26top27, "mq_open");

	mqd_p26top30 = mq_open(p26top30, flags, PERM, &attr);
	check_return(mqd_p24top26, p26top30, "mq_open");


	/*control part*/
	mqd_t mqd_ctrltop26, mqd_p26toctrl;
	char ctrltop26[] = "/ctrltop26";
	char p26toctrl[] = "/p26toctrl";
	mqd_ctrltop26 = mq_open(ctrltop26, flags_ctrl, PERM, &attr_ctrl);
	check_return(mqd_ctrltop26, ctrltop26, "mq_open");
	mqd_p26toctrl = mq_open(p26toctrl, flags_ctrl, PERM, &attr_ctrl);
	check_return(mqd_p26toctrl, p26toctrl, "mq_open");


	char buffer[2048];
	struct ndpi_iphdr * iph;
	long long int i = 0;

	/*pthread*/
	struct transfer noti_tran;
	noti_tran.mqd_ctop = mqd_ctrltop26;
	noti_tran.mqd_ptoc = mqd_p26toctrl;
	//noti_tran.mqd_p[0] = mqd_p24top26;
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
	char fileDir[] = "./log_IDS26.txt";
	filp = fopen(fileDir,"w");

/////////////////////////////////////////////////////////////////////


	//int port = 0;

	for(i = 0;i < PACKETS*10;i++) {//PACKETS = 5000 now.
		mq_return = mq_receive(mqd_p24top26, buffer, 2048, 0);
		if(mq_return == -1) {
			printf("%s:%s receive %lld times fails:%s, errno = %d \n", proname, p24top26, i, strerror(errno), errno);
		}
		iph = (struct ndpi_iphdr *) buffer;
		if((i%SHOW_FREQUENCY == 0) || (i < SHOW_THRESHOLD)) {
			printf("%s:%s i = %lld, packet length = %d, iph->daddr = %8X, pid = %d , working on CPU %d \n", proname, p24top26, i, mq_return, iph->daddr, getpid(), getcpu());
		}
		if(i%CHECKQUEUE_FREQUENCY == 0) {
			checkqueue(mqd_p24top26, p24top26, &noti_tran);
		}
		
		//////////////////////////////////////IDS
		IDS(timestamp, mq_return, iph, filp, i);
		mq_return = mq_send(mqd_p26top27, (char *) iph, mq_return, 0);
		if(mq_return == -1) {
			printf("%s:%s send %lld times fails:%s, errno = %d \n", proname, p26top27, i, strerror(errno), errno);
			return -1;
		}
		
		i++;
		
		mq_return = mq_receive(mqd_p24top26, buffer, 2048, 0);
		if(mq_return == -1) {
			printf("%s:%s receive %lld times fails:%s, errno = %d \n", proname, p24top26, i, strerror(errno), errno);
			return -1;
		}
		iph = (struct ndpi_iphdr *) buffer;
		if((i%SHOW_FREQUENCY == 0) || (i < SHOW_THRESHOLD)) {
			printf("%s:%s i = %lld, packet length = %d, iph->daddr = %8X, pid = %d , working on CPU %d \n", proname, p24top26, i, mq_return, iph->daddr, getpid(), getcpu());
		}
		if(i%CHECKQUEUE_FREQUENCY == 0) {
			checkqueue(mqd_p24top26, p24top26, &noti_tran);
		}
		
		//////////////////////////////////////IDS
		IDS(timestamp, mq_return, iph, filp, i);
		mq_return = mq_send(mqd_p26top30, (char *) iph, mq_return, 0);
		if(mq_return == -1) {
			printf("%s:%s send %lld times fails:%s, errno = %d \n", proname, p26top30, i, strerror(errno), errno);
			return -1;
		}
				
		

		

	}
	printf("%s has transfered %lld packets. \n", proname, i);

	//p24top26
	mq_return = mq_close(mqd_p24top26);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(p24top26);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");

	//p26top27
	mq_return = mq_close(mqd_p26top27);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(p26top27);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");

	//p26top30
	mq_return = mq_close(mqd_p26top30);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(p26top30);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");

	//ctrltop26
	mq_return = mq_close(mqd_ctrltop26);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(ctrltop26);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");
	//p26toctrl
	mq_return = mq_close(mqd_p26toctrl);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(p26toctrl);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");


	exit(0);

}

