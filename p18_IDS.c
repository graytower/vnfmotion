#include "nfv.h"
#include "fan.h"
#include "../posix/ndpi_api.h" //iphdr
#include <pcap.h>

int main() {
	/*initialization about mqueue*/
	char proname[] = "p18_IDS";
	setcpu(P18_STARTING_CPU);

	struct mq_attr attr, attr_ctrl;
	attr.mq_maxmsg = MAXMSG;//maximum is 382.
	attr.mq_msgsize = 2048;
	attr.mq_flags = 0;

	attr_ctrl.mq_maxmsg = MAXMSGCTOP;
	attr_ctrl.mq_msgsize = 2048;
	attr_ctrl.mq_flags = 0;


	int flags = O_CREAT | O_RDWR;
	int flags_ctrl = O_CREAT | O_RDWR | O_NONBLOCK;
	mqd_t mqd_p16top18, mqd_p18top19, mqd_p18top22;
	int mq_return = 0;
	char p16top18[] = "/p16top18";
	char p18top19[] = "/p18top19";
	char p18top22[] = "/p18top22";
	
	mqd_p16top18 = mq_open(p16top18, flags, PERM, &attr);
	check_return(mqd_p16top18, p16top18, "mq_open");

	mqd_p18top19 = mq_open(p18top19, flags, PERM, &attr);
	check_return(mqd_p16top18, p18top19, "mq_open");

	mqd_p18top22 = mq_open(p18top22, flags, PERM, &attr);
	check_return(mqd_p16top18, p18top22, "mq_open");


	/*control part*/
	mqd_t mqd_ctrltop18, mqd_p18toctrl;
	char ctrltop18[] = "/ctrltop18";
	char p18toctrl[] = "/p18toctrl";
	mqd_ctrltop18 = mq_open(ctrltop18, flags_ctrl, PERM, &attr_ctrl);
	check_return(mqd_ctrltop18, ctrltop18, "mq_open");
	mqd_p18toctrl = mq_open(p18toctrl, flags_ctrl, PERM, &attr_ctrl);
	check_return(mqd_p18toctrl, p18toctrl, "mq_open");


	char buffer[2048];
	struct ndpi_iphdr * iph;
	long long int i = 0;

	/*pthread*/
	struct transfer noti_tran;
	noti_tran.mqd_ctop = mqd_ctrltop18;
	noti_tran.mqd_ptoc = mqd_p18toctrl;
	//noti_tran.mqd_p[0] = mqd_p16top18;
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
	char fileDir[] = "./log_IDS18.txt";
	filp = fopen(fileDir,"w");

/////////////////////////////////////////////////////////////////////


	//int port = 0;

	for(i = 0;i < PACKETS*10;i++) {//PACKETS = 5000 now.
		mq_return = mq_receive(mqd_p16top18, buffer, 2048, 0);
		if(mq_return == -1) {
			printf("%s:%s receive %lld times fails:%s, errno = %d \n", proname, p16top18, i, strerror(errno), errno);
		}
		iph = (struct ndpi_iphdr *) buffer;
		if((i%SHOW_FREQUENCY == 0) || (i < SHOW_THRESHOLD)) {
			printf("%s:%s i = %lld, packet length = %d, iph->daddr = %8X, pid = %d , working on CPU %d \n", proname, p16top18, i, mq_return, iph->daddr, getpid(), getcpu());
		}
		if(i%CHECKQUEUE_FREQUENCY == 0) {
			checkqueue(mqd_p16top18, p16top18, &noti_tran);
		}
		
		//////////////////////////////////////IDS
		IDS(timestamp, mq_return, iph, filp, i);
		mq_return = mq_send(mqd_p18top19, (char *) iph, mq_return, 0);
		if(mq_return == -1) {
			printf("%s:%s send %lld times fails:%s, errno = %d \n", proname, p18top19, i, strerror(errno), errno);
			return -1;
		}
		
		i++;
		
		mq_return = mq_receive(mqd_p16top18, buffer, 2048, 0);
		if(mq_return == -1) {
			printf("%s:%s receive %lld times fails:%s, errno = %d \n", proname, p16top18, i, strerror(errno), errno);
			return -1;
		}
		iph = (struct ndpi_iphdr *) buffer;
		if((i%SHOW_FREQUENCY == 0) || (i < SHOW_THRESHOLD)) {
			printf("%s:%s i = %lld, packet length = %d, iph->daddr = %8X, pid = %d , working on CPU %d \n", proname, p16top18, i, mq_return, iph->daddr, getpid(), getcpu());
		}
		if(i%CHECKQUEUE_FREQUENCY == 0) {
			checkqueue(mqd_p16top18, p16top18, &noti_tran);
		}
		
		//////////////////////////////////////IDS
		IDS(timestamp, mq_return, iph, filp, i);
		mq_return = mq_send(mqd_p18top22, (char *) iph, mq_return, 0);
		if(mq_return == -1) {
			printf("%s:%s send %lld times fails:%s, errno = %d \n", proname, p18top22, i, strerror(errno), errno);
			return -1;
		}
				
		

		

	}
	printf("%s has transfered %lld packets. \n", proname, i);

	//p16top18
	mq_return = mq_close(mqd_p16top18);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(p16top18);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");

	//p18top19
	mq_return = mq_close(mqd_p18top19);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(p18top19);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");

	//p18top22
	mq_return = mq_close(mqd_p18top22);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(p18top22);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");

	//ctrltop18
	mq_return = mq_close(mqd_ctrltop18);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(ctrltop18);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");
	//p18toctrl
	mq_return = mq_close(mqd_p18toctrl);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(p18toctrl);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");


	exit(0);

}

