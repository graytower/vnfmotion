#include"nfv.h"
#include "../posix/ndpi_api.h" //iphdr
#include <pcap.h>

#include "fan.h"

int main() {
	/*initialization about mqueue*/
	char proname[] = "p5_FW";
	setcpu(P5_STARTING_CPU);

	struct mq_attr attr, attr_ctrl, q_attr;
	attr.mq_maxmsg = MAXMSG;
	attr.mq_msgsize = 2048;
	attr.mq_flags = 0;

	attr_ctrl.mq_maxmsg = MAXMSGCTOP;
	attr_ctrl.mq_msgsize = 2048;
	attr_ctrl.mq_flags = 0;


	int flags = O_CREAT | O_RDWR;
	int flags_ctrl = O_CREAT | O_RDWR | O_NONBLOCK;
	mqd_t mqd_p4top5, mqd_p3top5, mqd_p5top7;
	int mq_return = 0;
	char p4top5[] = "/p4top5";
	char p3top5[] = "/p3top5";
	char p5top7[] = "/p5top7";

	mqd_p4top5 = mq_open(p4top5, flags, PERM, &attr);
	check_return(mqd_p4top5, p4top5, "mq_open");
	
	mqd_p3top5 = mq_open(p3top5, flags, PERM, &attr);
	check_return(mqd_p3top5, p3top5, "mq_open");

	mqd_p5top7 = mq_open(p5top7, flags, PERM, &attr);
	check_return(mqd_p5top7, p5top7, "mq_open");

	/*control part*/
	mqd_t mqd_ctrltop5, mqd_p5toctrl;
	char ctrltop5[] = "/ctrltop5";
	char p5toctrl[] = "/p5toctrl";
	mqd_ctrltop5 = mq_open(ctrltop5, flags_ctrl, PERM, &attr_ctrl);
	check_return(mqd_ctrltop5, ctrltop5, "mq_open");
	mqd_p5toctrl = mq_open(p5toctrl, flags_ctrl, PERM, &attr_ctrl);
	check_return(mqd_p5toctrl, p5toctrl, "mq_open");



	char buffer[2048];
	struct ndpi_iphdr * iph;
	long long int i = 0;
	long long int j = 0;

	/*pthread*/
	struct transfer noti_tran;
	noti_tran.mqd_ctop = mqd_ctrltop5;
	noti_tran.mqd_ptoc = mqd_p5toctrl;
	noti_tran.qds = 2;
	noti_tran.i[0] = &i;
	noti_tran.i[1] = &j;
	notifysetup(&noti_tran);


//////////////////////////////////////////fw///////////////////////////
    setupDetection();    //ndpi setup

	writeAcl(50);
	struct timeval timestamp;
	gettimeofday( &timestamp, NULL);
/////////////////////////////////////////////////////////////////////

	int flag = 0; //1: block, shows the result of firewall.
	int p_count1 = 0;
	int p_count2 = 0;
	int k = 0;
	while(1) {
		//p4top5
		mq_return = mq_getattr(mqd_p4top5, &q_attr);
		if(mq_return == -1) {
			printf("something wrong happened in %s when mq_getattr p4top5. \n", proname);
		}
		p_count1 = q_attr.mq_curmsgs >= 50?50:q_attr.mq_curmsgs;
		for(k = 0;k < p_count1;k++) {
			mq_return = mq_receive(mqd_p4top5, buffer, 2048, 0);
			if(mq_return == -1) {
				printf("%s:%s receive %lld times fails:%s, errno = %d \n", proname, p4top5, i, strerror(errno), errno);
				return -1;
			}
			iph = (struct ndpi_iphdr *) buffer;
			
			if(((i + j)%SHOW_FREQUENCY == 0) || ((i + j) < SHOW_THRESHOLD)) {
				printf("%s:%s i = %lld, packet length = %d, pid = %d , working on CPU %d \n", proname, p4top5, i, mq_return, getpid(), getcpu());
			}
			if(i%CHECKQUEUE_FREQUENCY == 0) {

				checkqueue(mqd_p4top5, p4top5, &noti_tran);//check if the queue is congested and process needs to be splited.
			}
			
/////////////////////////////////////////////////////////////////////////
			//FW actions
		
			fwpacket_preprocess(timestamp, mq_return, iph, &flag);
			if(flag != 0) {
				//printf("i = %lld, flag: %d \n", i, flag);
			}
			else {
					mq_return = mq_send(mqd_p5top7, (char *) iph, mq_return, 0);
					if(mq_return == -1) {
						printf("%s:send %lld times fails:%s, errno = %d \n", p5top7, i, strerror(errno), errno);
						return -1;
					}
			
			}
			///////////////////////////////////
			
			
			i++;			
		}
		
		//p3top5
		mq_return = mq_getattr(mqd_p3top5, &q_attr);
		if(mq_return == -1) {
			printf("something wrong happened in %s when mq_getattr p4top5. \n", proname);
			return -1;
		}
		p_count2 = q_attr.mq_curmsgs >= 50?50:q_attr.mq_curmsgs;
		for(k = 0;k < p_count2;k++) {
			mq_return = mq_receive(mqd_p3top5, buffer, 2048, 0);
			if(mq_return == -1) {
				printf("%s:%s receive %lld times fails:%s, errno = %d \n", proname, p3top5, j, strerror(errno), errno);
				return -1;
			}
			
			iph = (struct ndpi_iphdr *) buffer;
			if(((i + j)%SHOW_FREQUENCY == 0) || ((i + j) < SHOW_THRESHOLD)) {
				printf("%s:%s j = %lld, packet length = %d, pid = %d , working on CPU %d \n", proname, p3top5, j, mq_return, getpid(), getcpu());
			}
			if(j%CHECKQUEUE_FREQUENCY == 0) {

				checkqueue(mqd_p3top5, p3top5, &noti_tran);//check if the queue is congested and process needs to be splited.
			}
			
/////////////////////////////////////////////////////////////////////////
			//FW actions
		
			fwpacket_preprocess(timestamp, mq_return, iph, &flag);
			if(flag != 0) {
				printf("j = %lld, flag: %d \n", j, flag);
			}
			else {
					mq_return = mq_send(mqd_p5top7, (char *) iph, mq_return, 0);
					if(mq_return == -1) {
						printf("%s:send %lld times fails:%s, errno = %d \n", p5top7, j, strerror(errno), errno);
						return -1;
					}
			
			}
			///////////////////////////////////
			
			
			j++;
		}	
		if(p_count1 || p_count2) {
			continue;
		}
		else {//pretend the process to work when there is nothing in queue.
			usleep(1000);
		}	
		
	}
	
	
	
	printf("%s has transfered %lld packets. \n", proname, i);
	checkcpu();

	//p4top5
	mq_return = mq_close(mqd_p4top5);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(p4top5);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");

	//p3top5
	mq_return = mq_close(mqd_p3top5);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(p3top5);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");
	
	//p5top7
	mq_return = mq_close(mqd_p5top7);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(p5top7);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");

	//ctrltop5
	mq_return = mq_close(mqd_ctrltop5);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(ctrltop5);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");
	//p5toctrl
	mq_return = mq_close(mqd_p5toctrl);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_close");
	mq_return = mq_unlink(p5toctrl);//returns 0 on success, or -1 on error.
	check_return(mq_return, proname, "mq_unlink");




	exit(0);

}

