#include "nfv.h"
#include "fan.h"





int main() {
	/*initialization about mqueue*/
	char proname[] = "p8_l3";
	setcpu(P8_STARTING_CPU);

	struct mq_attr attr, attr_ctrl;
	//struct mq_attr q_attr;
	attr.mq_maxmsg = MAXMSG;//maximum is 382.
	attr.mq_msgsize = 2048;
	attr.mq_flags = 0;

	attr_ctrl.mq_maxmsg = MAXMSGCTOP;
	attr_ctrl.mq_msgsize = 2048;
	attr_ctrl.mq_flags = 0;

	int flags = O_CREAT | O_RDWR;
	int flags_ctrl = O_CREAT | O_RDWR | O_NONBLOCK;
	mqd_t mqd_send1top8, mqd_p8top9, mqd_p8top10;
	int mq_return = 0;
	char send1top8[] = "/send1top8";
	char p8top9[] = "/p8top9";
	char p8top10[] = "/p8top10";

	mqd_send1top8 = mq_open(send1top8, flags, PERM, &attr);
	check_return(mqd_send1top8, send1top8, "mq_open");

	mqd_p8top9 = mq_open(p8top9, flags, PERM, &attr);
	check_return(mqd_p8top9, p8top9, "mq_open");

	mqd_p8top10 = mq_open(p8top10, flags, PERM, &attr);
	check_return(mqd_p8top10, p8top10, "mq_open");

	/*control part*/
	mqd_t mqd_ctrltop8, mqd_p8toctrl;
	char ctrltop8[] = "/ctrltop8";
	char p8toctrl[] = "/p8toctrl";
	mqd_ctrltop8 = mq_open(ctrltop8, flags_ctrl, PERM, &attr_ctrl);
	check_return(mqd_ctrltop8, ctrltop8, "mq_open");
	mqd_p8toctrl = mq_open(p8toctrl, flags_ctrl, PERM, &attr_ctrl);
	check_return(mqd_p8toctrl, p8toctrl, "mq_open");


	char buffer[2048];
	struct ndpi_iphdr * iph;
	long long int i = 0;


	/*pthread*/
	struct transfer noti_tran;
	noti_tran.mqd_ctop = mqd_ctrltop8;
	noti_tran.mqd_ptoc = mqd_p8toctrl;
	//noti_tran.mqd_p[0] = mqd_send1top8;
	noti_tran.qds = 1;
	noti_tran.i[0] = &i;
	notifysetup(&noti_tran);






	/*NODE * g_pRouteTree = createNode();

	int routetable[2] = {0x9000FFFF, 0x0000FFFF};
	int j = 0;
	for(j = 0;j < 2;j++) {
		createRouteTree(g_pRouteTree, routetable[j], 1, j);
		printf("route[%d]:%8X, port:%d\n", j, routetable[j], j);
	}
	createRouteTree(g_pRouteTree, 0, 0, 999);
	*/
	
	
	HASH_TABLE* route[MASK] ;       //route table
    lpmRouteInit(route);    //init route

	
	int port = 0;
	//u_int32_t nip = 0;

	for(i = 0;1;i++) {//PACKETS = 5000 now.
		mq_return = mq_receive(mqd_send1top8, buffer, 2048, 0);
		if(mq_return == -1) {
			printf("%s:%s receive %lld times fails:%s, errno = %d \n", proname, send1top8, i, strerror(errno), errno);
			return -1;
		}
		iph = (struct ndpi_iphdr *) buffer;

		//nip = iph->daddr;
		//port = findPort(route, nip);
		port = i%2; //don't use route function

		if((i%SHOW_FREQUENCY == 0) || (i < SHOW_THRESHOLD)) {
			printf("%s:%s i = %lld, packet length = %d, iph->daddr = %8X, port = %d, pid = %d , working on CPU %d \n",proname, send1top8, i, mq_return, iph->daddr, port, getpid(), getcpu());
		}
		if(i%CHECKQUEUE_FREQUENCY == 0) {

			checkqueue(mqd_send1top8, send1top8, &noti_tran);//check if the queue is congested and process need to be splited.
		}
		switch(port)
		{
			case 0:
				mq_return = mq_send(mqd_p8top9, (char *) iph, mq_return, 0);
				if(mq_return == -1) {
					printf("%s:%s send %lld times fails:%s, errno = %d \n", proname, p8top9, i, strerror(errno), errno);
					return -1;
				}
				break;
			case 1:
				mq_return = mq_send(mqd_p8top10, (char *) iph, mq_return, 0);
				if(mq_return == -1) {
					printf("%s:%s send %lld times fails:%s, errno = %d \n", proname, p8top10, i, strerror(errno), errno);
					return -1;
				}
				break;
		}

		
	}
	printf("%s:%s has transfered %lld packets. \n", proname, send1top8, i);
	checkcpu();

	//send1op8
	mq_return = mq_close(mqd_send1top8);//returns 0 on success, or -1 on error.
	check_return(mq_return, send1top8, "mq_close");
	mq_return = mq_unlink(send1top8);//returns 0 on success, or -1 on error.
	check_return(mq_return, send1top8, "mq_unlink");
	//p8top9
	mq_return = mq_close(mqd_p8top9);//returns 0 on success, or -1 on error.
	check_return(mq_return, p8top9, "mq_close");
	mq_return = mq_unlink(p8top9);//returns 0 on success, or -1 on error.
	check_return(mq_return, p8top9, "mq_unlink");
	//p8top10
	mq_return = mq_close(mqd_p8top10);//returns 0 on success, or -1 on error.
	check_return(mq_return, p8top10, "mq_close");
	mq_return = mq_unlink(p8top10);//returns 0 on success, or -1 on error.
	check_return(mq_return, p8top10, "mq_unlink");

	//ctrltop8
	mq_return = mq_close(mqd_ctrltop8);//returns 0 on success, or -1 on error.
	check_return(mq_return, ctrltop8, "mq_close");
	mq_return = mq_unlink(ctrltop8);//returns 0 on success, or -1 on error.
	check_return(mq_return, ctrltop8, "mq_unlink");
	//p8toctrl
	mq_return = mq_close(mqd_p8toctrl);//returns 0 on success, or -1 on error.
	check_return(mq_return, p8toctrl, "mq_close");
	mq_return = mq_unlink(p8toctrl);//returns 0 on success, or -1 on error.
	check_return(mq_return, p8toctrl, "mq_unlink");






	exit(0);

}







