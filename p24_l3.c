#include "nfv.h"
#include "fan.h"





int main() {
	/*initialization about mqueue*/
	char proname[] = "p24_l3";
	setcpu(P24_STARTING_CPU);

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
	mqd_t mqd_send3top24, mqd_p24top25, mqd_p24top26;
	int mq_return = 0;
	char send3top24[] = "/send3top24";
	char p24top25[] = "/p24top25";
	char p24top26[] = "/p24top26";

	mqd_send3top24 = mq_open(send3top24, flags, PERM, &attr);
	check_return(mqd_send3top24, send3top24, "mq_open");

	mqd_p24top25 = mq_open(p24top25, flags, PERM, &attr);
	check_return(mqd_p24top25, p24top25, "mq_open");

	mqd_p24top26 = mq_open(p24top26, flags, PERM, &attr);
	check_return(mqd_p24top26, p24top26, "mq_open");

	/*control part*/
	mqd_t mqd_ctrltop0, mqd_p24toctrl;
	char ctrltop0[] = "/ctrltop24";
	char p24toctrl[] = "/p24toctrl";
	mqd_ctrltop0 = mq_open(ctrltop0, flags_ctrl, PERM, &attr_ctrl);
	check_return(mqd_ctrltop0, ctrltop0, "mq_open");
	mqd_p24toctrl = mq_open(p24toctrl, flags_ctrl, PERM, &attr_ctrl);
	check_return(mqd_p24toctrl, p24toctrl, "mq_open");


	char buffer[2048];
	struct ndpi_iphdr * iph;
	long long int i = 0;


	/*pthread*/
	struct transfer noti_tran;
	noti_tran.mqd_ctop = mqd_ctrltop0;
	noti_tran.mqd_ptoc = mqd_p24toctrl;
	//noti_tran.mqd_p[0] = mqd_send3top24;
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
		mq_return = mq_receive(mqd_send3top24, buffer, 2048, 0);
		if(mq_return == -1) {
			printf("%s:%s receive %lld times fails:%s, errno = %d \n", proname, send3top24, i, strerror(errno), errno);
			return -1;
		}
		iph = (struct ndpi_iphdr *) buffer;

		//nip = iph->daddr;
		//port = findPort(route, nip);
		port = i%2; //don't use route function

		if((i%SHOW_FREQUENCY == 0) || (i < SHOW_THRESHOLD)) {
			printf("%s:%s i = %lld, packet length = %d, iph->daddr = %8X, port = %d, pid = %d , working on CPU %d \n",proname, send3top24, i, mq_return, iph->daddr, port, getpid(), getcpu());
		}
		if(i%CHECKQUEUE_FREQUENCY == 0) {

			checkqueue(mqd_send3top24, send3top24, &noti_tran);//check if the queue is congested and process need to be splited.
		}
		switch(port)
		{
			case 0:
				mq_return = mq_send(mqd_p24top25, (char *) iph, mq_return, 0);
				if(mq_return == -1) {
					printf("%s:%s send %lld times fails:%s, errno = %d \n", proname, p24top25, i, strerror(errno), errno);
					return -1;
				}
				break;
			case 1:
				mq_return = mq_send(mqd_p24top26, (char *) iph, mq_return, 0);
				if(mq_return == -1) {
					printf("%s:%s send %lld times fails:%s, errno = %d \n", proname, p24top26, i, strerror(errno), errno);
					return -1;
				}
				break;
		}

		
	}
	printf("%s:%s has transfered %lld packets. \n", proname, send3top24, i);
	checkcpu();

	//send3top24
	mq_return = mq_close(mqd_send3top24);//returns 0 on success, or -1 on error.
	check_return(mq_return, send3top24, "mq_close");
	mq_return = mq_unlink(send3top24);//returns 0 on success, or -1 on error.
	check_return(mq_return, send3top24, "mq_unlink");
	//p24top25
	mq_return = mq_close(mqd_p24top25);//returns 0 on success, or -1 on error.
	check_return(mq_return, p24top25, "mq_close");
	mq_return = mq_unlink(p24top25);//returns 0 on success, or -1 on error.
	check_return(mq_return, p24top25, "mq_unlink");
	//p24top26
	mq_return = mq_close(mqd_p24top26);//returns 0 on success, or -1 on error.
	check_return(mq_return, p24top26, "mq_close");
	mq_return = mq_unlink(p24top26);//returns 0 on success, or -1 on error.
	check_return(mq_return, p24top26, "mq_unlink");

	//ctrltop24
	mq_return = mq_close(mqd_ctrltop0);//returns 0 on success, or -1 on error.
	check_return(mq_return, ctrltop0, "mq_close");
	mq_return = mq_unlink(ctrltop0);//returns 0 on success, or -1 on error.
	check_return(mq_return, ctrltop0, "mq_unlink");
	//p24toctrl
	mq_return = mq_close(mqd_p24toctrl);//returns 0 on success, or -1 on error.
	check_return(mq_return, p24toctrl, "mq_close");
	mq_return = mq_unlink(p24toctrl);//returns 0 on success, or -1 on error.
	check_return(mq_return, p24toctrl, "mq_unlink");






	exit(0);

}







