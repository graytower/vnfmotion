#include "nfv.h"
#include "fan.h"





int main() {
	/*initialization about mqueue*/
	char proname[] = "p16_l3";
	setcpu(P16_STARTING_CPU);

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
	mqd_t mqd_send2top16, mqd_p16top17, mqd_p16top18;
	int mq_return = 0;
	char send2top16[] = "/send2top16";
	char p16top17[] = "/p16top17";
	char p16top18[] = "/p16top18";

	mqd_send2top16 = mq_open(send2top16, flags, PERM, &attr);
	check_return(mqd_send2top16, send2top16, "mq_open");

	mqd_p16top17 = mq_open(p16top17, flags, PERM, &attr);
	check_return(mqd_p16top17, p16top17, "mq_open");

	mqd_p16top18 = mq_open(p16top18, flags, PERM, &attr);
	check_return(mqd_p16top18, p16top18, "mq_open");

	/*control part*/
	mqd_t mqd_ctrltop16, mqd_p16toctrl;
	char ctrltop16[] = "/ctrltop16";
	char p16toctrl[] = "/p16toctrl";
	mqd_ctrltop16 = mq_open(ctrltop16, flags_ctrl, PERM, &attr_ctrl);
	check_return(mqd_ctrltop16, ctrltop16, "mq_open");
	mqd_p16toctrl = mq_open(p16toctrl, flags_ctrl, PERM, &attr_ctrl);
	check_return(mqd_p16toctrl, p16toctrl, "mq_open");


	char buffer[2048];
	struct ndpi_iphdr * iph;
	long long int i = 0;


	/*pthread*/
	struct transfer noti_tran;
	noti_tran.mqd_ctop = mqd_ctrltop16;
	noti_tran.mqd_ptoc = mqd_p16toctrl;
	//noti_tran.mqd_p[0] = mqd_send2top16;
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
		mq_return = mq_receive(mqd_send2top16, buffer, 2048, 0);
		if(mq_return == -1) {
			printf("%s:%s receive %lld times fails:%s, errno = %d \n", proname, send2top16, i, strerror(errno), errno);
			return -1;
		}
		iph = (struct ndpi_iphdr *) buffer;

		//nip = iph->daddr;
		//port = findPort(route, nip);
		port = i%2; //don't use route function

		if((i%SHOW_FREQUENCY == 0) || (i < SHOW_THRESHOLD)) {
			printf("%s:%s i = %lld, packet length = %d, iph->daddr = %8X, port = %d, pid = %d , working on CPU %d \n",proname, send2top16, i, mq_return, iph->daddr, port, getpid(), getcpu());
		}
		if(i%CHECKQUEUE_FREQUENCY == 0) {

			checkqueue(mqd_send2top16, send2top16, &noti_tran);//check if the queue is congested and process need to be splited.
		}
		switch(port)
		{
			case 0:
				mq_return = mq_send(mqd_p16top17, (char *) iph, mq_return, 0);
				if(mq_return == -1) {
					printf("%s:%s send %lld times fails:%s, errno = %d \n", proname, p16top17, i, strerror(errno), errno);
					return -1;
				}
				break;
			case 1:
				mq_return = mq_send(mqd_p16top18, (char *) iph, mq_return, 0);
				if(mq_return == -1) {
					printf("%s:%s send %lld times fails:%s, errno = %d \n", proname, p16top18, i, strerror(errno), errno);
					return -1;
				}
				break;
		}

		
	}
	printf("%s:%s has transfered %lld packets. \n", proname, send2top16, i);
	checkcpu();

	//send2top16
	mq_return = mq_close(mqd_send2top16);//returns 0 on success, or -1 on error.
	check_return(mq_return, send2top16, "mq_close");
	mq_return = mq_unlink(send2top16);//returns 0 on success, or -1 on error.
	check_return(mq_return, send2top16, "mq_unlink");
	//p16top17
	mq_return = mq_close(mqd_p16top17);//returns 0 on success, or -1 on error.
	check_return(mq_return, p16top17, "mq_close");
	mq_return = mq_unlink(p16top17);//returns 0 on success, or -1 on error.
	check_return(mq_return, p16top17, "mq_unlink");
	//p16top18
	mq_return = mq_close(mqd_p16top18);//returns 0 on success, or -1 on error.
	check_return(mq_return, p16top18, "mq_close");
	mq_return = mq_unlink(p16top18);//returns 0 on success, or -1 on error.
	check_return(mq_return, p16top18, "mq_unlink");

	//ctrltop16
	mq_return = mq_close(mqd_ctrltop16);//returns 0 on success, or -1 on error.
	check_return(mq_return, ctrltop16, "mq_close");
	mq_return = mq_unlink(ctrltop16);//returns 0 on success, or -1 on error.
	check_return(mq_return, ctrltop16, "mq_unlink");
	//p16toctrl
	mq_return = mq_close(mqd_p16toctrl);//returns 0 on success, or -1 on error.
	check_return(mq_return, p16toctrl, "mq_close");
	mq_return = mq_unlink(p16toctrl);//returns 0 on success, or -1 on error.
	check_return(mq_return, p16toctrl, "mq_unlink");






	exit(0);

}







