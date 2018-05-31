#include "nfv.h"
#include "fan.h"





int main() {
	/*initialization about mqueue*/
	char proname[] = "p32_l3";
	setcpu(P32_STARTING_CPU);

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
	mqd_t mqd_send4top32, mqd_p32top33, mqd_p32top34;
	int mq_return = 0;
	char send4top32[] = "/send4top32";
	char p32top33[] = "/p32top33";
	char p32top34[] = "/p32top34";

	mqd_send4top32 = mq_open(send4top32, flags, PERM, &attr);
	check_return(mqd_send4top32, send4top32, "mq_open");

	mqd_p32top33 = mq_open(p32top33, flags, PERM, &attr);
	check_return(mqd_p32top33, p32top33, "mq_open");

	mqd_p32top34 = mq_open(p32top34, flags, PERM, &attr);
	check_return(mqd_p32top34, p32top34, "mq_open");

	/*control part*/
	mqd_t mqd_ctrltop32, mqd_p32toctrl;
	char ctrltop32[] = "/ctrltop32";
	char p32toctrl[] = "/p32toctrl";
	mqd_ctrltop32 = mq_open(ctrltop32, flags_ctrl, PERM, &attr_ctrl);
	check_return(mqd_ctrltop32, ctrltop32, "mq_open");
	mqd_p32toctrl = mq_open(p32toctrl, flags_ctrl, PERM, &attr_ctrl);
	check_return(mqd_p32toctrl, p32toctrl, "mq_open");


	char buffer[2048];
	struct ndpi_iphdr * iph;
	long long int i = 0;


	/*pthread*/
	struct transfer noti_tran;
	noti_tran.mqd_ctop = mqd_ctrltop32;
	noti_tran.mqd_ptoc = mqd_p32toctrl;
	//noti_tran.mqd_p[0] = mqd_send4top32;
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
		mq_return = mq_receive(mqd_send4top32, buffer, 2048, 0);
		if(mq_return == -1) {
			printf("%s:%s receive %lld times fails:%s, errno = %d \n", proname, send4top32, i, strerror(errno), errno);
			return -1;
		}
		iph = (struct ndpi_iphdr *) buffer;
		
		//nip = iph->daddr;
		//port = findPort(route, nip);
		port = i%2; //don't use route function

		if((i%SHOW_FREQUENCY == 0) || (i < SHOW_THRESHOLD)) {
			printf("%s:%s i = %lld, packet length = %d, iph->daddr = %8X, port = %d, pid = %d , working on CPU %d \n",proname, send4top32, i, mq_return, iph->daddr, port, getpid(), getcpu());
		}
		if(i%CHECKQUEUE_FREQUENCY == 0) {

			checkqueue(mqd_send4top32, send4top32, &noti_tran);//check if the queue is congested and process need to be splited.
		}
		switch(port)
		{
			case 0:
				mq_return = mq_send(mqd_p32top33, (char *) iph, mq_return, 0);
				if(mq_return == -1) {
					printf("%s:%s send %lld times fails:%s, errno = %d \n", proname, p32top33, i, strerror(errno), errno);
					return -1;
				}
				break;
			case 1:
				mq_return = mq_send(mqd_p32top34, (char *) iph, mq_return, 0);
				if(mq_return == -1) {
					printf("%s:%s send %lld times fails:%s, errno = %d \n", proname, p32top34, i, strerror(errno), errno);
					return -1;
				}
				break;
		}

		
	}
	printf("%s:%s has transfered %lld packets. \n", proname, send4top32, i);
	checkcpu();

	//send4top32
	mq_return = mq_close(mqd_send4top32);//returns 0 on success, or -1 on error.
	check_return(mq_return, send4top32, "mq_close");
	mq_return = mq_unlink(send4top32);//returns 0 on success, or -1 on error.
	check_return(mq_return, send4top32, "mq_unlink");
	//p32top33
	mq_return = mq_close(mqd_p32top33);//returns 0 on success, or -1 on error.
	check_return(mq_return, p32top33, "mq_close");
	mq_return = mq_unlink(p32top33);//returns 0 on success, or -1 on error.
	check_return(mq_return, p32top33, "mq_unlink");
	//p32top34
	mq_return = mq_close(mqd_p32top34);//returns 0 on success, or -1 on error.
	check_return(mq_return, p32top34, "mq_close");
	mq_return = mq_unlink(p32top34);//returns 0 on success, or -1 on error.
	check_return(mq_return, p32top34, "mq_unlink");

	//ctrltop32
	mq_return = mq_close(mqd_ctrltop32);//returns 0 on success, or -1 on error.
	check_return(mq_return, ctrltop32, "mq_close");
	mq_return = mq_unlink(ctrltop32);//returns 0 on success, or -1 on error.
	check_return(mq_return, ctrltop32, "mq_unlink");
	//p32toctrl
	mq_return = mq_close(mqd_p32toctrl);//returns 0 on success, or -1 on error.
	check_return(mq_return, p32toctrl, "mq_close");
	mq_return = mq_unlink(p32toctrl);//returns 0 on success, or -1 on error.
	check_return(mq_return, p32toctrl, "mq_unlink");






	exit(0);

}







