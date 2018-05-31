#include "nfv.h"
#include "fan.h"





int main() {
	/*initialization about mqueue*/
	char proname[] = "p11_l3fwd";
	setcpu(P11_STARTING_CPU);

	struct mq_attr attr, attr_ctrl, q_attr;
	attr.mq_maxmsg = MAXMSG;//maximum is 382.
	attr.mq_msgsize = 2048;
	attr.mq_flags = 0;

	attr_ctrl.mq_maxmsg = MAXMSGCTOP;
	attr_ctrl.mq_msgsize = 2048;
	attr_ctrl.mq_flags = 0;

	int flags = O_CREAT | O_RDWR;
	int flags_ctrl = O_CREAT | O_RDWR | O_NONBLOCK;
	mqd_t mqd_p9top11, mqd_p10top11, mqd_p11top13, mqd_p11top14;
	int mq_return = 0;
	char p9top11[] = "/p9top11";
	char p10top11[] = "/p10top11";
	char p11top13[] = "/p11top13";
	char p11top14[] = "/p11top14";

	/*working processes queues*/
	mqd_p9top11 = mq_open(p9top11, flags, PERM, &attr);
	check_return(mqd_p9top11, p9top11, "mq_open");

	mqd_p10top11 = mq_open(p10top11, flags, PERM, &attr);
	check_return(mqd_p10top11, p10top11, "mq_open");
	
	mqd_p11top13 = mq_open(p11top13, flags, PERM, &attr);
	check_return(mqd_p11top13, p11top13, "mq_open");

	mqd_p11top14 = mq_open(p11top14, flags, PERM, &attr);
	check_return(mqd_p11top14, p11top14, "mq_open");
	
	/*control part*/
	mqd_t mqd_ctrltop11, mqd_p11toctrl;
	char ctrltop11[] = "/ctrltop11";
	char p11toctrl[] = "/p11toctrl";
	mqd_ctrltop11 = mq_open(ctrltop11, flags_ctrl, PERM, &attr_ctrl);
	check_return(mqd_ctrltop11, ctrltop11, "mq_open");
	mqd_p11toctrl = mq_open(p11toctrl, flags_ctrl, PERM, &attr_ctrl);
	check_return(mqd_p11toctrl, p11toctrl, "mq_open");


	char buffer[2048];
	struct ndpi_iphdr * iph;
	long long int i = 0;
	long long int j = 0;


	/*pthread*/
	struct transfer noti_tran;
	noti_tran.mqd_ctop = mqd_ctrltop11;
	noti_tran.mqd_ptoc = mqd_p11toctrl;
	//noti_tran.mqd_p[0] = mqd_sdtop1;
	noti_tran.qds = 2;
	noti_tran.i[0] = &i;
	noti_tran.i[1] = &j;
	notifysetup(&noti_tran);





	/*
	NODE * g_pRouteTree = createNode();

	int routetable[2] = {0x8000FFFF, 0x0000FFFF};
	int route_i = 0;
	for(route_i = 0;route_i < 2;route_i++) {
		createRouteTree(g_pRouteTree, routetable[route_i], 1, route_i);
		printf("route[%d]:%8X, port:%d\n", route_i, routetable[route_i], route_i);
	}
	createRouteTree(g_pRouteTree, 0, 0, 999);8*/
	
	HASH_TABLE* route[MASK] ;       //route table
    lpmRouteInit(route);    //init route

	u_int32_t nip = 0;

	int port = 0;
	int p_count1 = 0;
	int p_count2 = 0;
	int k = 0;
	while(1) {
		//queue p9top11.
		mq_return = mq_getattr(mqd_p9top11, &q_attr);
		if(mq_return == -1) {
			printf("%s:something wrong happened when mq_getattr p9top11. \n", proname);
			return -1;
		}
		p_count1 = q_attr.mq_curmsgs >= 50?50:q_attr.mq_curmsgs;
		for(k = 0;k < p_count1;k++) {
			mq_return = mq_receive(mqd_p9top11, buffer, 2048, 0);
			if(mq_return == -1) {
				printf("%s:%s receive %lld times fails:%s, errno = %d \n", proname, p9top11, i, strerror(errno), errno);
				return -1;
			}
			iph = (struct ndpi_iphdr *) buffer;
			nip = iph->daddr;
			port = findPort(route, nip);
			if((i + j)%SHOW_FREQUENCY == 0 || (i + j) < SHOW_THRESHOLD) {
				printf("%s:%s i = %lld, packet length = %d, iph->daddr = %8X, port = %d, pid = %d , working on CPU %d \n ", proname, p9top11, i, mq_return, iph->daddr, port, getpid(), getcpu());				
			}
			if(i%CHECKQUEUE_FREQUENCY == 0) {

				checkqueue(mqd_p9top11, p9top11, &noti_tran);//check if the queue is congested and process need to be splited.
			}
			switch(port)
			{
				case 0:
					mq_return = mq_send(mqd_p11top13, (char *) iph, mq_return, 0);
					if(mq_return == -1) {
						printf("%s:%s send %lld times fails:%s, errno = %d \n", proname, p11top13, i, strerror(errno), errno);
						return -1;
					}
					break;
				case 1:
					mq_return = mq_send(mqd_p11top14, (char *) iph, mq_return, 0);
					if(mq_return == -1) {
						printf("%s:%s send %lld times fails:%s, errno = %d \n", proname, p11top14, i, strerror(errno), errno);
						return -1;
					}
					break;
			}
			i++;
		}
		//queue p10top11.
		mq_return = mq_getattr(mqd_p10top11, &q_attr);
		if(mq_return == -1) {
			printf("%s:something wrong happened when mq_getattr p10top11. \n", proname);
			return -1;
		}
		p_count2 = q_attr.mq_curmsgs >= 50?50:q_attr.mq_curmsgs;
		for(k = 0;k < p_count2;k++) {
			mq_return = mq_receive(mqd_p10top11, buffer, 2048, 0);
			if(mq_return == -1) {
				printf("%s:%s receive %lld times fails:%s, errno = %d \n", proname, p10top11, j, strerror(errno), errno);
				return -1;
			}
			iph = (struct ndpi_iphdr *) buffer;
			nip = iph->daddr;
			port = findPort(route, nip);
			if((i + j)%SHOW_FREQUENCY == 0 || (i + j) < SHOW_THRESHOLD) {
				printf("%s:%s j = %lld, packet length = %d, iph->daddr = %8X, port = %d, pid = %d, working on CPU %d \n", proname, p10top11, j, mq_return, iph->daddr, port, getpid(), getcpu());
			}
			if(j%CHECKQUEUE_FREQUENCY == 0) {

				checkqueue(mqd_p10top11, p10top11, &noti_tran);//check if the queue is congested and process need to be splited.
			}
			switch(port)
			{
				case 0:
					mq_return = mq_send(mqd_p11top13, (char *) iph, mq_return, 0);
					if(mq_return == -1) {
						printf("%s:%s send %lld times fails:%s, errno = %d \n", proname, p11top13, i, strerror(errno), errno);
						return -1;
					}
					break;
				case 1:
					mq_return = mq_send(mqd_p11top14, (char *) iph, mq_return, 0);
					if(mq_return == -1) {
						printf("%s:%s send %lld times fails:%s, errno = %d \n", proname, p11top14, i, strerror(errno), errno);
						return -1;
					}
					break;
			}
			j++;
		}
		if(p_count1 || p_count2) {
			continue;
		}
		else {//pretend the process to work when there is nothing in queue.
			usleep(1000);
		}
		
	}

	printf("%s has transfered %lld and %lld packets. \n", proname, i, j);
	checkcpu();


	//p9top11
	mq_return = mq_close(mqd_p9top11);//returns 0 on success, or -1 on error.
	check_return(mq_return, p9top11, "mq_close");
	mq_return = mq_unlink(p9top11);//returns 0 on success, or -1 on error.
	check_return(mq_return, p9top11, "mq_unlink");
	//p10top11
	mq_return = mq_close(mqd_p10top11);//returns 0 on success, or -1 on error.
	check_return(mq_return, p10top11, "mq_close");
	mq_return = mq_unlink(p10top11);//returns 0 on success, or -1 on error.
	check_return(mq_return, p10top11, "mq_unlink");
	
	//p11top13
	mq_return = mq_close(mqd_p11top13);//returns 0 on success, or -1 on error.
	check_return(mq_return, p11top13, "mq_close");
	mq_return = mq_unlink(p11top13);//returns 0 on success, or -1 on error.
	check_return(mq_return, p11top13, "mq_unlink");
	//p11top14
	mq_return = mq_close(mqd_p11top14);//returns 0 on success, or -1 on error.
	check_return(mq_return, p11top14, "mq_close");
	mq_return = mq_unlink(p11top14);//returns 0 on success, or -1 on error.
	check_return(mq_return, p11top14, "mq_unlink");

	//ctrltop11
	mq_return = mq_close(mqd_ctrltop11);//returns 0 on success, or -1 on error.
	check_return(mq_return, ctrltop11, "mq_close");
	mq_return = mq_unlink(ctrltop11);//returns 0 on success, or -1 on error.
	check_return(mq_return, ctrltop11, "mq_unlink");
	//p11toctrl
	mq_return = mq_close(mqd_p11toctrl);//returns 0 on success, or -1 on error.
	check_return(mq_return, p11toctrl, "mq_close");
	mq_return = mq_unlink(p11toctrl);//returns 0 on success, or -1 on error.
	check_return(mq_return, p11toctrl, "mq_unlink");






	exit(0);

}







