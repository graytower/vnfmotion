#include "nfv.h"
#include "fan.h"





int main() {
	/*initialization about mqueue*/
	char proname[] = "p3_l3fwd";
	setcpu(P3_STARTING_CPU);

	struct mq_attr attr, attr_ctrl, q_attr;
	attr.mq_maxmsg = MAXMSG;//maximum is 382.
	attr.mq_msgsize = 2048;
	attr.mq_flags = 0;

	attr_ctrl.mq_maxmsg = MAXMSGCTOP;
	attr_ctrl.mq_msgsize = 2048;
	attr_ctrl.mq_flags = 0;

	int flags = O_CREAT | O_RDWR;
	int flags_ctrl = O_CREAT | O_RDWR | O_NONBLOCK;
	mqd_t mqd_p1top3, mqd_p2top3, mqd_p3top5, mqd_p3top6;
	int mq_return = 0;
	char p1top3[] = "/p1top3";
	char p2top3[] = "/p2top3";
	char p3top5[] = "/p3top5";
	char p3top6[] = "/p3top6";

	/*working processes queues*/
	mqd_p1top3 = mq_open(p1top3, flags, PERM, &attr);
	check_return(mqd_p1top3, p1top3, "mq_open");

	mqd_p2top3 = mq_open(p2top3, flags, PERM, &attr);
	check_return(mqd_p2top3, p2top3, "mq_open");
	
	mqd_p3top5 = mq_open(p3top5, flags, PERM, &attr);
	check_return(mqd_p3top5, p3top5, "mq_open");

	mqd_p3top6 = mq_open(p3top6, flags, PERM, &attr);
	check_return(mqd_p3top6, p3top6, "mq_open");
	
	/*control part*/
	mqd_t mqd_ctrltop3, mqd_p3toctrl;
	char ctrltop3[] = "/ctrltop3";
	char p3toctrl[] = "/p3toctrl";
	mqd_ctrltop3 = mq_open(ctrltop3, flags_ctrl, PERM, &attr_ctrl);
	check_return(mqd_ctrltop3, ctrltop3, "mq_open");
	mqd_p3toctrl = mq_open(p3toctrl, flags_ctrl, PERM, &attr_ctrl);
	check_return(mqd_p3toctrl, p3toctrl, "mq_open");


	char buffer[2048];
	struct ndpi_iphdr * iph;
	long long int i = 0;
	long long int j = 0;


	/*pthread*/
	struct transfer noti_tran;
	noti_tran.mqd_ctop = mqd_ctrltop3;
	noti_tran.mqd_ptoc = mqd_p3toctrl;
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
		//queue p1top3.
		mq_return = mq_getattr(mqd_p1top3, &q_attr);
		if(mq_return == -1) {
			printf("%s:something wrong happened when mq_getattr p1top3. \n", proname);
			return -1;
		}
		p_count1 = q_attr.mq_curmsgs >= 50?50:q_attr.mq_curmsgs;
		for(k = 0;k < p_count1;k++) {
			mq_return = mq_receive(mqd_p1top3, buffer, 2048, 0);
			if(mq_return == -1) {
				printf("%s:%s receive %lld times fails:%s, errno = %d \n", proname, p1top3, i, strerror(errno), errno);
				return -1;
			}
			iph = (struct ndpi_iphdr *) buffer;
			nip = iph->daddr;
			port = findPort(route, nip);
			if((i + j)%SHOW_FREQUENCY == 0 || (i + j) < SHOW_THRESHOLD) {
				printf("%s:%s i = %lld, packet length = %d, iph->daddr = %8X, port = %d, pid = %d , working on CPU %d \n ", proname, p1top3, i, mq_return, iph->daddr, port, getpid(), getcpu());				
			}
			if(i%CHECKQUEUE_FREQUENCY == 0) {

				checkqueue(mqd_p1top3, p1top3, &noti_tran);//check if the queue is congested and process need to be splited.
			}
			switch(port)
			{
				case 0:
					mq_return = mq_send(mqd_p3top5, (char *) iph, mq_return, 0);
					if(mq_return == -1) {
						printf("%s:%s send %lld times fails:%s, errno = %d \n", proname, p3top5, i, strerror(errno), errno);
						return -1;
					}
					break;
				case 1:
					mq_return = mq_send(mqd_p3top6, (char *) iph, mq_return, 0);
					if(mq_return == -1) {
						printf("%s:%s send %lld times fails:%s, errno = %d \n", proname, p3top6, i, strerror(errno), errno);
						return -1;
					}
					break;
			}
			i++;
		}
		//queue p2top3.
		mq_return = mq_getattr(mqd_p2top3, &q_attr);
		if(mq_return == -1) {
			printf("%s:something wrong happened when mq_getattr p2top3. \n", proname);
			return -1;
		}
		p_count2 = q_attr.mq_curmsgs >= 50?50:q_attr.mq_curmsgs;
		for(k = 0;k < p_count2;k++) {
			mq_return = mq_receive(mqd_p2top3, buffer, 2048, 0);
			if(mq_return == -1) {
				printf("%s:%s receive %lld times fails:%s, errno = %d \n", proname, p2top3, j, strerror(errno), errno);
				return -1;
			}
			iph = (struct ndpi_iphdr *) buffer;
			nip = iph->daddr;
			port = findPort(route, nip);
			if((i + j)%SHOW_FREQUENCY == 0 || (i + j) < SHOW_THRESHOLD) {
				printf("%s:%s j = %lld, packet length = %d, iph->daddr = %8X, port = %d, pid = %d, working on CPU %d \n", proname, p2top3, j, mq_return, iph->daddr, port, getpid(), getcpu());
			}
			if(j%CHECKQUEUE_FREQUENCY == 0) {

				checkqueue(mqd_p2top3, p2top3, &noti_tran);//check if the queue is congested and process need to be splited.
			}
			switch(port)
			{
				case 0:
					mq_return = mq_send(mqd_p3top5, (char *) iph, mq_return, 0);
					if(mq_return == -1) {
						printf("%s:%s send %lld times fails:%s, errno = %d \n", proname, p3top5, i, strerror(errno), errno);
						return -1;
					}
					break;
				case 1:
					mq_return = mq_send(mqd_p3top6, (char *) iph, mq_return, 0);
					if(mq_return == -1) {
						printf("%s:%s send %lld times fails:%s, errno = %d \n", proname, p3top6, i, strerror(errno), errno);
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


	//p1top3
	mq_return = mq_close(mqd_p1top3);//returns 0 on success, or -1 on error.
	check_return(mq_return, p1top3, "mq_close");
	mq_return = mq_unlink(p1top3);//returns 0 on success, or -1 on error.
	check_return(mq_return, p1top3, "mq_unlink");
	//p2top3
	mq_return = mq_close(mqd_p2top3);//returns 0 on success, or -1 on error.
	check_return(mq_return, p2top3, "mq_close");
	mq_return = mq_unlink(p2top3);//returns 0 on success, or -1 on error.
	check_return(mq_return, p2top3, "mq_unlink");
	
	//p3top5
	mq_return = mq_close(mqd_p3top5);//returns 0 on success, or -1 on error.
	check_return(mq_return, p3top5, "mq_close");
	mq_return = mq_unlink(p3top5);//returns 0 on success, or -1 on error.
	check_return(mq_return, p3top5, "mq_unlink");
	//p3top6
	mq_return = mq_close(mqd_p3top6);//returns 0 on success, or -1 on error.
	check_return(mq_return, p3top6, "mq_close");
	mq_return = mq_unlink(p3top6);//returns 0 on success, or -1 on error.
	check_return(mq_return, p3top6, "mq_unlink");

	//ctrltop3
	mq_return = mq_close(mqd_ctrltop3);//returns 0 on success, or -1 on error.
	check_return(mq_return, ctrltop3, "mq_close");
	mq_return = mq_unlink(ctrltop3);//returns 0 on success, or -1 on error.
	check_return(mq_return, ctrltop3, "mq_unlink");
	//p3toctrl
	mq_return = mq_close(mqd_p3toctrl);//returns 0 on success, or -1 on error.
	check_return(mq_return, p3toctrl, "mq_close");
	mq_return = mq_unlink(p3toctrl);//returns 0 on success, or -1 on error.
	check_return(mq_return, p3toctrl, "mq_unlink");






	exit(0);

}







