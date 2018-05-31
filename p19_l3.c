#include "nfv.h"
#include "fan.h"





int main() {
	/*initialization about mqueue*/
	char proname[] = "p19_l3fwd";
	setcpu(P19_STARTING_CPU);

	struct mq_attr attr, attr_ctrl, q_attr;
	attr.mq_maxmsg = MAXMSG;//maximum is 382.
	attr.mq_msgsize = 2048;
	attr.mq_flags = 0;

	attr_ctrl.mq_maxmsg = MAXMSGCTOP;
	attr_ctrl.mq_msgsize = 2048;
	attr_ctrl.mq_flags = 0;

	int flags = O_CREAT | O_RDWR;
	int flags_ctrl = O_CREAT | O_RDWR | O_NONBLOCK;
	mqd_t mqd_p17top19, mqd_p18top19, mqd_p19top21, mqd_p19top22;
	int mq_return = 0;
	char p17top19[] = "/p17top19";
	char p18top19[] = "/p18top19";
	char p19top21[] = "/p19top21";
	char p19top22[] = "/p19top22";

	/*working processes queues*/
	mqd_p17top19 = mq_open(p17top19, flags, PERM, &attr);
	check_return(mqd_p17top19, p17top19, "mq_open");

	mqd_p18top19 = mq_open(p18top19, flags, PERM, &attr);
	check_return(mqd_p18top19, p18top19, "mq_open");
	
	mqd_p19top21 = mq_open(p19top21, flags, PERM, &attr);
	check_return(mqd_p19top21, p19top21, "mq_open");

	mqd_p19top22 = mq_open(p19top22, flags, PERM, &attr);
	check_return(mqd_p19top22, p19top22, "mq_open");
	
	/*control part*/
	mqd_t mqd_ctrltop19, mqd_p19toctrl;
	char ctrltop19[] = "/ctrltop19";
	char p19toctrl[] = "/p19toctrl";
	mqd_ctrltop19 = mq_open(ctrltop19, flags_ctrl, PERM, &attr_ctrl);
	check_return(mqd_ctrltop19, ctrltop19, "mq_open");
	mqd_p19toctrl = mq_open(p19toctrl, flags_ctrl, PERM, &attr_ctrl);
	check_return(mqd_p19toctrl, p19toctrl, "mq_open");


	char buffer[2048];
	struct ndpi_iphdr * iph;
	long long int i = 0;
	long long int j = 0;


	/*pthread*/
	struct transfer noti_tran;
	noti_tran.mqd_ctop = mqd_ctrltop19;
	noti_tran.mqd_ptoc = mqd_p19toctrl;
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
		//queue p17top19.
		mq_return = mq_getattr(mqd_p17top19, &q_attr);
		if(mq_return == -1) {
			printf("%s:something wrong happened when mq_getattr p17top19. \n", proname);
			return -1;
		}
		p_count1 = q_attr.mq_curmsgs >= 50?50:q_attr.mq_curmsgs;
		for(k = 0;k < p_count1;k++) {
			mq_return = mq_receive(mqd_p17top19, buffer, 2048, 0);
			if(mq_return == -1) {
				printf("%s:%s receive %lld times fails:%s, errno = %d \n", proname, p17top19, i, strerror(errno), errno);
				return -1;
			}
			iph = (struct ndpi_iphdr *) buffer;
			nip = iph->daddr;
			port = findPort(route, nip);
			if((i + j)%SHOW_FREQUENCY == 0 || (i + j) < SHOW_THRESHOLD) {
				printf("%s:%s i = %lld, packet length = %d, iph->daddr = %8X, port = %d, pid = %d , working on CPU %d \n ", proname, p17top19, i, mq_return, iph->daddr, port, getpid(), getcpu());				
			}
			if(i%CHECKQUEUE_FREQUENCY == 0) {

				checkqueue(mqd_p17top19, p17top19, &noti_tran);//check if the queue is congested and process need to be splited.
			}
			switch(port)
			{
				case 0:
					mq_return = mq_send(mqd_p19top21, (char *) iph, mq_return, 0);
					if(mq_return == -1) {
						printf("%s:%s send %lld times fails:%s, errno = %d \n", proname, p19top21, i, strerror(errno), errno);
						return -1;
					}
					break;
				case 1:
					mq_return = mq_send(mqd_p19top22, (char *) iph, mq_return, 0);
					if(mq_return == -1) {
						printf("%s:%s send %lld times fails:%s, errno = %d \n", proname, p19top22, i, strerror(errno), errno);
						return -1;
					}
					break;
			}
			i++;
		}
		//queue p18top19.
		mq_return = mq_getattr(mqd_p18top19, &q_attr);
		if(mq_return == -1) {
			printf("%s:something wrong happened when mq_getattr p18top19. \n", proname);
			return -1;
		}
		p_count2 = q_attr.mq_curmsgs >= 50?50:q_attr.mq_curmsgs;
		for(k = 0;k < p_count2;k++) {
			mq_return = mq_receive(mqd_p18top19, buffer, 2048, 0);
			if(mq_return == -1) {
				printf("%s:%s receive %lld times fails:%s, errno = %d \n", proname, p18top19, j, strerror(errno), errno);
				return -1;
			}
			iph = (struct ndpi_iphdr *) buffer;
			nip = iph->daddr;
			port = findPort(route, nip);
			if((i + j)%SHOW_FREQUENCY == 0 || (i + j) < SHOW_THRESHOLD) {
				printf("%s:%s j = %lld, packet length = %d, iph->daddr = %8X, port = %d, pid = %d, working on CPU %d \n", proname, p18top19, j, mq_return, iph->daddr, port, getpid(), getcpu());
			}
			if(j%CHECKQUEUE_FREQUENCY == 0) {

				checkqueue(mqd_p18top19, p18top19, &noti_tran);//check if the queue is congested and process need to be splited.
			}
			switch(port)
			{
				case 0:
					mq_return = mq_send(mqd_p19top21, (char *) iph, mq_return, 0);
					if(mq_return == -1) {
						printf("%s:%s send %lld times fails:%s, errno = %d \n", proname, p19top21, i, strerror(errno), errno);
						return -1;
					}
					break;
				case 1:
					mq_return = mq_send(mqd_p19top22, (char *) iph, mq_return, 0);
					if(mq_return == -1) {
						printf("%s:%s send %lld times fails:%s, errno = %d \n", proname, p19top22, i, strerror(errno), errno);
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


	//p17top19
	mq_return = mq_close(mqd_p17top19);//returns 0 on success, or -1 on error.
	check_return(mq_return, p17top19, "mq_close");
	mq_return = mq_unlink(p17top19);//returns 0 on success, or -1 on error.
	check_return(mq_return, p17top19, "mq_unlink");
	//p18top19
	mq_return = mq_close(mqd_p18top19);//returns 0 on success, or -1 on error.
	check_return(mq_return, p18top19, "mq_close");
	mq_return = mq_unlink(p18top19);//returns 0 on success, or -1 on error.
	check_return(mq_return, p18top19, "mq_unlink");
	
	//p19top21
	mq_return = mq_close(mqd_p19top21);//returns 0 on success, or -1 on error.
	check_return(mq_return, p19top21, "mq_close");
	mq_return = mq_unlink(p19top21);//returns 0 on success, or -1 on error.
	check_return(mq_return, p19top21, "mq_unlink");
	//p19top22
	mq_return = mq_close(mqd_p19top22);//returns 0 on success, or -1 on error.
	check_return(mq_return, p19top22, "mq_close");
	mq_return = mq_unlink(p19top22);//returns 0 on success, or -1 on error.
	check_return(mq_return, p19top22, "mq_unlink");

	//ctrltop19
	mq_return = mq_close(mqd_ctrltop19);//returns 0 on success, or -1 on error.
	check_return(mq_return, ctrltop19, "mq_close");
	mq_return = mq_unlink(ctrltop19);//returns 0 on success, or -1 on error.
	check_return(mq_return, ctrltop19, "mq_unlink");
	//p19toctrl
	mq_return = mq_close(mqd_p19toctrl);//returns 0 on success, or -1 on error.
	check_return(mq_return, p19toctrl, "mq_close");
	mq_return = mq_unlink(p19toctrl);//returns 0 on success, or -1 on error.
	check_return(mq_return, p19toctrl, "mq_unlink");






	exit(0);

}







