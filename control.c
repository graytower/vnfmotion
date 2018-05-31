#include"nfv.h"
#include"extended_KL.h"
#include"control.h"




int main(void) {
	/*initialization about mqueue*/
	char proname[] = "controller";
	
	#ifdef RUNMODE
	printf("Please not define RUNMODE!!! \n");
	return 1;
	#endif
	
	init_controller();
	int i = 0, j = 0;
	int re_turn_cpu = 0;
	//turn on CPUs
	for(i = 1;i <= LAST_WORKING_CPU;i++) {
		re_turn_cpu = turn_cpu(1, i);
		if(re_turn_cpu) {
			printf("something wrong happened in turn_cpu \n");
			return -1;
		}
	}
	//turn down CPUs
	for(i = LAST_WORKING_CPU + 1;i < PHYSICAL_CPUS;i++) {
		turn_cpu(0, i);
		if(re_turn_cpu) {
			printf("something wrong happened in turn_cpu \n");
			return -1;
		}
	}

	setcpu(CONTROLLER_CPU);
	
	
	struct mq_attr attr_ct;
	attr_ct.mq_maxmsg = MAXMSGCTOP;//maximum is 382.
	attr_ct.mq_msgsize = 2048;
	attr_ct.mq_flags = 0;


	int flags = O_CREAT | O_RDWR | O_NONBLOCK;
	mqd_t mqd_ctop[PROC_NUMBER];
	mqd_t mqd_ptoc[PROC_NUMBER];
	

	int mq_return = 0;
	char ctop[PROC_NUMBER][20];
	char ptoc[PROC_NUMBER][20];
	
	for(i = 0;i < PROC_NUMBER;i++) {
		sprintf(ctop[i], "/ctrltop%d", i);
		sprintf(ptoc[i], "/p%dtoctrl", i);
		mqd_ctop[i] = mq_open(ctop[i], flags, PERM, &attr_ct);
		check_return(mqd_ctop[i], ctop[i], "mq_open");
		mqd_ptoc[i] = mq_open(ptoc[i], flags, PERM, &attr_ct);
		check_return(mqd_ptoc[i], ptoc[i], "mq_open");
	}


	

	
	struct record pstats[PROC_NUMBER];//PROC_NUMBER = 3 defined in control.h.
	printstar();
	for(i = 0;i < PROC_NUMBER;i++) {
		pstats[i].number = i;
		pstats[i].queues = 0;
		pstats[i].cpu = 1;
		pstats[i].cpu_usage = 0.3;
		for(j = 0;j < MAXQUEUES;j++) {
			//pstats[i].queuelength[j] = 0;
			//pstats[i].qmax[j] = MAXMSG;
			pstats[i].i[j] = 0;
			pstats[i].throughput[j] = 0;
		}
		pstats[i].mqd_ctop = mqd_ctop[i];
		pstats[i].mqd_ptoc = mqd_ptoc[i];
	}


	double adj_array[ADJ_ARRAY_EDGES][ADJ_ARRAY_EDGES];
	clear_double_array(ADJ_ARRAY_EDGES, adj_array, "adj_array in control.c first time");
	show_double_array(ADJ_ARRAY_EDGES, adj_array, "adj_array in control.c first time");

	double point_weight[PROC_NUMBER];
	clear_double_series(PROC_NUMBER, point_weight, "point_weight in control.c first time");
	struct ctrltrans noti_p[PROC_NUMBER];
	for(i = 0;i < PROC_NUMBER;i++) {
		for(j = 0;j < PROC_NUMBER;j++) {
			noti_p[i].statistics[j] = &pstats[j];
		}
	}


	for(i = 0;i < PROC_NUMBER;i++) {
		noti_p[i].p_number = i;
		noti_p[i].adj_array = adj_array;
		noti_p[i].point_weight = point_weight;
		ctrl_notifysetup(&noti_p[i]);//pthread
		usleep(5000);//why sleep? wait for notifysetup?
	}


	//char buffer[2048];
	struct ctrlmsg ctrlbuffer;
	ctrlbuffer.cpu = -100;
	ctrlbuffer.service_number = 1;

	printf("everything is ready, controller is going to work!\n");
	sleep(3);
	for(i = 0;i < 1800;i++) {
		for(j = 0;j < PROC_NUMBER;j++) {
			mq_return = mq_send(mqd_ctop[j], (char *) &ctrlbuffer, sizeof(struct ctrlmsg), 0);
			check_return(mq_return, ctop[j], "mq_send in controller");
		
		}
			

		printf("\nLOOP i = %d \n\n", i);
		sleep(UPDATE_PERIOD);

	}



	printstar();
	printf("controller has sent all ctrlmsg. \n");
	for(i = 0;i < PROC_NUMBER;i++) {
		printf("i = %d, pstats[%d].queues = %d \n", i, i, pstats[i].queues);
		for(j = 0;j < pstats[i].queues;j++) {
			printf("pstats[%d].i[%d] = %lld \n", i, j, pstats[i].i[j]);
		}
	}
	printf("Now show CPUs that processes work on. \n");
	int cpu_status[PHYSICAL_CPUS];
	clear_int_series(PHYSICAL_CPUS, cpu_status, "cpu_status");
	for(i = 0;i < PROC_NUMBER;i++) {
		printf("p_number = %d, works on CPU %d \n", i, pstats[i].cpu);
		cpu_status[pstats[i].cpu] += 1;
	}
	show_int_series(PHYSICAL_CPUS, cpu_status, "cpu_status");
	printstar();

	for(i = 0;i < PROC_NUMBER;i++) {
		mq_return = mq_close(mqd_ctop[i]);//returns 0 on success, or -1 on error.
		check_return(mq_return, ctop[i], "mq_close");
		mq_return = mq_unlink(ctop[i]);//returns 0 on success, or -1 on error.
		check_return(mq_return, ctop[i], "mq_unlink");
		
		mq_return = mq_close(mqd_ptoc[i]);//returns 0 on success, or -1 on error.
		check_return(mq_return, ptoc[i], "mq_close");
		mq_return = mq_unlink(ptoc[i]);//returns 0 on success, or -1 on error.
		check_return(mq_return, ptoc[i], "mq_unlink");

	}


	printf("Please remember to use cpuon.sh!!!\n");
	for(i = 1;i < PHYSICAL_CPUS;i++) {
		re_turn_cpu = turn_cpu(1, i);
		if(re_turn_cpu) {
			printf("something wrong happened in turn_cpu \n");
		}
	}

	destroy_controller();
	func_quit(proname);
	return 0;

}


