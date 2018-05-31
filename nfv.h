#ifndef	NFV_H
#define	NFV_H

#define _GNU_SOURCE

#include<stdio.h>//printf()
#include<unistd.h>//fork() sleep() getpid()
#include<sys/types.h>//fork() getpid()
#include<stdlib.h>//malloc(), calloc()
#include<mqueue.h>
#include<sys/stat.h>//for mode constants---mq_open()
#include<fcntl.h>//for O_* constants---mq_open()
#include<string.h>//perror()
#include<errno.h>//errno
#include<signal.h>//union signal, struct sigevent, sigset_t
#include<pthread.h>//pthread
#include<sys/resource.h>//rlimit
#include<sched.h>//sched_setaffinity
#include<sys/time.h>//for timeval


/***Look at here, the RUNMODE is here!!!***/
//#define RUNMODE 1//if define RUNMODE, setcpu() will not work.

#define PRINTMODE 1//if define PRINTMODE, successful printf will not work.

//#define CPUS 4//should be change to 4/1!!!!!!!!!!!!!!!!!!!!!!!!!

#define PHYSICAL_CPUS 40//should be change to 40/4!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

//#define CORES_PER_CPU 10//should be changed to 10/4!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

#define PERM 0766//the authority of m_queue.

#define PACKETS 50000000//the number of packets that we will send.

#define MAXMSG 2000//the stable number of mq_attr.mq_maxmsg. 300 is available.

#define MAXMSGCTOP 10//the queue from controller to process .

#define MAXQUEUES 3//the maximum queues we will use.

#define QUEUERATIO 0.8//the ratio of queue needed to report.

#define CHECKQUEUE_ALPHA 0.5//alpha in checkqueue ratio = alpha * q_ratio_old + (1 - alpha) * q_ratio_now.

#define SHOW_FREQUENCY 100000

#define SHOW_THRESHOLD 0

#define SEND_SHOW_FREQUENCY  500000

#define START_TIME	5000000

#define END_TIME	15000000

#define SEND_SLEEP_FREQUENCY	1

#define SEND_SLEEP_TIME	10

#define CHECKQUEUE_FREQUENCY 1000


#define FIRST_WORKING_CPU 6

#define LAST_WORKING_CPU 35

#define CONTROLLER_CPU 0
////////////////////////////////
#define SEND0_CPU 1

#define SEND1_CPU 2

#define SEND2_CPU 3

#define SEND3_CPU 4

#define SEND4_CPU 5

#define P0_STARTING_CPU 6

#define P1_STARTING_CPU 7

#define P2_STARTING_CPU 7

#define P3_STARTING_CPU 8

#define P4_STARTING_CPU 9

#define P5_STARTING_CPU 10

#define P6_STARTING_CPU 11

#define P7_STARTING_CPU 11
/////////////////////////////////


#define P8_STARTING_CPU 12

#define P9_STARTING_CPU 13

#define P10_STARTING_CPU 13

#define P11_STARTING_CPU 14

#define P12_STARTING_CPU 15

#define P13_STARTING_CPU 16

#define P14_STARTING_CPU 17

#define P15_STARTING_CPU 17
////////////////////////////////


#define P16_STARTING_CPU 18

#define P17_STARTING_CPU 19

#define P18_STARTING_CPU 19

#define P19_STARTING_CPU 20

#define P20_STARTING_CPU 21

#define P21_STARTING_CPU 22

#define P22_STARTING_CPU 23

#define P23_STARTING_CPU 23
////////////////////////////////


#define P24_STARTING_CPU 24

#define P25_STARTING_CPU 25

#define P26_STARTING_CPU 25

#define P27_STARTING_CPU 26

#define P28_STARTING_CPU 27

#define P29_STARTING_CPU 28

#define P30_STARTING_CPU 29

#define P31_STARTING_CPU 29
////////////////////////////////


#define P32_STARTING_CPU 30

#define P33_STARTING_CPU 31

#define P34_STARTING_CPU 31

#define P35_STARTING_CPU 32

#define P36_STARTING_CPU 33

#define P37_STARTING_CPU 34

#define P38_STARTING_CPU 35

#define P39_STARTING_CPU 35





struct transfer {//this needs to be global struct.
	mqd_t mqd_ctop;//queue from controlloer to process.
	mqd_t mqd_ptoc;//queue from process to controller.
	//mqd_t mqd_p[MAXQUEUES];//queue with other processes.
	int qds;//the number of queues that process receives from other processes.
	long long int *i[MAXQUEUES];
};



struct ctrlmsg {
	long service_number;/*	1:the controller asks processes to report message about themselves.
				2:the answer message about vertex sent by processes.
				3:the control message that controller sends.
				4:the urgent message that process sends to controller that the process needs a new cpu immediately.
				
				5:the controller tells process to be quiet that it is already using up a CPU alone, controller can do nothing more.!!!!!!we may debate this later.
				n:the processes send to controller to tell that the process has finished all work and controller could free the queues between them. */
	pid_t pid_in_ctrlmsg;//the pid of process
	int cpu;//the cpu where the process runs on or the controller wants it to run on
	int edges;//the amount of edges who go into the vertex
	
	long qsize[MAXQUEUES];//the current packets in every queue received by process.
	long qmaxsize[MAXQUEUES];//the max packets in every queu received by process.
	
	long long int i[MAXQUEUES];//the packets that passed queue between 2 updates.
};

struct cpu_sta {//use the struct to avoid freeing space by calloc(). 
	int cpu[PHYSICAL_CPUS];
};




void func_quit(char * proname);//show message that function quits.

void check_return(int return_value, char * proname, char * function_name);//check the return value of mq_* functions

void notifysetup(struct transfer * trans);//set the mq_notify up which is used for first setup or in process_control function.

void process_control(union sigval sv);//processes use notifysetup to set this function to process the control message from controller.

int setcpu(int cpu_id);//set the process to work on cpu 'cpu_id'.

int getcpu();//get the cpu where the process is working on.

struct cpu_sta checkcpu();//check which CPUs the process can run on.

void printstar();//print a line of stars, '************'.
void printnewline();//print a new line with nothing.


void printerror();//print "you should not see this line. Please debug your code!!!"

void checkqueue(mqd_t mqd, char * qname, struct transfer * parameter);//if queue is busy will use process_report to tell 

void process_report(int service_type, struct transfer * parameter);//process use the function to report the status to controller.

void func_quit(char * proname) {//show message that function quits.
	printf("*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*\n");
	printf("*!*!*!*!*!*!*!* %s quits! *!*!*!*!*!*!*!*\n", proname);
	printf("*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*!*\n");
}



void check_return(int return_value, char * proname, char * function_name) {
	if(return_value == -1) {
		printf("%s: %s fails: %s, errno = %d. \n", proname, function_name, strerror(errno), errno);
		if(strncmp(function_name, "mq_open", 7) == 0) {
			printf("******************************************\n");
			printf("***mq_oepn failed in %s !***\n", proname);
			printf("******************************************\n");
			exit(0);
		}
		return;
	}
	else if(strncmp(function_name, "mq_receive", 10) == 0) {//so we can input "mq_receive blabla"
		if(return_value > 0) {
			#ifndef PRINTMODE
			printf("%s: %s receives %d bytes succesfully. \n", proname, function_name, return_value);
			#endif
		}
		else {//return_value == 0
			printf("return_value == 0, something is wrong in %s in %s \n", function_name, proname);
		}
		return;
	}
	else if((return_value > 0) && (strncmp(function_name, "mq_open", 7) == 0)) {//so we can input "mq_open blabla"
		#ifndef PRINTMODE
		printf("%s: %s succeeds, mqd_t = %d. \n", proname, function_name, return_value);
		#endif
		return;
	}
	else if(return_value == 0) {
		/*if(strlen(function_name)) {
			printf("%s: %s succeeds. \n", proname, function_name);
		}*/
		return;
	}
	else {
		printf("WARNING!!!WARNING!!!WARNING!!!\nThere is an abnormal condition in check_return needed to be set!!!Please debug!!!\n");
		printf("return_value = %d, fucntion_name = %s, happened in pro %s \n",return_value, function_name, proname);
		printf("WARNING!!!WARNING!!!WARNING!!!\n");
		exit(0);
	}
	return;
}


void notifysetup(struct transfer * trans) {//set the mq_notify up which is used for first setup or in process_control function.
	int mq_return = 0;
	struct sigevent mq_notification;

	char funcname[] = "notifysetup";

	#ifndef PRINTMODE
	printstar();
	printf("now in %s, trans->mqd_ctop = %d \n", funcname, trans->mqd_ctop);
	#endif
	mq_notification.sigev_notify = SIGEV_THREAD;
	mq_notification.sigev_notify_function = process_control;
	mq_notification.sigev_notify_attributes = NULL;
	mq_notification.sigev_value.sival_ptr = trans;


	mq_return = mq_notify(trans->mqd_ctop, &mq_notification);
	check_return(mq_return, funcname, "mq_notify in notifysetup");
	//printstar();
	return;
}

void process_control(union sigval sv) {//processes use notifysetup to set this function to process the control message from controller.
	struct transfer * parameter;
	parameter = (struct transfer *) sv.sival_ptr;
	int func_re;
	char ptname[] = "process_control";

	#ifndef PRINTMODE
	printstar();
	printf("Now in %s \n", ptname);
	#endif

	struct mq_attr rc_mq_attr;
	mq_getattr(parameter->mqd_ctop, &rc_mq_attr);

	struct ctrlmsg ctrlbuffer;/*, up_ctrlmsg*/
	struct ctrlmsg * ctrlbufferp;
	char msg_buffer[rc_mq_attr.mq_msgsize];
	#ifndef PRINTMODE
	printf("msg_buffer size is %lu \n", sizeof(msg_buffer));
	printf("parameter->mqd_ctop = %d \n", parameter->mqd_ctop);
	printf("%s is working in pid %d, cpu %d\n", ptname, getpid(), getcpu());
	#endif

	notifysetup(parameter);

	while ((func_re = mq_receive(parameter->mqd_ctop, msg_buffer, rc_mq_attr.mq_msgsize, 0)) >= 0) {
		check_return(func_re, ptname, "mq_receive");
		ctrlbufferp = (struct ctrlmsg *) msg_buffer;
		ctrlbuffer = *ctrlbufferp;
		#ifndef PRINTMODE
		printf("%s received ctrlbuffer.service_number is %ld \n", ptname, ctrlbuffer.service_number);
		#endif
	}

//	check_return(func_re, ptname, "mq_receive enough");
	if (errno != EAGAIN) {//in nonblock mode, "errno = EAGAIN" means that there is no message in queue.	EAGAIN = 11
		check_return(func_re, ptname, "mq_receive");
		printstar();
		printstar();
		printstar();
		printf("mq_receive exits unnormally!!!!!!!!!!!!!!!!!!!!\n");
		printstar();
		printstar();
		printstar();
		exit(0);/* Unexpected error */
	}

	#ifndef PRINTMODE
	printstar();
	#endif

	switch(ctrlbuffer.service_number)
	{
		case 1:
/*			printf("process received ctrlmsg.service_number = 1 \n");
			up_ctrlmsg.cpu = getcpu();
			up_ctrlmsg.edges = parameter->qds;
			int i_edges = 0;
			for(i_edges = 0;i_edges < up_ctrlmsg.edges;i_edges++) {
				mq_getattr(parameter->mqd_p[i_edges], &q_mq_attr);
				up_ctrlmsg.qsize[i_edges] = q_mq_attr.mq_curmsgs;
				up_ctrlmsg.qmaxsize[i_edges] = q_mq_attr.mq_maxmsg;
			}
			func_re = mq_send(parameter->mqd_ptoc, (char *) &up_ctrlmsg, sizeof(struct ctrlmsg), 0);
			check_return(func_re, ptname, "mq_send");*/
			process_report(2, parameter);

			break;//we will process this later
		case 3:
			#ifndef PRINTMODE
			printf("process is working on CPU%d before set to CPU%d \n", getcpu(), ctrlbuffer.cpu);
			checkcpu();
			#endif
			setcpu(ctrlbuffer.cpu);
			#ifndef PRINTMODE
			printf("process has been set on CPU%d \n", getcpu());
			checkcpu();
			#endif
			break;
	}
	#ifndef PRINTMODE
	printf("finish a process control \n");
	printstar();
	#endif
	pthread_exit(NULL);
}



int setcpu(int cpu_id) {//set the process to work on cpu 'cpu_id'.
	#ifdef RUNMODE
	return -1;
	#endif
	#ifndef PRINTMODE
	printf("setcpu's pid is %d, set to CPU %d \n", getpid(), cpu_id);
	#endif
	cpu_set_t mask;
	CPU_ZERO(&mask);
	CPU_SET(cpu_id, &mask);
	CPU_SET(cpu_id + PHYSICAL_CPUS, &mask);
	int check;
	check = sched_setaffinity(getpid(), sizeof(mask), &mask);
	check_return(check, "setcpu", "sched_setaffinity");
	//checkcpu();
	//printf("after setcpu cpu = %d \n", getcpu());
	return 0;
}//  set cpu affinity



int getcpu() {//get the cpu where the process is working on.
	#ifdef RUNMODE
	return 999;
	#endif

	//printf("getcpu's pid is %d\n", getpid());
	char func_name[] = "getcpu";
	int func_return = 0;
	cpu_set_t set;
	CPU_ZERO(&set);
	func_return = sched_getaffinity(getpid(), sizeof(cpu_set_t), &set);
	check_return(func_return, func_name, "sched_getaffinity");
	int i = 0;
	//int j = 0;
	int cpunow = -1;
	int test_cpu = 0;
	int count = 0;
	for(i = 0;i < PHYSICAL_CPUS;i++) {
		test_cpu = CPU_ISSET(i, &set);
		if(test_cpu != 0) {
			cpunow = i;
			count++;
		}
	}
	//printf("\n");
	if(count == 1) {
		return cpunow;
	}
	else if(count > 1) {
		//printf("count = %d, there are more than one CPUs being used!\n", count);
		return -1000;//there is more than one physical cpu being used.
	}
	//count == 0
	//printf("count = %d, something wrong!\n", count);
	else return -1;//something wrong.
}

struct cpu_sta checkcpu() {////check which CPUs the process can run on.
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	int func_re = 0;
	func_re = sched_getaffinity(getpid(), sizeof(cpu_set_t), &cpuset);
	check_return(func_re, "checkcpu", "sched_getaffinity");
	int i = 0;
	int test_cpu = 0;
	struct cpu_sta statistics;
	for(i = 0;i < PHYSICAL_CPUS * 2;i++) {
		test_cpu = CPU_ISSET(i, &cpuset);
		if(test_cpu != 0) {
			printf("test_cpu = %d, process can work on CPU %d\n", test_cpu, i);
			statistics.cpu[i] = 1;
		}
		else {
			printf("test_cpu = %d, process can't work on CPU %d\n", test_cpu, i);
			statistics.cpu[i] = 0;
		}
	}
	return statistics;
}

void printstar(void) {
	printf("******************************************\n");\
	return;
}

void printnewline(void) {
	printf("\n");
	return;
}

void printerror(void) {
	printf("you should not see this line. Please debug your code!!!\n");
	return;
}

void checkqueue(mqd_t mqd, char * qname, struct transfer * parameter) {//return 1 when queue is busy or return 0.
	char proname[] = "checkqueue";
	struct mq_attr q_attr;
	static long Lold = 0;
	static long Lnow = 0;
	static struct timeval time_old = {0, 0};
	static struct timeval time_now = {0, 0};

	int func_re;
	func_re = mq_getattr(mqd, &q_attr);
	check_return(func_re, proname, "mq_getattr");

	Lnow = q_attr.mq_curmsgs;
	double ratio = 0;
	ratio = CHECKQUEUE_ALPHA * ((double) Lold/ (double) q_attr.mq_maxmsg) + (1 - CHECKQUEUE_ALPHA) * ((double) Lnow/ (double) q_attr.mq_maxmsg);
	
	if(ratio > QUEUERATIO) {
		gettimeofday(&time_now, 0);
		if((time_now.tv_usec - time_old.tv_usec) + 1000000 * (time_now.tv_sec - time_old.tv_sec) >= 1000000) {
			#ifndef PRINTMODE
			printf("%s has been congested and need to be splited!!!\n", qname);
			#endif
			process_report(4, parameter);
			time_old = time_now;
		}
		else {
			#ifndef PRINTMODE
			printf("%s has been congested and need to be splited!!!\n", qname);
			printf("But it's too early to send urgent msg again, wait for a moment and try again!!!\n");
			#endif
		}
	}//else mqueue is alright, there is nothing need to be done.
	Lold = Lnow;
	return;
}

void process_report(int service_type, struct transfer * parameter) {
	char funcname[] = "process_report";
	struct ctrlmsg up_ctrlmsg;
	//struct mq_attr q_mq_attr;
	int func_re = 0;
	if((service_type == 2)||(service_type == 4)) {
		up_ctrlmsg.service_number = service_type;
		#ifndef PRINTMODE
		checkcpu();
		#endif
		up_ctrlmsg.cpu = getcpu();
		up_ctrlmsg.edges = parameter->qds;
		up_ctrlmsg.pid_in_ctrlmsg = getpid();
		int i_edges = 0;
		for(i_edges = 0;i_edges < up_ctrlmsg.edges;i_edges++) {
			//mq_getattr(parameter->mqd_p[i_edges], &q_mq_attr);
			//up_ctrlmsg.qsize[i_edges] = q_mq_attr.mq_curmsgs;
			//up_ctrlmsg.qmaxsize[i_edges] = q_mq_attr.mq_maxmsg;
			up_ctrlmsg.i[i_edges] = *(parameter->i[i_edges]);
		}
		func_re = mq_send(parameter->mqd_ptoc, (char *) &up_ctrlmsg, sizeof(struct ctrlmsg), 0);
		check_return(func_re, funcname, "mq_send");
	}
	else {
		printstar();
		printf("service_type = %d is wrong!!!\n", service_type);
		printstar();
	}
	return;
}

#endif
