#ifndef FAN_H
#define FAN_H
#include <stdlib.h> 
#include <stdio.h>
#include "../posix/ndpi_api.h" //iphdr
#include <string.h> 
#include <pcap.h>
#include <assert.h>
/////////////////////////////////////////////
#define	MAX_NDPI_FLOWS     20000000

#define GTP_U_V1_PORT        2152

#define DBG_PRINT if(1 == g_ulDbgPrint) printf
//uint32_t lenth in char*
#define STRLEN 15
//hash bucket
#define DICLEN 50
//MASK lenth
#define MASK 32

////////rand
# define M_PI        3.14159265358979323846

# define MAX_N 3000   /*这个值为N可以定义的最大长度*/
# define RAND_N 100        /*产生随机序列的点数，注意不要大于MAX_N*/

# define RAND_MAX 2147483647

# define MAX_DELAY 100
# define MIN_DELAY 0
# define DELAY_CHANGE_FREQ 5000000 //pkts

//#define PRINT    // vnf print when defined

int g_ulDbgPrint = 0;

static struct ndpi_detection_module_struct *ndpi_struct = NULL;  //检测模块	
static struct ndpi_flow *ndpi_flows_root = NULL;  //流表根

static struct ndpi_flow *acl_root = NULL;  //ACL根

static u_int32_t detection_tick_resolution = 1000;

static u_int32_t size_id_struct = 0;

static u_int32_t size_flow_struct = 0;

static u_int16_t decode_tunnels = 0;

static u_int64_t protocol_counter[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
static u_int64_t protocol_counter_bytes[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
static u_int32_t protocol_flows[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1] = { 0 };

static char *_protoFilePath = NULL;

static u_int64_t raw_packet_count = 0;
static u_int64_t total_bytes = 0;
static u_int32_t ndpi_flow_count = 0;
static u_int64_t ip_packet_count = 0;

static u_int64_t acl_count = 0;   //firewall

float map[10] = {1, 1, 1, 1, 1, 0.01, 0.01, 0.01, 0.01, 0.01}; //randgen比例分布

float wave[8] = {1, 10, 100, 300, 1000, 300, 100, 10}; //wave shape for send
////////////////////////////////rand gen/////////////
float gendelay(float top, float btm){//generate delay
	int temp;
	struct timeval stime;
	unsigned seed;
	gettimeofday(&stime, NULL);
	seed=stime.tv_sec*stime.tv_usec;
	srand(seed);//gen new seed

	float btot = top - btm;
	float ration = btot;

	temp = rand();
	
	temp = (int)10*(temp/(RAND_MAX+1.0));	//0-9
	
	float delay = btm + map[temp]*ration;
	

	return delay;
}
/////////////////////////////////////wave gen/////////////
int genSleepFreq(i, change_freq){
	int n = i/change_freq;  //CHANGE_FREQ
	return wave[n%8];
}

////hash ///////////////////////////new l3////////////////////
typedef char* TYPE;

typedef struct _NODE{
    TYPE data;
    int port;
    struct _NODE* next;
}NODE;

typedef struct _HASH_TABLE{
    NODE* phead;           //此变量可以不用，这里使用是为了减少其他函数中的重新定义过程
    NODE** chainhash;
}HASH_TABLE;

int maxdepth = 0;

//hash algo
unsigned int BKDRhash(TYPE key)
{//BKDRhash函数
    unsigned int seed = 131;
    unsigned int hash = 0;

    while(*key != '\n' && *key != 0)      //通常使用时，判别条件为*key != 0即可，此处的*key != '\n'是因笔者程序需要
        hash = hash * seed + (*key++);

    return hash % DICLEN;
}

//creat
NODE* create_node()
{//开辟节点
    NODE* pnode = (NODE*)malloc(sizeof(NODE));
    memset(pnode, 0, sizeof(NODE));

    pnode->data = (char*)malloc(STRLEN * sizeof(char));
    memset(pnode->data, 0, STRLEN * sizeof(char));
    pnode->next = NULL;
    pnode->port = -1;

    return pnode;
}

HASH_TABLE* create_hash()
{//创建hash表
    HASH_TABLE* new_hash_table = (HASH_TABLE*)malloc(sizeof(HASH_TABLE));
    memset(new_hash_table, 0, sizeof(HASH_TABLE));

    new_hash_table->phead = create_node();
    new_hash_table->chainhash = (NODE**)malloc(DICLEN * sizeof(NODE*));

	int i = 0;
    for(i = 0; i < DICLEN; i++){
        new_hash_table->chainhash[i] = (NODE*)malloc(sizeof(NODE));
        memset(new_hash_table->chainhash[i], 0, sizeof(NODE));
        new_hash_table->chainhash[i]->data = "";
        new_hash_table->chainhash[i]->next = NULL;
        new_hash_table->chainhash[i]->port = -1;
    }

    return new_hash_table;
}




//insert NODE
int insert_data(HASH_TABLE* hash, NODE* phead, TYPE data, int port)
{//插入新数据
    if(hash == NULL)
        return -1;
    int depth = 0; //chainhash depth
    //printf("hash: %d, DICLEN: %d \n", BKDRhash(data), DICLEN);

    if(hash->chainhash[BKDRhash(data)]->data == NULL){
        NODE* newnode = create_node();

        strcpy(newnode->data, data);
        newnode->next = NULL;
        newnode->port = port;
        hash->chainhash[BKDRhash(data)]->data = newnode->data;
        hash->chainhash[BKDRhash(data)]->next = newnode->next;
        hash->chainhash[BKDRhash(data)]->port = newnode->port;
        depth += 1;//chainhash depth
        free(newnode);
        maxdepth = (depth>=maxdepth)?depth:maxdepth;
        return 0;
    }

    else{
        phead = hash->chainhash[BKDRhash(data)];
        depth += 1;
        while(phead->next != NULL){
            phead = phead->next;
            depth += 1;
        }
        phead->next = create_node();

        strcpy(phead->next->data, data);
        phead->next->next = NULL;
        phead->next->port = port;
        maxdepth = (depth>=maxdepth)?depth:maxdepth;
        return 0;
    }
}


//find NODE
NODE* find_data(HASH_TABLE* hash, NODE* phead, TYPE data)
{//查找数据

    phead = hash->chainhash[BKDRhash(data)];

    if(hash == NULL)
        return NULL;

    while(phead != NULL){

        if(strncmp(phead->data, data, STRLEN) == 0)
            return phead;
        else
            phead = phead->next;
    }

    return NULL;
}




void int2str(u_int32_t i, char *s) {
    sprintf(s,"%u\n",i);
}

static u_int32_t power (u_int32_t bottom, u_int32_t times){//power
    u_int32_t res = 1;
    if(times == 0) {
        return 1;
    }
    int i = 0;
    for(i = 0; i < times; i++)
        res = res*bottom;
    return res;
}


u_int32_t lpmMask(int ilenth){
    u_int32_t lenth = (u_int32_t)ilenth;
    u_int32_t nmask = 32-lenth;
    u_int32_t mask = 0;
    u_int32_t intmask;
    intmask = power(2, nmask);
    mask = ~(intmask - 1);
    return mask;
}


int lpmRouteInit(HASH_TABLE** route){
	int i = 0;
    for(i = 0; i < MASK; i++){      //route init
        route[i] = create_hash();
        assert(route[i] != NULL);
    }

    char data[STRLEN + 2] = {0};
    FILE* fp = fopen("dics.txt", "r+");
    assert(fp != 0);
    i = 0;
    while(i < DICLEN){
        fgets(data, STRLEN + 2, fp);
        u_int32_t routenIp = (u_int32_t)atoi(data);  //char* to int
        u_int32_t routeIp = ntohl(routenIp);

        //printf("%u string %s",routeip, data);       //data end with \n
        u_int32_t mask = lpmMask((i%16)+17);       //lpm: i%MASK   --  i%MASK+1
        u_int32_t maskedRoute = routeIp&mask;   //mask
        int2str(maskedRoute, data);
        //printf("%u string %s",maskedRoute, data);       //data end with \n
		int port = -1; 
		if(i == 18)
			port = 0;
		else
			port = 1;
        insert_data(route[i%16+16], route[i%16+16]->phead, data, port);      //insert route data(with mask)
        i++;
    }
    fclose(fp);
    return 0;
}

int findPort(HASH_TABLE** route, u_int32_t nip){
    u_int32_t ip = ntohl(nip);   //host ip
    char testdata[12] = {0};
    int2str(ip, testdata);

    int outPort = -1;
    int i = 0;
    for(i = 32; i > 0; i--){
        NODE* target = NULL;
        u_int32_t mask = lpmMask(i);
        u_int32_t maskedIp = ip&mask;
        int2str(maskedIp, testdata);
        //printf("%u string %s",maskedIp, testdata);

        target = find_data(route[i-1], route[i-1]->phead, testdata);

        if(target != NULL){
            //printf("masked: %s, target: %s\n", testdata, target->data);
            //printf("find it in route[%d]\n", i-1);
            outPort = target->port;
            //printf("port/num = %d\n", outPort);
            break;
        }else{
            //printf("not in route[%d]\n", i);
        }
    }
    if(outPort == -1){
        //printf("not in route, defaule route 1\n");
        outPort = 1;      //default route
    }
    return outPort;
}
/////////////////////////////////////////////
/*
//路由表元素节点
typedef struct node {
    struct node *pLeftChild;
    struct node *pRightChild;
    int iPort;
}NODE;

//路由表root


NODE *createNode();

void createRouteTree(NODE * g_pRouteTree, int iRoute, int iMask, int iPort);

int getIpFwdPort(NODE * g_pRouteTree, int iIp);

//'创建节点'函数
NODE *createNode() {
    NODE *pNode = malloc(sizeof(NODE));
    pNode->pLeftChild = NULL;
    pNode->pRightChild = NULL;
    pNode->iPort = -1;
    return pNode;
}

//'创建路由表'函数
void createRouteTree(NODE * g_pRouteTree, int iRoute, int iMask, int iPort) {
    int i = 0;
    // 0 -- left, 1 -- right
    int iLeftOrRight = 0;
    
    if (g_pRouteTree == NULL) {
        g_pRouteTree = createNode();
	printf("createRouteTree create the root node \n");
    }
    
    DBG_PRINT("input rounte: %8x, mask: %d, port: %d\n", iRoute, iMask, iPort);

    NODE *pCurrNode = g_pRouteTree;
    for (i = 0; i < iMask; i++) {
        iLeftOrRight = (iRoute >> (31 - i)) & 0x1;
        
        if(0 == iLeftOrRight) {
            if (NULL == pCurrNode->pLeftChild) {
                pCurrNode->pLeftChild = createNode();
            }
            pCurrNode = pCurrNode->pLeftChild;
            DBG_PRINT("0 left\n");
        }
        else {
            if (NULL == pCurrNode->pRightChild) {
                pCurrNode->pRightChild = createNode();
            }
            pCurrNode = pCurrNode->pRightChild;
            DBG_PRINT("1 right\n");
        }
        
    }

    pCurrNode->iPort = iPort;
    DBG_PRINT("%d port\n", iPort);
    return;
}

//ip转发查找路由表函数
int getIpFwdPort(NODE * g_pRouteTree, int iIp) {
	int i = 0, iLeftOrRight = 0, iPort = -1;
	NODE *pCurrNode = g_pRouteTree;

	iPort = (-1 == pCurrNode->iPort)?iPort:pCurrNode->iPort;

	DBG_PRINT("input ip: %8x\n", iIp);

	for (i = 0; i < 32; i++) {
		iLeftOrRight = (iIp >> (31-i)) & 0x1;

		if (0 == iLeftOrRight) {
			if (NULL != pCurrNode->pLeftChild) {
				pCurrNode = pCurrNode->pLeftChild;
				iPort = (-1 == pCurrNode->iPort)?iPort:pCurrNode->iPort;
				DBG_PRINT("0 go left, %d port\n", iPort);
			}
			else {
				break;
			}
		}
		else {// (1 == iLeftOrRight)
			if (NULL != pCurrNode->pRightChild) {
				pCurrNode = pCurrNode->pRightChild;
				iPort = (-1 == pCurrNode->iPort)?iPort:pCurrNode->iPort;
				DBG_PRINT("1 go right, %d port\n", iPort);
			}
			else {
				break;
			}
		}
	}

	return iPort;
}
*/


///////////////////dpi/////////////////////
//////////////////////////////////////////
int Action(u_int16_t protocol){
#ifdef PRINT
	printf("[proto: %s]\n",
    ndpi_get_proto_name(ndpi_struct, protocol));
	printf(": %d \n", protocol);
#endif
	return 0;
}

// flow tracking
typedef struct ndpi_flow {
	u_int32_t lower_ip;
	u_int32_t upper_ip;
	u_int16_t lower_port;
	u_int16_t upper_port;
	u_int32_t first_packet_time_sec;
	u_int32_t first_packet_time_usec;
	u_int8_t detection_completed, protocol;
	struct ndpi_flow_struct *ndpi_flow;

	u_int8_t action;  //firewall


	u_int16_t packets, bytes;
	// result only, not used for flow identification
	u_int16_t detected_protocol;

	void *src_id, *dst_id;
} ndpi_flow_t;

static void *malloc_wrapper(unsigned long size)
{
	return malloc(size);
	//return rte_malloc(NULL,size,0);  //size in bytes
}
/////////////////////////////////////////
static void free_wrapper(void *freeable)
{
	free(freeable);
	//rte_free(freeable);
}
////////////////////////
static void debug_printf(u_int32_t protocol, void *id_struct,
	ndpi_log_level_t log_level,
	const char *format, ...) {
}

//////////////////////////
static void free_ndpi_flow(struct ndpi_flow *flow) {
	if(flow->ndpi_flow) { ndpi_free_flow(flow->ndpi_flow); flow->ndpi_flow = NULL; }
	if(flow->src_id)    { ndpi_free(flow->src_id); flow->src_id = NULL;       }
	if(flow->dst_id)    { ndpi_free(flow->dst_id); flow->dst_id = NULL;       }
}

///////////////////////////
static void setupDetection(void)
{

	NDPI_PROTOCOL_BITMASK all;

	// init global detection structure
	ndpi_struct = ndpi_init_detection_module(detection_tick_resolution, malloc_wrapper, free_wrapper, debug_printf);
	if (ndpi_struct == NULL) {
		printf("ERROR: global structure initialization failed\n");
		exit(-1);
	}
	// enable all protocols
	NDPI_BITMASK_SET_ALL(all);
	ndpi_set_protocol_detection_bitmask2(ndpi_struct, &all);

	// allocate memory for id and flow tracking
	size_id_struct = ndpi_detection_get_sizeof_ndpi_id_struct();
	size_flow_struct = ndpi_detection_get_sizeof_ndpi_flow_struct();

	// clear memory for results
	memset(protocol_counter, 0, sizeof(protocol_counter));
	memset(protocol_counter_bytes, 0, sizeof(protocol_counter_bytes));
	memset(protocol_flows, 0, sizeof(protocol_flows));

	if(_protoFilePath != NULL)
	ndpi_load_protocols_file(ndpi_struct, _protoFilePath);

	raw_packet_count = ip_packet_count = total_bytes = 0;
	ndpi_flow_count = 0;
}


static int node_cmp(const void *a, const void *b) {
	struct ndpi_flow *fa = (struct ndpi_flow*)a;
	struct ndpi_flow *fb = (struct ndpi_flow*)b;

	if(fa->lower_ip < fb->lower_ip) return(-1); else { if(fa->lower_ip > fb->lower_ip) return(1); }
	if(fa->lower_port < fb->lower_port) return(-1); else { if(fa->lower_port > fb->lower_port) return(1); }
	if(fa->upper_ip < fb->upper_ip) return(-1); else { if(fa->upper_ip > fb->upper_ip) return(1); }
	if(fa->upper_port < fb->upper_port) return(-1); else { if(fa->upper_port > fb->upper_port) return(1); }
	if(fa->protocol < fb->protocol) return(-1); else { if(fa->protocol > fb->protocol) return(1); }

	return(0);
}


static struct ndpi_flow *get_ndpi_flow(const struct timeval ts, const struct ndpi_iphdr *iph, u_int16_t ipsize)
{

	u_int16_t l4_packet_len;
	struct ndpi_tcphdr *tcph = NULL;
	struct ndpi_udphdr *udph = NULL;
	u_int32_t lower_ip;
	u_int32_t upper_ip;
	u_int16_t lower_port;
	u_int16_t upper_port;
	struct ndpi_flow flow;
	void *ret;

	if (ipsize < 20)
		return NULL;

	if ((iph->ihl * 4) > ipsize || ipsize < ntohs(iph->tot_len)|| (iph->frag_off & htons(0x1FFF)) != 0)
		return NULL;

	l4_packet_len = ntohs(iph->tot_len) - (iph->ihl * 4);

	if (iph->saddr < iph->daddr) {
		lower_ip = iph->saddr;
		upper_ip = iph->daddr;
	} else {
		lower_ip = iph->daddr;
		upper_ip = iph->saddr;
	}
	if (iph->protocol == 6 && l4_packet_len >= 20) {
		// tcp
		tcph = (struct ndpi_tcphdr *) ((u_int8_t *) iph + iph->ihl * 4);
		if (iph->saddr < iph->daddr) {
    		lower_port = tcph->source;
			upper_port = tcph->dest;
  		} else {
    		lower_port = tcph->dest;
    		upper_port = tcph->source;
		}
	} else if (iph->protocol == 17 && l4_packet_len >= 8) {
		// udp
		udph = (struct ndpi_udphdr *) ((u_int8_t *) iph + iph->ihl * 4);
		if (iph->saddr < iph->daddr) {
			lower_port = udph->source;
			upper_port = udph->dest;
		} else {
			lower_port = udph->dest;
			upper_port = udph->source;
		}
	} else {
		// non tcp/udp protocols
		lower_port = 0;
		upper_port = 0;
	}

	flow.protocol = iph->protocol;
	flow.lower_ip = lower_ip;
	flow.upper_ip = upper_ip;
	flow.lower_port = lower_port;
	flow.upper_port = upper_port;
	flow.first_packet_time_sec = ts.tv_sec;
	flow.first_packet_time_usec = ts.tv_usec;

	ret = ndpi_tfind(&flow, (void*)&ndpi_flows_root, node_cmp);

	if(ret == NULL) {
		if (ndpi_flow_count == MAX_NDPI_FLOWS) {
			printf("ERROR: maximum flow count (%u) has been exceeded\n", MAX_NDPI_FLOWS);
			exit(-1);
		} else {
			struct ndpi_flow *newflow = (struct ndpi_flow*)malloc(sizeof(struct ndpi_flow));  

			if(newflow == NULL) {
				printf("[NDPI] %s(1): not enough memory\n", __FUNCTION__);
				return(NULL);
			}

			memset(newflow, 0, sizeof(struct ndpi_flow));
			newflow->protocol = iph->protocol;
			newflow->lower_ip = lower_ip, newflow->upper_ip = upper_ip;
			newflow->lower_port = lower_port, newflow->upper_port = upper_port;
			newflow->first_packet_time_sec = ts.tv_sec;
			newflow->first_packet_time_usec = ts.tv_usec;

			if((newflow->ndpi_flow = calloc(1, size_flow_struct)) == NULL) {
				printf("[NDPI] %s(2): not enough memory\n", __FUNCTION__);
				return(NULL);
			}

			if((newflow->src_id = calloc(1, size_id_struct)) == NULL) {
				printf("[NDPI] %s(3): not enough memory\n", __FUNCTION__);
				return(NULL);
			}

			if((newflow->dst_id = calloc(1, size_id_struct)) == NULL) {
				printf("[NDPI] %s(4): not enough memory\n", __FUNCTION__);
				return(NULL);
			}

			ndpi_tsearch(newflow, (void*)&ndpi_flows_root, node_cmp); /* Add */

			ndpi_flow_count += 1;

			//printFlow(newflow);
			return(newflow);
		}
	} else
		return *(struct ndpi_flow**)ret;
}

static struct ndpi_flow *get_acl(const struct timeval ts, 
                          const struct ndpi_iphdr *iph, u_int16_t ipsize)
{

  u_int16_t l4_packet_len;
  struct ndpi_tcphdr *tcph = NULL;
  struct ndpi_udphdr *udph = NULL;
  u_int32_t lower_ip;
  u_int32_t upper_ip;
  u_int16_t lower_port;
  u_int16_t upper_port;
  struct ndpi_flow flow;
  void *ret;

  if (ipsize < 20)
    return NULL;

  if ((iph->ihl * 4) > ipsize || ipsize < ntohs(iph->tot_len)
      || (iph->frag_off & htons(0x1FFF)) != 0)
    return NULL;

  l4_packet_len = ntohs(iph->tot_len) - (iph->ihl * 4);

  if (iph->saddr < iph->daddr) {
    lower_ip = iph->saddr;
    upper_ip = iph->daddr;
  } else {
    lower_ip = iph->daddr;
    upper_ip = iph->saddr;
  }

  if (iph->protocol == 6 && l4_packet_len >= 20) {
    // tcp
    tcph = (struct ndpi_tcphdr *) ((u_int8_t *) iph + iph->ihl * 4);
    if (iph->saddr < iph->daddr) {
      lower_port = tcph->source;
      upper_port = tcph->dest;
    } else {
      lower_port = tcph->dest;
      upper_port = tcph->source;
    }
  } else if (iph->protocol == 17 && l4_packet_len >= 8) {
    // udp
    udph = (struct ndpi_udphdr *) ((u_int8_t *) iph + iph->ihl * 4);
    if (iph->saddr < iph->daddr) {
      lower_port = udph->source;
      upper_port = udph->dest;
    } else {
      lower_port = udph->dest;
      upper_port = udph->source;
    }
  } else {
    // non tcp/udp protocols
    lower_port = 0;
    upper_port = 0;
  }

  flow.protocol = iph->protocol;
  flow.lower_ip = lower_ip;
  flow.upper_ip = upper_ip;
  flow.lower_port = lower_port;
  flow.upper_port = upper_port;
  flow.first_packet_time_sec = ts.tv_sec;
  flow.first_packet_time_usec = ts.tv_usec;

  ret = ndpi_tfind(&flow, (void*)&acl_root, node_cmp); //search in acl

  if(ret == NULL) {
	//not in acl, pkt is okay.
	return NULL; 
  } else
    return *(struct ndpi_flow**)ret; //pkt in acl, not okay
}


static u_int16_t packet_processing(const u_int64_t time, const struct timeval ts, const struct ndpi_iphdr *iph, u_int16_t ipsize, u_int16_t rawsize)
{
	struct ndpi_id_struct *src, *dst;
	struct ndpi_flow *flow;
	struct ndpi_flow_struct *ndpi_flow = NULL;
	u_int16_t protocol = 0;
	u_int16_t frag_off = ntohs(iph->frag_off);

	flow = get_ndpi_flow(ts, iph, ipsize);
	if (flow != NULL) {
		ndpi_flow = flow->ndpi_flow;
		flow->packets++, flow->bytes += rawsize;
		src = flow->src_id, dst = flow->dst_id;
	} else
		return -1;

	ip_packet_count++;
	total_bytes += rawsize;

	if(flow->detection_completed){

		Action(flow->detected_protocol);
		//printf("[proto: %s]\n\0",
		//ndpi_get_proto_name(ndpi_struct, flow->detected_protocol));  //print
		return flow->detected_protocol;
	}

		// only handle unfragmented packets
	if ((frag_off & 0x3FFF) == 0) {
		// here the actual detection is performed
		protocol = ndpi_detection_process_packet(ndpi_struct, ndpi_flow, (uint8_t *) iph, ipsize, time, src, dst);
	} else {
		static u_int8_t frag_warning_used = 0;

		if (frag_warning_used == 0) {
			printf("\n\nWARNING: fragmented ip packets are not supported and will be skipped \n\n");
			frag_warning_used = 1;
		}

		return 0;
	}



	flow->detected_protocol = protocol;
	Action(flow->detected_protocol);
    //printf("[proto: %s]\n\0",
    //ndpi_get_proto_name(ndpi_struct, flow->detected_protocol));  //print

	if((flow->detected_protocol != NDPI_PROTOCOL_UNKNOWN)
	|| (iph->protocol == IPPROTO_UDP)
	|| ((iph->protocol == IPPROTO_TCP) && (flow->packets > 10))) {
		flow->detection_completed = 1;



		free_ndpi_flow(flow);
	}


	return flow->detected_protocol;
}



static u_int16_t ProtoDtect(const struct timeval ts, const u_int16_t pktlen, struct ndpi_iphdr * ippkt)
{
	//const struct ndpi_ethhdr *ethernet = (struct ndpi_ethhdr *) packet;
	const u_char * packet = (const u_char *)ippkt;
	struct ndpi_iphdr *iph = (struct ndpi_iphdr *) &packet[0];
	u_int64_t time;

	u_int16_t ip_offset;
	u_int16_t frag_off = 0;

	raw_packet_count++;



	time = ((uint64_t) ts.tv_sec) * detection_tick_resolution + ts.tv_usec / (1000000 / detection_tick_resolution);


	ip_offset = 0;
	if(decode_tunnels && (iph->protocol == IPPROTO_UDP) && ((frag_off & 0x3FFF) == 0)) {
		u_short ip_len = ((u_short)iph->ihl * 4);
		struct ndpi_udphdr *udp = (struct ndpi_udphdr *)&packet[0+ip_len];
		u_int16_t sport = ntohs(udp->source), dport = ntohs(udp->dest);

		if((sport == GTP_U_V1_PORT) || (dport == GTP_U_V1_PORT)) {
		/* Check if it's GTPv1 */
		u_int offset = 0+ip_len+sizeof(struct ndpi_udphdr);
		u_int8_t flags = packet[offset];
		u_int8_t message_type = packet[offset+1];

			if((((flags & 0xE0) >> 5) == 1 /* GTPv1 */) && (message_type == 0xFF /* T-PDU */)) {
				ip_offset = 0+ip_len+sizeof(struct ndpi_udphdr)+8 /* GTPv1 header len */;

				if(flags & 0x04) ip_offset += 1; /* next_ext_header is present */
				if(flags & 0x02) ip_offset += 4; /* sequence_number is present (it also includes next_ext_header and pdu_number) */
				if(flags & 0x01) ip_offset += 1; /* pdu_number is present */

				iph = (struct ndpi_iphdr *) &packet[ip_offset];

				if (iph->version != 4) {
					printf("WARNING: not good (packet_id=%u)!\n", (unsigned int)raw_packet_count);
					//goto v4_warning;
				}
			}
		}
	}
	
    // process the packet
    u_int16_t proto = packet_processing(time, ts, iph, pktlen - ip_offset, pktlen);
	return proto;
}


///////////////////////////////////////////////
int getPkt(pcap_t* p,struct pcap_pkthdr** pkt_header,const u_char** pkt_data){
	if(pcap_next_ex(p, pkt_header, pkt_data) != 1){
		pcap_close(p);
		char errbuf[100];  //error buf for pcapReader
		p = pcap_open_offline("/tmp/traffic_sample.pcap", errbuf);  //head
		pcap_next_ex(p, pkt_header, pkt_data);
	}
	return 0;
}  //获取下一个数据包







///////////firewall
/////////////////////////////////////////
char* intoaV4(unsigned int addr, char* buf, u_short bufLen) {
  char *cp, *retStr;
  uint byte;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    byte = addr & 0xff;
    *--cp = byte % 10 + '0';
    byte /= 10;
    if (byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if (byte > 0)
	*--cp = byte + '0';
    }
    *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  /* Convert the string to lowercase */
  retStr = (char*)(cp+1);

  return(retStr);
}


static char* ipProto2Name(u_short proto_id) {
  static char proto[8];

  switch(proto_id) {
  case IPPROTO_TCP:
    return("TCP");
    break;
  case IPPROTO_UDP:
    return("UDP");
    break;
  case IPPROTO_ICMP:
    return("ICMP");
    break;
  case 112:
    return("VRRP");
    break;
  }

  snprintf(proto, sizeof(proto), "%u", proto_id);
  return(proto);
}
///////////////////////////////////////////
///////////////////////////////////////////
static void printFlow(struct ndpi_flow *flow) {
  char buf1[32], buf2[32];

  printf("\t%s %s:%u > %s:%u [proto: %u/%s][%u pkts/%u bytes]\n",
	 ipProto2Name(flow->protocol),
	 intoaV4(ntohl(flow->lower_ip), buf1, sizeof(buf1)),
	 ntohs(flow->lower_port),
	 intoaV4(ntohl(flow->upper_ip), buf2, sizeof(buf2)),
	 ntohs(flow->upper_port),
	 flow->detected_protocol,
	 ndpi_get_proto_name(ndpi_struct, flow->detected_protocol),
	 flow->packets, flow->bytes);
  printf("\n\t%d %d:%d > %d:%d \n", 
	flow->protocol, 
	flow->lower_ip,
	flow->lower_port, 
	flow->upper_ip,
	flow->upper_port);

}
/////////////////////////////////////
///////////////////////////////



//--------------------------------------------------------------------------------------------------------//
/////////////////////////////add acl
int addAcl(u_int32_t lower_ip, u_int32_t upper_ip, u_int16_t lower_port, u_int16_t upper_port, u_int8_t protocol, u_int8_t actions){
    if (ndpi_flow_count == MAX_NDPI_FLOWS) {
      printf("ERROR: maximum flow count (%u) has been exceeded\n", MAX_NDPI_FLOWS);
      exit(-1);
    } else {
      struct ndpi_flow *newflow = (struct ndpi_flow*)malloc(sizeof(struct ndpi_flow));  

      if(newflow == NULL) {
	    printf("[NDPI] %s(1): not enough memory\n", __FUNCTION__);
	    return -1;
      }

      memset(newflow, 0, sizeof(struct ndpi_flow));
      newflow->protocol = protocol;
      newflow->lower_ip = lower_ip, newflow->upper_ip = upper_ip;
      newflow->lower_port = lower_port, newflow->upper_port = upper_port;
      newflow->first_packet_time_sec = 0;
      newflow->first_packet_time_usec = 0;

      if((newflow->ndpi_flow = calloc(1, size_flow_struct)) == NULL) {
	    printf("[NDPI] %s(2): not enough memory\n", __FUNCTION__);
	    return -1;
      }

      if((newflow->src_id = calloc(1, size_id_struct)) == NULL) {
	    printf("[NDPI] %s(3): not enough memory\n", __FUNCTION__);
	    return -1;
      }

      if((newflow->dst_id = calloc(1, size_id_struct)) == NULL) {
	    printf("[NDPI] %s(4): not enough memory\n", __FUNCTION__);
	    return -1;
      }

      ndpi_tsearch(newflow, (void*)&ndpi_flows_root, node_cmp); /* Add */

      ndpi_flow_count += 1;
	  newflow->action = 1;
	  acl_count += 1;

      //printFlow(newflow);
      return 0;
    }
  }
////////////////


static unsigned int fw_pkt_procs(const u_int64_t time, const struct timeval ts,
              const struct ndpi_iphdr *iph, u_int16_t ipsize, u_int16_t rawsize, int * flag)
{

  struct ndpi_flow *flow;




  flow = get_acl(ts, iph, ipsize);
  ip_packet_count++;
  total_bytes += rawsize;
  if (flow != NULL) {  // pkt in acl, not okay:
	*flag = 1;
	//printf("not ok\n");
	return 0;
  } else{
	*flag = 0;
	return 0;
  }
    

}

static int ACLadd(struct ndpi_flow *flow){
	if(flow->detected_protocol == 0){  //unknown proto
		if (acl_count == MAX_NDPI_FLOWS) {
			printf("ERROR: maximum flow count (%u) has been exceeded\n", MAX_NDPI_FLOWS);
			exit(-1);
		}else {
			struct ndpi_flow *newflow = (struct ndpi_flow*)malloc(sizeof(struct ndpi_flow));  

			if(newflow == NULL) {
			printf("[NDPI] %s(1): not enough memory\n", __FUNCTION__);
			return -1 ;
			}

			memset(newflow, 0, sizeof(struct ndpi_flow));
			newflow->protocol = flow->protocol;
			newflow->lower_ip = flow->lower_ip, newflow->upper_ip = flow->upper_ip;
			newflow->lower_port = flow->lower_port, newflow->upper_port = flow->upper_port;
			newflow->first_packet_time_sec = flow->first_packet_time_sec;
			newflow->first_packet_time_usec = flow->first_packet_time_usec;

			if((newflow->ndpi_flow = calloc(1, size_flow_struct)) == NULL) {
				printf("[NDPI] %s(2): not enough memory\n", __FUNCTION__);
				return -1 ;
			}

			if((newflow->src_id = calloc(1, size_id_struct)) == NULL) {
				printf("[NDPI] %s(3): not enough memory\n", __FUNCTION__);
				return -1;
			}

			if((newflow->dst_id = calloc(1, size_id_struct)) == NULL) {
				printf("[NDPI] %s(4): not enough memory\n", __FUNCTION__);
				return -1;
			}

			ndpi_tsearch(newflow, (void*)&acl_root, node_cmp); /* Add */

			acl_count += 1;
#ifdef PRINT
			printFlow(newflow);
#endif
			return 0;
			}
	}
	//this should not happen?
	return 1;//flow->detected_protocol != 0

}

////////////////////////ACL/////////////
static unsigned int ACL_processing(const u_int64_t time, const struct timeval ts, const struct ndpi_iphdr *iph, u_int16_t ipsize, u_int16_t rawsize)
{
	struct ndpi_id_struct *src, *dst;
	struct ndpi_flow *flow;
	struct ndpi_flow_struct *ndpi_flow = NULL;
	u_int16_t protocol = 0;
	u_int16_t frag_off = ntohs(iph->frag_off);

	flow = get_ndpi_flow(ts, iph, ipsize);
	if (flow != NULL) {
		ndpi_flow = flow->ndpi_flow;
		flow->packets++, flow->bytes += rawsize;
		src = flow->src_id, dst = flow->dst_id;
	} else
		return -1;

	ip_packet_count++;
	total_bytes += rawsize;

	if(flow->detection_completed){
		ACLadd(flow);
		//printf("[proto: %s]\n\0",
		//ndpi_get_proto_name(ndpi_struct, flow->detected_protocol));  //print
		return 0;
	}

		// only handle unfragmented packets
	if ((frag_off & 0x3FFF) == 0) {
		// here the actual detection is performed
		protocol = ndpi_detection_process_packet(ndpi_struct, ndpi_flow, (uint8_t *) iph, ipsize, time, src, dst);
	} else {
		static u_int8_t frag_warning_used = 0;

		if (frag_warning_used == 0) {
			printf("\n\nWARNING: fragmented ip packets are not supported and will be skipped \n\n");
			frag_warning_used = 1;
		}

		return 0;
	}

#if 0
  if(verbose && (protocol == 0)) {
    char buf1[32], buf2[32];

    printf("%s %s:%u > %s:%u [proto: %u/%s]\n",
	   ipProto2Name(flow->protocol),
	   intoaV4(ntohl(flow->lower_ip), buf1, sizeof(buf1)), ntohs(flow->lower_port),
	   intoaV4(ntohl(flow->upper_ip), buf2, sizeof(buf2)), ntohs(flow->upper_port),
	   protocol, ndpi_get_proto_name(ndpi_struct, protocol));
  }
#endif

	flow->detected_protocol = protocol;
	ACLadd(flow);
    //printf("[proto: %s]\n\0",
    //ndpi_get_proto_name(ndpi_struct, flow->detected_protocol));  //print

	if((flow->detected_protocol != NDPI_PROTOCOL_UNKNOWN)
	|| (iph->protocol == IPPROTO_UDP)
	|| ((iph->protocol == IPPROTO_TCP) && (flow->packets > 10))) {
		flow->detection_completed = 1;

#if 0
    if(flow->ndpi_flow->l4.tcp.host_server_name[0] != '\0')
      printf("%s\n", flow->ndpi_flow->l4.tcp.host_server_name);
#endif

		free_ndpi_flow(flow);
	}

#if 0
  if(ndpi_flow->l4.tcp.host_server_name[0] != '\0')
    printf("%s\n", ndpi_flow->l4.tcp.host_server_name);
#endif  

	return 0;
}

////////////////////////////////////////////

static void fwpacket_preprocess(const struct timeval ts, const u_int16_t pktlen, struct ndpi_iphdr * ippkt, int * flag)
{
	const u_char * packet = (const u_char *)ippkt;
  //const struct ndpi_ethhdr *ethernet = (struct ndpi_ethhdr *) packet;
  struct ndpi_iphdr *iph = (struct ndpi_iphdr *) &packet[0];
  u_int64_t time;
//static u_int64_t lasttime = 0;
  u_int16_t ip_offset;
  u_int16_t frag_off = 0;

  raw_packet_count++;

//  if((capture_until != 0) && (ts >= capture_until)) {
//    sigproc(0);
//    return;
//  }

  time = ((uint64_t) ts.tv_sec) * detection_tick_resolution +
    ts.tv_usec / (1000000 / detection_tick_resolution);
//  time = ((uint64_t) ts) * detection_tick_resolution +
//   header->ts.tv_usec / (1000000 / detection_tick_resolution);
//  if (lasttime > time) {
//    // printf("\nWARNING: timestamp bug in the pcap file (ts delta: %//llu, repairing)\n", lasttime - time);
//    time = lasttime;
//  }
//  lasttime = time;

	
  //type = ethernet->h_proto;

  // just work on Ethernet packets that contain IP
//  if (_pcap_datalink_type == DLT_EN10MB && type == htons(ETH_P_IP)
//      && header->caplen >= sizeof(struct ndpi_ethhdr)) {
//    u_int16_t frag_off = ntohs(iph->frag_off);
//
//    if(header->caplen < header->len) {
//      static u_int8_t cap_warning_used = 0;
//    if (cap_warning_used == 0) {
//	printf("\n\nWARNING: packet capture size is smaller than packet //size, DETECTION MIGHT NOT WORK CORRECTLY\n\n");
//	cap_warning_used = 1;
//      }
//    }
//
//    if (iph->version != 4) {
//      static u_int8_t ipv4_warning_used = 0;
//
//    v4_warning:
//    if (ipv4_warning_used == 0) {
//	printf("\n\nWARNING: only IPv4 packets are supported in this demo (nDPI supports both IPv4 and IPv6), all other packets will be discarded\n\n");
//	ipv4_warning_used = 1;
//      }
//      return;
//    }

    ip_offset = 0;
    if(decode_tunnels && (iph->protocol == IPPROTO_UDP) && ((frag_off & 0x3FFF) == 0)) {
      u_short ip_len = ((u_short)iph->ihl * 4);
      struct ndpi_udphdr *udp = (struct ndpi_udphdr *)&packet[0+ip_len];
      u_int16_t sport = ntohs(udp->source), dport = ntohs(udp->dest);

      if((sport == GTP_U_V1_PORT) || (dport == GTP_U_V1_PORT)) {
	/* Check if it's GTPv1 */
	u_int offset = 0+ip_len+sizeof(struct ndpi_udphdr);
	u_int8_t flags = packet[offset];
	u_int8_t message_type = packet[offset+1];

	if((((flags & 0xE0) >> 5) == 1 /* GTPv1 */) && (message_type == 0xFF /* T-PDU */)) {
	  ip_offset = 0+ip_len+sizeof(struct ndpi_udphdr)+8 /* GTPv1 header len */;

	  if(flags & 0x04) ip_offset += 1; /* next_ext_header is present */
	  if(flags & 0x02) ip_offset += 4; /* sequence_number is present (it also includes next_ext_header and pdu_number) */
	  if(flags & 0x01) ip_offset += 1; /* pdu_number is present */

	  iph = (struct ndpi_iphdr *) &packet[ip_offset];

	  if (iph->version != 4) {
	     printf("WARNING: not good (packet_id=%u)!\n", (unsigned int)raw_packet_count);
	    //goto v4_warning;
	  }
	}
      }

    }
	
    // process the packet
    fw_pkt_procs(time, ts, iph, pktlen - ip_offset, pktlen, flag);
}

static void ACL_preprocess(const struct timeval ts, const u_int16_t pktlen, const u_char * packet)
{

  struct ndpi_iphdr *iph = (struct ndpi_iphdr *) &packet[sizeof(struct ndpi_ethhdr)];
  u_int64_t time;
//static u_int64_t lasttime = 0;
  u_int16_t ip_offset;
  u_int16_t frag_off = 0;

  raw_packet_count++;

//  if((capture_until != 0) && (ts >= capture_until)) {
//    sigproc(0);
//    return;
//  }

  time = ((uint64_t) ts.tv_sec) * detection_tick_resolution +
    ts.tv_usec / (1000000 / detection_tick_resolution);
//  time = ((uint64_t) ts) * detection_tick_resolution +
//   header->ts.tv_usec / (1000000 / detection_tick_resolution);
//  if (lasttime > time) {
//    // printf("\nWARNING: timestamp bug in the pcap file (ts delta: %//llu, repairing)\n", lasttime - time);
//    time = lasttime;
//  }
//  lasttime = time;

	


  // just work on Ethernet packets that contain IP
//  if (_pcap_datalink_type == DLT_EN10MB && type == htons(ETH_P_IP)
//      && header->caplen >= sizeof(struct ndpi_ethhdr)) {
//    u_int16_t frag_off = ntohs(iph->frag_off);
//
//    if(header->caplen < header->len) {
//      static u_int8_t cap_warning_used = 0;
//    if (cap_warning_used == 0) {
//	printf("\n\nWARNING: packet capture size is smaller than packet //size, DETECTION MIGHT NOT WORK CORRECTLY\n\n");
//	cap_warning_used = 1;
//      }
//    }
//
//    if (iph->version != 4) {
//      static u_int8_t ipv4_warning_used = 0;
//
//    v4_warning:
//    if (ipv4_warning_used == 0) {
//	printf("\n\nWARNING: only IPv4 packets are supported in this demo (nDPI supports both IPv4 and IPv6), all other packets will be discarded\n\n");
//	ipv4_warning_used = 1;
//      }
//      return;
//    }

    ip_offset = sizeof(struct ndpi_ethhdr);
    if(decode_tunnels && (iph->protocol == IPPROTO_UDP) && ((frag_off & 0x3FFF) == 0)) {
      u_short ip_len = ((u_short)iph->ihl * 4);
      struct ndpi_udphdr *udp = (struct ndpi_udphdr *)&packet[sizeof(struct ndpi_ethhdr)+ip_len];
      u_int16_t sport = ntohs(udp->source), dport = ntohs(udp->dest);

      if((sport == GTP_U_V1_PORT) || (dport == GTP_U_V1_PORT)) {
	/* Check if it's GTPv1 */
	u_int offset = sizeof(struct ndpi_ethhdr)+ip_len+sizeof(struct ndpi_udphdr);
	u_int8_t flags = packet[offset];
	u_int8_t message_type = packet[offset+1];

	if((((flags & 0xE0) >> 5) == 1 /* GTPv1 */) && (message_type == 0xFF /* T-PDU */)) {
	  ip_offset = sizeof(struct ndpi_ethhdr)+ip_len+sizeof(struct ndpi_udphdr)+8 /* GTPv1 header len */;

	  if(flags & 0x04) ip_offset += 1; /* next_ext_header is present */
	  if(flags & 0x02) ip_offset += 4; /* sequence_number is present (it also includes next_ext_header and pdu_number) */
	  if(flags & 0x01) ip_offset += 1; /* pdu_number is present */

	  iph = (struct ndpi_iphdr *) &packet[ip_offset];

	  if (iph->version != 4) {
	     printf("WARNING: not good (packet_id=%u)!\n", (unsigned int)raw_packet_count);
	    //goto v4_warning;
	  }
	}
      }

    }
	
    // process the packet
    ACL_processing(time, ts, iph, pktlen - ip_offset, pktlen);
}




///////////////////////////////////////////

int writeAcl(int num){
	
	char errbuf[100];  //error buf for pcapReader
	pcap_t *pfile = pcap_open_offline("/tmp/traffic_sample.pcap", errbuf);  //head
	if (NULL == pfile) {
		system("cp ../posix/traffic_sample.pcap /tmp/");   //转移到tmpfs
		pfile = pcap_open_offline("/tmp/traffic_sample.pcap", errbuf);  //head
		if (NULL == pfile){
			printf("%s\n", errbuf);
			return -1;
		} 
	} 
	//printf("file opened\n");
	struct pcap_pkthdr *pkthdr = 0;
	const u_char *pktdata = 0;
	struct timeval timestamp;
	gettimeofday( &timestamp, NULL);

	for(;acl_count < num;){
		getPkt(pfile, &pkthdr, &pktdata);
		ACL_preprocess(timestamp, pkthdr->caplen, pktdata);
	}
	pcap_close(pfile);
	
	return 0;
}
////////////////////////


////////////////ids

static int IDS(const struct timeval ts, const u_int16_t pktlen, struct ndpi_iphdr * packet, FILE *filp, int num){
	int flag = 0;
	fwpacket_preprocess(ts, pktlen, packet, &flag);
	if (flag == 1){
		struct ndpi_iphdr *iph = (struct ndpi_iphdr *) &packet[0];

		u_int16_t l4_packet_len;
		struct ndpi_tcphdr *tcph = NULL;
		struct ndpi_udphdr *udph = NULL;
		u_int32_t lower_ip;
		u_int32_t upper_ip;
		u_int16_t lower_port;
		u_int16_t upper_port;
		u_int16_t ipsize = pktlen;

		if (ipsize < 20)
			return -1;

		if ((iph->ihl * 4) > ipsize || ipsize < ntohs(iph->tot_len)
		|| (iph->frag_off & htons(0x1FFF)) != 0)
			return -1;

		l4_packet_len = ntohs(iph->tot_len) - (iph->ihl * 4);

		if (iph->saddr < iph->daddr) {
			lower_ip = iph->saddr;
			upper_ip = iph->daddr;
		} else {
			lower_ip = iph->daddr;
			upper_ip = iph->saddr;
		}

		if (iph->protocol == 6 && l4_packet_len >= 20) {
    // tcp
			tcph = (struct ndpi_tcphdr *) ((u_int8_t *) iph + iph->ihl * 4);
			if (iph->saddr < iph->daddr) {
				lower_port = tcph->source;
				upper_port = tcph->dest;
			} else {
				lower_port = tcph->dest;
				upper_port = tcph->source;
			}
		} else if (iph->protocol == 17 && l4_packet_len >= 8) {
    // udp
			udph = (struct ndpi_udphdr *) ((u_int8_t *) iph + iph->ihl * 4);
			if (iph->saddr < iph->daddr) {
				lower_port = udph->source;
				upper_port = udph->dest;
			} else {
				lower_port = udph->dest;
				upper_port = udph->source;
			}
		} else {
    // non tcp/udp protocols
			lower_port = 0;
			upper_port = 0;
		}


		char buf1[32], buf2[32];
		fprintf(filp, "No.%d %s %s:%u > %s:%u\n", num,
			 ipProto2Name(iph->protocol),
			 intoaV4(ntohl(lower_ip), buf1, sizeof(buf1)),
			 ntohs(lower_port),
			 intoaV4(ntohl(upper_ip), buf2, sizeof(buf2)),
			 ntohs(upper_port)
			 );	
		
		//int writeCnt = fprintf(filp, "num: %d\n", num);
		//printf("%d\n",writeCnt );
		return 0;
	}else{

		return 0;	
	}
	
	
}

#endif
