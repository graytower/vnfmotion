#ifndef SERIES_ARRAY_H
#define SERIES_ARRAY_H

#include<stdio.h>//printf()
#include<unistd.h>//fork() sleep()
#include<sys/types.h>//fork()
#include<stdlib.h>//malloc()
#include<string.h>//perror()
#include<errno.h>//errno
#include<math.h>//double fabs(double x)

#define CLEAR_SHOW 1

void show_int_series(int length, int showed_series[length], char * series_name);
void show_double_series(int length, double showed_series[length], char * series_name);
void show_int_array(int edges, int showed_array[edges][edges], char * array_name);
void show_long_array(int edges, long showed_array[edges][edges], char * array_name);
void show_double_array(int edges, double showed_array[edges][edges], char * array_name);

void clear_int_series(int edges, int cleared_series[edges], char * series_name);
void clear_double_series(int edges, double cleared_series[edges], char * series_name);
void clear_double_array(int edges, double cleared_array[edges][edges], char * array_name);

void copy_int_series(int edges, int src_series[edges], int dst_series[edges]);
void copy_double_series(int edges, double src_series[edges], double dst_series[edges]);
void copy_double_array(int edges, double src_array[edges][edges], double dst_array[edges][edges]);


void show_int_series(int length, int showed_series[length], char * series_name) {
	printf("Series \'%s\':", series_name);
	int i = 0;
	printf("%d", showed_series[0]);
	for(i = 1;i < length;i++) {
		printf(", %d", showed_series[i]);
	}
	printf("\n");
}

void show_double_series(int length, double showed_series[length], char * series_name) {
	printf("Series \'%s\':", series_name);
	int i = 0;
	printf("%f", showed_series[0]);
	for(i = 1;i < length;i++) {
		printf(", %f", showed_series[i]);
	}
	printf("\n");
}


void show_int_array(int edges, int showed_array[edges][edges], char * array_name) {
	printf("Array \'%s\':\n", array_name);
	int i = 0;
	int j = 0;
	for(i = 0;i < edges;i++) {
		for(j = 0;j < edges;j++) {
			printf("%d\t", showed_array[i][j]);
		}
		printf("\n");
	}
	printf("\n");
}

void show_long_array(int edges, long showed_array[edges][edges], char * array_name) {
	printf("Array \'%s\':\n", array_name);
	int i = 0;
	int j = 0;
	for(i = 0;i < edges;i++) {
		for(j = 0;j < edges;j++) {
			printf("%ld\t", showed_array[i][j]);
		}
		printf("\n");
	}
	printf("\n");
}

void show_double_array(int edges, double showed_array[edges][edges], char * array_name) {
	printf("Array \'%s\':\n", array_name);
	int i = 0;
	int j = 0;
	for(i = 0;i < edges;i++) {
		for(j = 0;j < edges;j++) {
			printf("%f\t", showed_array[i][j]);
		}
		printf("\n");
	}
	printf("\n");
}

void clear_int_series(int edges, int cleared_series[edges], char * series_name) {
	int i = 0;
	for(i = 0;i < edges;i++) {
		cleared_series[i] = 0;
	}
	#ifndef CLEAR_SHOW
	if(strlen(series_name)) {
		
		printf("cleared the series \'%s\'\n", series_name);
	}
	#endif
}


void clear_double_series(int edges, double cleared_series[edges], char * series_name) {
	int i = 0;
	for(i = 0;i < edges;i++) {
		cleared_series[i] = 0;
	}
	#ifndef CLEAR_SHOW
	if(strlen(series_name)) {
		printf("cleared the series \'%s\'\n", series_name);
	}
	#endif
}


void clear_double_array(int edges, double cleared_array[edges][edges], char * array_name) {
	int i = 0;
	int j = 0;
	for(i = 0;i < edges;i++) {
		for(j = 0;j < edges;j++) {
			cleared_array[i][j] = 0;
		}
	}
	#ifndef CLEAR_SHOW
	if(strlen(array_name)) {
		printf("cleared the array \'%s\'\n", array_name);
	}
	#endif
}

void copy_int_series(int edges, int src_series[edges], int dst_series[edges]) {
	int i = 0;
	for(i = 0;i < edges;i++) {
		dst_series[i] = src_series[i];
	}
}


void copy_double_series(int edges, double src_series[edges], double dst_series[edges]) {
	int i = 0;
	for(i = 0;i < edges;i++) {
		dst_series[i] = src_series[i];
	}
}


void copy_double_array(int edges, double src_array[edges][edges], double dst_array[edges][edges]) {
	int i = 0;
	int j = 0;
	for(i = 0;i < edges;i++) {
		for(j = 0;j < edges;j++) {
			dst_array[i][j] = src_array[i][j];
		}
	}
}



#endif
