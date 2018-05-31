#ifndef EXTENDED_KL_H
#define EXTENDED_KL_H

#include<stdio.h>//printf()
#include<unistd.h>//fork() sleep()
#include<sys/types.h>//fork()
#include<stdlib.h>//malloc()
#include<string.h>//perror()
#include<errno.h>//errno
#include<math.h>//double fabs(double x)

#include"series_array.h"//show/clear/copy series/array.

#define MAX_LOOP_TIMES 5

#define KL_ALPHA 0.3

struct KL_return {
	//int length;
	int set1[50];
	int set2[50];
};//maybe we could use a two-dimensional array to replace the struct.



struct KL_return KL_step(int edges, double adj_array[edges][edges], double point_weight[edges], int set_edges, int set1[set_edges], int set2[set_edges]);


int * KL_partition(int old_edges, double adj_array[old_edges][old_edges], double raw_point_weight[old_edges]);//return a one dimensional array(with [(edges+edges%2)/2] members)
			//WARNING:remember to free the returned series!!!


double Diff_value(int row_number, int edges, double adj_array[edges][edges], int set_edges, int set_in[set_edges], int set_other[set_edges]);



struct KL_return KL_step(int edges, double adj_array[edges][edges], double point_weight[edges],int set_edges, int set1[set_edges], int set2[set_edges]) {
	printf("now is in KL_step, set_edges = %d\n", set_edges);
	struct KL_return KL_re;
	copy_int_series(set_edges, set1, KL_re.set1);
	copy_int_series(set_edges, set2, KL_re.set2);
	show_int_series(set_edges, KL_re.set1, "KL_step's return value: KL_re.set1");
	show_int_series(set_edges, KL_re.set2, "KL_step's return value: KL_re.set2");
	show_double_series(edges, point_weight, "point_weight");


	int i = 0;
	int j = 0;
	double sum_weight = 0;
	for(i = 0;i < set_edges;i++) {
		sum_weight = sum_weight + point_weight[i];
	}

	double set1_Dvalue[set_edges];
	double set2_Dvalue[set_edges];
	clear_double_series(set_edges, set1_Dvalue, "set1_Dvalue");
	clear_double_series(set_edges, set2_Dvalue, "set2_Dvalue");

	double gain_edgecut[set_edges][set_edges];
	double gain_balance[set_edges][set_edges];
	double gain[set_edges][set_edges];
	double edgecut_old = 0;
	double max_gain = 0;
	int loop_times = 0;

	do {
		loop_times++;
		printf("******************************************\n");
		printf("LOOP %d!!!\n", loop_times);
		show_int_series(set_edges, KL_re.set1, "KL_re.set1");
		show_int_series(set_edges, KL_re.set2, "KL_re.set2");
		edgecut_old = 0;
		for(i = 0;i < set_edges;i++) {
			for(j = 0;j < set_edges;j++) {
				edgecut_old = edgecut_old + adj_array[KL_re.set1[i]][KL_re.set2[j]];
			}
		}
		printf("edgecut_old = %f\n", edgecut_old);
		if(fabs(edgecut_old) <= 1e-15) {
			printf("Surprise!edgecut_old = 0!!!!\n");
			edgecut_old = 1;
		}
		for(i = 0;i < set_edges;i++) {
			set1_Dvalue[i] = Diff_value(KL_re.set1[i], edges, adj_array, set_edges, KL_re.set1, KL_re.set2);
			set2_Dvalue[i] = Diff_value(KL_re.set2[i], edges, adj_array, set_edges, KL_re.set2, KL_re.set1);
		}
		for(i = 0;i < set_edges;i++) {
			for(j = 0;j < set_edges;j++) {
				//gain_edgecut[i][j] = Diff_value(KL_re.set1[i], edges, adj_array, set_edges, KL_re.set1, KL_re.set2);
				//printf("gain_edgecut[%d][%d] = %f Diff_value(KL_re.set1[%d]) = %d \n", i, j, gain_edgecut[i][j], i, Diff_value(KL_re.set1[i], edges, adj_array, set_edges, set1, set2));
				//gain_edgecut[i][j] = gain_edgecut[i][j] + Diff_value(KL_re.set2[j], edges, adj_array, set_edges, KL_re.set2, KL_re.set1);
				//printf("gain_edgecut[%d][%d] = %f Diff_value(KL_re.set2[%d]) = %d \n", i, j, gain_edgecut[i][j], j, Diff_value(KL_re.set1[i], edges, adj_array, set_edges, set2, set1));
				
				gain_edgecut[i][j] = set1_Dvalue[i] + set2_Dvalue[j];
				gain_edgecut[i][j] = gain_edgecut[i][j] - 2 * adj_array[KL_re.set1[i]][KL_re.set2[j]];
				//printf("adj_array[KL_re.set1[%d]][KL_re.set2[%d]] = %d", i, j, adj_array[KL_re.set1[i]][KL_re.set2[j]]);
				gain_edgecut[i][j] = gain_edgecut[i][j] / edgecut_old;
			}
		}
/*		show_double_array(set_edges, gain_edgecut, "gain_edgecut");

		for(i = 0;i < set_edges;i++) {
			for(j = 0;j < set_edges;j++) {
				gain_edgecut[i][j] = gain_edgecut[i][j] / edgecut_old;

			}
		}*/
		printf("got the gain_edgecut array\n");
		show_double_array(set_edges, gain_edgecut, "gain_edgecut");

		double D_workloaddiff = 0;
		double workloaddiff_old = 0;
		double workloaddiff_new = 0;
		printf("******************************************\n");
		for(i = 0;i < set_edges;i++) {
			workloaddiff_old = workloaddiff_old + point_weight[KL_re.set1[i]] - point_weight[KL_re.set2[i]];
			printf("point_weight[KL_re.set1[%d]] = %f, point_weight[KL_re.set2[%d]] = %f\n", i, point_weight[KL_re.set1[i]], i, point_weight[KL_re.set2[i]]);
		}
		printf("workloaddiff_old = %f \n", workloaddiff_old);
	

		if(fabs(workloaddiff_old) <= 1e-15) {//fabs(workloaddiff_old == 0)
			for(i = 0;i < set_edges;i++) {
				for(j = 0;j < set_edges;j++) {
					workloaddiff_new = workloaddiff_old - 2 * point_weight[KL_re.set1[i]] + 2 * point_weight[KL_re.set2[j]];
					//printf("i = %d, j = %d, point_weight[KL_re.set1[%d]] = %f, point_weight[KL_re.set2[%d]] = %f\n", i, j, i, point_weight[KL_re.set1[i]], j, point_weight[KL_re.set2[j]]);
					//printf("workloaddiff_old = %f, workloaddiff_new = %f \n", workloaddiff_old, workloaddiff_new);
					D_workloaddiff = fabs(workloaddiff_old) - fabs(workloaddiff_new);
					if(fabs(D_workloaddiff) <= 1e-15) {
						gain_balance[i][j] = 0;
					}
					else {
						gain_balance[i][j] = -1;
					}
				}
			}

		}
		else {
			for(i = 0;i < set_edges;i++) {
				for(j = 0;j < set_edges;j++) {
					workloaddiff_new = workloaddiff_old - 2 * point_weight[KL_re.set1[i]] + 2 * point_weight[KL_re.set2[j]];
					//printf("i = %d, j = %d, point_weight[KL_re.set1[%d]] = %f, point_weight[KL_re.set2[%d]] = %f\n", i, j, i, point_weight[KL_re.set1[i]], j, point_weight[KL_re.set2[j]]);
					//printf("workloaddiff_old = %f, workloaddiff_new = %f \n", workloaddiff_old, workloaddiff_new);
					D_workloaddiff = fabs(workloaddiff_old) - fabs(workloaddiff_new);
					gain_balance[i][j] = D_workloaddiff / fabs(workloaddiff_old);
				}
			}
		}

		

		printf("got the gain_balance array\n");
		show_double_array(set_edges, gain_balance, "gain_balance");


		int max_i = 0, max_j = 0;
		max_gain = -10000;
		for(i = 0;i < set_edges;i++) {
			for(j = 0;j < set_edges;j++) {
				gain[i][j] = KL_ALPHA * gain_edgecut[i][j] + (1 - KL_ALPHA) * gain_balance[i][j];
				if(gain[i][j] > max_gain) {
					max_gain = gain[i][j];
					max_i = i;
					max_j = j;
				}
			}
		}
		printf("got the gain array\n");
		show_double_array(set_edges, gain, "gain");
		printf("max_gain is gain[%d][%d] = %f\n", max_i, max_j, gain[max_i][max_j]);
		
		if(max_gain > 0) {
			int temp = 0;//exchange two nodes.
			temp = KL_re.set1[max_i];
			KL_re.set1[max_i] = KL_re.set2[max_j];
			KL_re.set2[max_j] = temp;
		}
	}while(max_gain > 0 && loop_times < MAX_LOOP_TIMES);


	return KL_re;
}







int * KL_partition(int old_edges, double raw_adj_array[old_edges][old_edges], double raw_point_weight[old_edges]) {//remember to free the return value!!!
	//printstar();
	printf("Now in the KL_partition!!!\n");
	int set_edges = (old_edges + (old_edges % 2)) / 2;
	int * cut_order = (int *) malloc(set_edges);//WARNING!!!the pointer needs to be freed!
	clear_int_series(set_edges, cut_order, "cut_order");

	if(old_edges == 2) {
		cut_order[0] = 0;
		return cut_order;
	}

	show_double_array(old_edges, raw_adj_array, "raw_adj_array");

	int new_edges = old_edges;
	if((old_edges % 2) != 0) {
		new_edges = old_edges + 1;
	}

	double adj_array[new_edges][new_edges];
	double point_weight[new_edges];
	clear_double_series(new_edges, point_weight, "point_weight");
	clear_double_array(new_edges, adj_array, "adj_array");
	copy_double_series(old_edges, raw_point_weight, point_weight);

	if((old_edges % 2) == 0) {
		copy_double_array(new_edges, raw_adj_array, adj_array);
	}
	if((old_edges % 2) != 0) {
		int i = 0;
		int j = 0;
		for(i = 0;i < old_edges;i++) {
			for(j = 0;j < old_edges;j++) {
				adj_array[i][j] = raw_adj_array[i][j];
			}
		}
		for(i = 0;i < new_edges;i++) {//let the last column of array equal 0.
			adj_array[i][old_edges] = 0;
		}
		for(j = 0;j < new_edges;j++) {//let the last row of array equal 0.
			adj_array[old_edges][j] = 0;
		}
		point_weight[new_edges - 1] = 0;

	}
	show_double_array(new_edges, adj_array, "adj_array");
	show_double_series(new_edges, point_weight, "point_weight");

	int i = 0;
	struct KL_return KL_re;
	for(i = 0;i < set_edges;i++) {	//initialize the orders.
		KL_re.set1[i] = i;
		KL_re.set2[i] = i + set_edges;
	}


/*	for(i = 0;i < set_edges;i++) {	//another way to initialize the orders.
		KL_re.set1[i] = 2*i;
		KL_re.set2[i] = 2*i + 1;
	}
*/
	printf("set1 and set2 have been initialized!\n");
	show_int_series(set_edges, KL_re.set1, "KL_re.set1");
	show_int_series(set_edges, KL_re.set2, "KL_re.set2");
	printf("******************************************\n");
	KL_re = KL_step(new_edges, adj_array, point_weight, set_edges, KL_re.set1, KL_re.set2);//the 'return' can tell us to split which processes to another CPU.

	copy_int_series(set_edges, KL_re.set1, cut_order);
	if(new_edges > old_edges) {
		for(i = 0;i < set_edges;i++) {
			if(KL_re.set1[i] == old_edges) {
				clear_int_series(set_edges, cut_order, "cut_order cleared");
				copy_int_series(set_edges, KL_re.set2, cut_order);
				break;
			}
		}
	}
	show_int_series(set_edges, cut_order, "final cut_order");
	return cut_order;//remember to free the return value!!!


}





double Diff_value(int row_number, int edges, double adj_array[edges][edges], int set_edges, int set_in[set_edges], int set_other[set_edges]) {
	double d = 0;
	int i = 0;
	for(i = 0;i < set_edges;i++) {//calculate the externals
		d = d + adj_array[row_number][set_other[i]];
	}

	for(i = 0;i < set_edges;i++) {//calculate the internals
		d = d - adj_array[row_number][set_in[i]];
	}
	return d;
}




#endif
