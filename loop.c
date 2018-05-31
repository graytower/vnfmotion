#include <unistd.h>
#include "nfv.h"
int main(void) {
	setcpu(1);
	int sum = 0;
	int i = 0;
	while(1) {
		sum = sum + i;
		sum = sum - i;
		sum++;
		if(i%1000 == 0) {
			usleep(1);
		}
		i++;
	}
	return 0;
}
