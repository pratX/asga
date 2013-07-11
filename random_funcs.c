#include<time.h>
#include<stdlib.h>


/* +------------------------------------------------------------------------+ */
/* |                       RANDOM NUMBERS FUNCTIONS                         | */
/* +------------------------------------------------------------------------+ */

/* initialize the pseudo-random numbers generator */
/* ============================================== */
void random_initialize() {
 	srand((unsigned int)time(0));
}


/* get a random integer i (0<=i<max) */
/* ================================= */
int random_get_int(int max) {
	return (rand()%max);
}

unsigned char randnum(unsigned char* arr, unsigned int size){
	// returns a randomly selected element from arr[size]		
	// arr has indices from 0 to size-1
	unsigned int index;
	index = random_get_int(size);
	return arr[index];
}

unsigned char enc_data_msn(unsigned char c, unsigned char i){
        /* c is the lsn to be encoded with a msn */
        /* lsn = least significant nibble  msn = most significant nibble */  
	if(c <= i)
		if(c==0){
               		//Randomly select and return from {5,7}
			unsigned char arr[2] = {5,7}; 
			return randnum(arr, 2);
		}	
            	else{ 
               		//Randomly select and return from {4,5,6,7}
			unsigned char arr[4] = {4,5,6,7}; 
			return randnum(arr, 4);
		}
         else
            	if(c==0){
               		//Randomly select and return from {3,5,7}
			unsigned char arr[3] = {3,5,7}; 
			return randnum(arr, 3);
		}
            	else{ 
               		//Randomly select and return from {3,4,5,6,7}
			if(c <= 0x0A){
				unsigned char arr[4] = {4,5,6,7}; 
				return randnum(arr, 4);
			}
			else{
				unsigned char arr[2] = {4,6}; 
				return randnum(arr, 2);
			}
		}	   
}


