

/* +------------------------------------------------------------------------+ */
/* |                    ALPHANUMERIC MANIPULATIONS FUNCTIONS                | */
/* +------------------------------------------------------------------------+ */

#include<string.h>
#define ALPHANUMERIC_BYTES "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

/* return 1 if the byte is alphanumeric */
/* ==================================== */
int alphanumeric_check(unsigned char c) {
 if (c<'0') return 0;
 else if (c<='9') return 1;
 else if (c<'A') return 0;
 else if (c<='Z') return 1;
 else if (c<'a') return 0;
 else if (c<='z') return 1;
 else return 0;
}


/* return a random alphanumeric byte */
/* ================================= */
unsigned char alphanumeric_get_byte() {
 unsigned char *bytes=ALPHANUMERIC_BYTES;

 return bytes[random_get_int(strlen(bytes))];
}


/* return a randomly selected alphanumeric byte less than max */
/* ========================================================== */
unsigned char alphanumeric_get_byte_ltmax(unsigned char max){
	unsigned char* bytes=ALPHANUMERIC_BYTES;
	unsigned int size = 0;
	for(; (size < strlen(bytes)) && (bytes[size]<=max); ++size);
	return randnum(bytes, size);
}



/* generate an alphanumeric offset such that c+offset is also alphanumeric */
/* ======================================================================= */
unsigned char off_gen (unsigned char c){
	if(c>=0 && c<=0x4a){
		unsigned char max = 16*7+10-c;
        	while(1){   
            		unsigned char x = alphanumeric_get_byte_ltmax(max); 
            		if(alphanumeric_check(c+x))
                		return x;  
          	} 
	} 
	else
		return 0;   
}



/* return an alphanumeric value ret such that c XOR ret is also alphanumeric */
/* ========================================================================= */
unsigned char alphanumeric_get_complement(unsigned char c) {
 	unsigned char ret;

 	while (1) {
  	ret=alphanumeric_get_byte();
  	if (alphanumeric_check(c^ret)) return ret;
 	}
}


