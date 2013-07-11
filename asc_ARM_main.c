#include <stdio.h>
#include <getopt.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

extern struct Sshellcode {
 unsigned char* opcodes; /* opcodes bytes */
 int size; /* size of the opcodes bytes */
};

extern void random_initialize();
extern struct Sshellcode* shellcode_malloc();
extern void shellcode_zero(struct Sshellcode*);
extern int shellcode_read_C(struct Sshellcode*, char*, char*);
extern void shellcode_hex_print(struct Sshellcode*);
extern void enc_data_builder(struct Sshellcode* output, struct Sshellcode* input);
extern void DecoderLoopBuilder(struct Sshellcode* dec_loop, unsigned int icache_flush);
extern void encDecoderLoopBuilder(struct Sshellcode* output, struct Sshellcode* dec_loop);
extern void DecoderBuilder(struct Sshellcode* dec, struct Sshellcode* dec_loop, unsigned int icache_flush);
extern void buildInit(struct Sshellcode* output, struct Sshellcode* dec);
extern struct Sshellcode* shellcode_cat(struct Sshellcode* dest, struct Sshellcode* src);
extern int shellcode_print(struct Sshellcode*); 
extern int shellcode_write_C(struct Sshellcode* shellcode, char* filename);

int main(){

       	random_initialize();    
        struct Sshellcode* input;
        input = shellcode_malloc();
        shellcode_zero(input);
        

	/*Command line UI*/
	char input_C[20], input_var[20], input_bin[20], output_C[20], output_bin[20];
	unsigned char in_choice[10], out_choice[10], flush_choice[10], try_choice[10];
	unsigned int icache_flush, try_flag = 0;
	printf("Input file type: C or binary? [C/b]");
	scanf(" %s",in_choice);
	do{
		switch(in_choice[0]){
			case 'c':
			case 'C': printf("Input C file name: ");
				  scanf("%s", input_C);
			  	  printf("Name of the array containing the shellcode: ");
			  	  scanf("%s", input_var);
			  	  if((shellcode_read_C(input, input_C, input_var))==-1){
					printf("Incorrect file name or variable name\n");
					free(input);
					return;
			  	  }	
				  try_flag = 0;
				  break;

			case 'b':
			case 'B': printf("Input binary file name: ");
				  scanf("%s",input_bin);
		  		  if((shellcode_read_binary(input, input_bin))==-1){
					printf("Incorrect file name or variable name\n");
					free(input);
					return;	
			  	  }
				  try_flag = 0;
			  	  break;
			default:  printf("Incorrect Option, want to try again? [y/n]");
				  scanf(" %s", try_choice);		
				  if((try_choice[0] == 'y')|(try_choice[0] == 'Y')){
					try_flag = 1;
					printf("Input file type: C or binary? [C/b]");
				        scanf(" %s",in_choice);
				  }
				  else {
					free(input);
					return;
				  }					
			  	  
		}
	}while(try_flag);		
	
	
	printf("Does the target system require instruction cache flush for self-modifying code?[y/n/c(can't say)]");
	scanf(" %s", flush_choice);
	switch(flush_choice[0]){
		case 'n':
		case 'N': icache_flush = 0;
			  break;
		case 'Y':
		case 'y':
		case 'c':
		case 'C':
		default:  icache_flush = 1;
	
	}
	struct Sshellcode* enc_data = shellcode_malloc();
	shellcode_zero(enc_data);
	enc_data_builder(enc_data,input);
	
	struct Sshellcode* dec_loop = shellcode_malloc();
	shellcode_zero(dec_loop);
	DecoderLoopBuilder(dec_loop,icache_flush);
	
	struct Sshellcode* enc_dec_loop = shellcode_malloc();
	shellcode_zero(enc_dec_loop);
	encDecoderLoopBuilder(enc_dec_loop, dec_loop);
	
	struct Sshellcode* dec = shellcode_malloc();
	shellcode_zero(dec);
	DecoderBuilder(dec, dec_loop, icache_flush);

	struct Sshellcode* Init = shellcode_malloc();
	shellcode_zero(Init);
	buildInit(Init, dec);	
	
	struct Sshellcode* output = shellcode_malloc();
	shellcode_zero(output);
	shellcode_cat(output,Init);
	//printf("Initializer:\n");
	//shellcode_hex_print(output);
	
	shellcode_cat(output, dec);
	shellcode_cat(output, enc_dec_loop);
	shellcode_cat(output, enc_data);
	
	printf("Output file type: C or binary? [C/b] ");
	scanf(" %s",out_choice);
	try_flag = 0;
	do{
	        switch(out_choice[0]){
        	        case 'c':
               	 	case 'C': printf("Output C file name: ");
                        	  scanf("%s", output_C);
                          	  if((shellcode_write_C(output, output_C))==-1){
                                	printf("Error while writing to output file \n");
                                
                          	  }
			  	  try_flag = 0;
                          	  break;

                	case 'b':
                	case 'B': printf("Output binary file name: ");
                        	  scanf("%s",output_bin);
                        	  if((shellcode_write_binary(output, output_bin))==-1){
                               		 printf("Error while writing to file\n");
                                
                         	   }
			  	  try_flag = 0;
                          	  break;
                	default:  printf("Incorrect Option\n");
                        	  printf("Want to try again? [y/n] ");
			 	  scanf(" %s", try_choice);
				  if((try_choice[0] == 'y')|(try_choice[0] == 'Y')){
                        	   	try_flag = 1;
					printf("Output file type: C or binary? [C/b] ");
				        scanf(" %s",out_choice);
				  }
			       	  else
					try_flag = 0;
        	}
	}while(try_flag);

	//shellcode_hex_print(output);
 	//shellcode_print(output);	
	//shellcode_write_binary(output, "shspbin");
	//shellcode_write_C(output, "addusr.c");
	//shellcode_print(Init);
	//shellcode_print(dec);
	//shellcode_hex_print(dec);	
	//shellcode_hex_print(dec_loop);
	//shellcode_hex_print(enc_dec_loop);
	
	/*printf("Initializer\n");
	shellcode_hex_print(Init);
	printf("\nDecoder\n");
	shellcode_hex_print(dec);
	printf("\nDecoder_Loop\n");
	shellcode_hex_print(dec_loop);*/
	//printf("\nEncoded_Data\n");
	//shellcode_hex_print(enc_data);

	printf("The alphanumeric shellcode:\n");
	shellcode_print(output);
	printf("Shellcode Length: %d\n", output->size);
	
	free(Init);
	free(dec);
	free(enc_dec_loop);
	free(dec_loop);
	free(enc_data);	
	free(input);
	free(output);	
}
