arm_alnum: asc_ARM_main.o builder.o random_funcs.o shellcode_funcs.o ARM_Instructions.o alphanum_byte.o 
	gcc -g -o arm_alnum asc_ARM_main.o builder.o random_funcs.o shellcode_funcs.o ARM_Instructions.o alphanum_byte.o

asc_ARM_main.o: asc_ARM_main.c 
	gcc -g -c asc_ARM_main.c
builder.o: builder.c
	gcc -g -c builder.c
random_funcs.o: random_funcs.c
	gcc -c -g random_funcs.c
shellcode_funcs.o: shellcode_funcs.c
	gcc -c -g shellcode_funcs.c
ARM_Instructions.o: ARM_Instructions.c
	gcc -c -g ARM_Instructions.c
alphanum_byte.o: alphanum_byte.c
	gcc -c -g alphanum_byte.c
	 
