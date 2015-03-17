

/* +------------------------------------------------------------------------+ */
/* |                        ARM Instructions                                | */
/* +------------------------------------------------------------------------+ */


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


/* (EOR/SUB/RSB)(PL/MI){S} rd, rn, #imm */
/* ==================================== */
void dpimm(struct Sshellcode* x, unsigned char op, unsigned char cond, unsigned char s, unsigned char d, unsigned char n, unsigned char imm){
	shellcode_db(x,imm);
	d = (d<<4);
	shellcode_db(x,d);
	if(s){
		if(op == EOR)
			shellcode_db(x, (0x30|n));
		if(op == SUB)
			shellcode_db(x, (0x50|n));
		if(op == RSB)
			shellcode_db(x,(0x70|n));		
	}				
	else{
		if(op == SUB)
			shellcode_db(x, (0x40|n));
		if(op == RSB)
			shellcode_db(x,(0x60|n));
	}
	if(cond == PL){
		shellcode_db(x, 0x52);
	}
	else{
		shellcode_db(x, 0x42);
	}
}

/* (EOR/SUB/RSB)PL{S} rd, rn, ra ROR #imm */
/* ====================================== */
void dpshiftimm(struct Sshellcode* x, unsigned char op, unsigned char s, unsigned char d, unsigned char n, unsigned char a, unsigned char imm){
	shellcode_db(x, ((0x60)|a));
	shellcode_db(x, (d<<4)|(imm>>1));
	if(s){
		if(op == EOR)
			shellcode_db(x, (0x30|n));
		if(op == SUB)
			shellcode_db(x, (0x50|n));
		if(op == RSB)
			shellcode_db(x,(0x70|n));		
	}				
	else{
		if(op == SUB)
			shellcode_db(x, (0x40|n));
		if(op == RSB)
			shellcode_db(x,(0x60|n));
	}
	shellcode_db(x, 0x50);	
}


/* (EOR/SUB/RSB)PL{S} rd, rn, ra (ROR/LSR) rb */
/* ========================================== */
void dpshiftreg(struct Sshellcode* x, unsigned char op, unsigned char s, unsigned char d, unsigned char n, unsigned char a, unsigned char shift, unsigned char b){
	if(shift == LSR)
		shellcode_db(x, ((0x30)|a));
	else	
		shellcode_db(x, ((0x70)|a));
	shellcode_db(x, (d<<4)|b);
	if(s){
		if(op == EOR)
			shellcode_db(x, (0x30|n));
		if(op == SUB)
			shellcode_db(x, (0x50|n));
		if(op == RSB)
			shellcode_db(x,(0x70|n));		
	}				
	else{
		if(op == SUB)
			shellcode_db(x, (0x40|n));
		if(op == RSB)
			shellcode_db(x,(0x60|n));
	}
	shellcode_db(x, 0x50);
}


/* (LDR/STR)(PL/MI)B rd, [rn, #-imm] */
/* ================================= */
void lsbyte(struct Sshellcode* x, unsigned char op, unsigned char cond, unsigned char d, unsigned char n, unsigned char imm){
	shellcode_db(x, imm);
	shellcode_db(x, (d<<4));
	if(op == STR)
		shellcode_db(x, ((0x40)|n));
	else 
		shellcode_db(x, ((0x50)|n));
	if(cond == PL)
		shellcode_db(x, 0x55);
	else
		shellcode_db(x, 0x45);		
}


/* STMPLFD rd, (Register List)^ */
/* ============================ */
void smul(struct Sshellcode* x, unsigned char d, unsigned char reglH, unsigned char reglL){
	shellcode_db(x, reglL);
	shellcode_db(x, reglH);
	shellcode_db(x, (0x40)|d);
	shellcode_db(x,0x59);
}


/* LDMPLDB rn!, (Register List) */
/* ============================ */
void lmul(struct Sshellcode* x, unsigned char n, unsigned char reglH, unsigned char reglL){
	shellcode_db(x, reglL);	
	shellcode_db(x, reglH);
	shellcode_db(x, (0x30)|n);	
	shellcode_db(x,0x59);
}


/* SWI(PL/MI) 0x9f0002 */
/* ============== */
void swi(struct Sshellcode* x, unsigned char cond){
	shellcode_db(x,0x02);
	shellcode_db(x,0x00);
	shellcode_db(x,0x9f);
	if(cond == MI)
		shellcode_db(x,0x4f);
	else
		shellcode_db(x,0x5f);
}


/* BMI 0xfffff4 */
/* ============ */
void bmi(struct Sshellcode* x){
	shellcode_db(x, 0xf4);
	shellcode_db(x, 0xff);
	shellcode_db(x, 0xff);
	shellcode_db(x, 0x4b);
}

/* STRPLB rd, [!rn, -(rm ROR #imm)] with P=0 i.e. post-indexed addressing mode */
/* =========================================================================== */
sbyteposti(struct Sshellcode* x, unsigned char d, unsigned char n, unsigned char m, unsigned char imm){
	shellcode_db(x, ((0x60)|m));
	shellcode_db(x, ((d<<4)|(imm>>1)));
	shellcode_db(x, ((0x40)|n));
	shellcode_db(x, 0x56);
}


