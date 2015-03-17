#include<string.h>
#include<stdlib.h>
#include<stdio.h>




/* +------------------------------------------------------------------------+ */
/* |                         SHELLCODES FUNCTIONS                           | */
/* +------------------------------------------------------------------------+ */

/* this structure will contain all our shellcodes */
/* ============================================== */
struct Sshellcode {
 unsigned char* opcodes; /* opcodes bytes */
 int size; /* size of the opcodes bytes */
};


/* allocate a new Sshellcode structure */
/* =================================== */
struct Sshellcode *shellcode_malloc() {
 struct Sshellcode *ret;

 if ((ret=(struct Sshellcode*)malloc(sizeof(struct Sshellcode)))!=NULL) {
  ret->opcodes=NULL;
  ret->size=0;
 }
 return ret;
}


/* initialize an existing Sshellcode structure */
/* =========================================== */
void shellcode_zero(struct Sshellcode *shellcode) {
 if (shellcode==NULL) return;

 if (shellcode->opcodes!=NULL) free(shellcode->opcodes);
 shellcode->opcodes=NULL;
 shellcode->size=0;
}


/* free an existing Sshellcode structure */
/* ===================================== */
void shellcode_free(struct Sshellcode *shellcode) {
 if (shellcode!=NULL) {
  shellcode_zero(shellcode);
  free(shellcode);
 }
}


/* return an allocated string from an existing Sshellcode */
/* ====================================================== */
char *shellcode_malloc_string(struct Sshellcode *shellcode) {
 char *ret;

 if (shellcode==NULL) return NULL;

 if (shellcode->opcodes==NULL) return "";

 if ((ret=(char*)malloc(shellcode->size+1))==NULL) return NULL;
 memcpy(ret,shellcode->opcodes,shellcode->size);
 ret[shellcode->size]=0;
 return ret;
}


/* overwrite an existing Sshellcode with a Sshellcode */
/* ================================================== */
struct Sshellcode *shellcode_cpy(struct Sshellcode *destination,struct Sshellcode *source) {
 if (destination==NULL) return NULL;

 shellcode_zero(destination);

 if (source!=NULL) {
  if (source->opcodes!=NULL) { /* if source contains a shellcode, we copy it */
   if ((destination->opcodes=(unsigned char*)malloc(source->size))==NULL) return NULL;
   memcpy(destination->opcodes,source->opcodes,source->size);
   destination->size=source->size;
  }
 }

 return destination;
}


/* append a Sshellcode at the end of an existing Sshellcode */
/* ======================================================== */
struct Sshellcode *shellcode_cat(struct Sshellcode *destination,struct Sshellcode *source) {
 if (destination==NULL) return NULL;

 if (destination->opcodes==NULL) shellcode_cpy(destination,source);
 else { /* destination already contains a shellcode */

  if (source!=NULL) {
   if (source->opcodes!=NULL) { /* if source contain a shellcode, we copy it */

    if ((destination->opcodes=(unsigned char*)realloc(destination->opcodes,destination->size+source->size))==NULL) return NULL;
    memcpy(destination->opcodes+destination->size,source->opcodes,source->size);
    destination->size+=source->size;
   }
  }
 }
 return destination;
}


/* add a byte at the end of an existing Sshellcode */
/* =============================================== */
struct Sshellcode *shellcode_db(struct Sshellcode *destination,unsigned char c) {
 struct Sshellcode *ret,*tmp;

 /* build a tiny one byte Sshellcode */
 tmp=shellcode_malloc();
 if ((tmp->opcodes=(unsigned char*)malloc(1))==NULL) return NULL;
 tmp->opcodes[0]=c;
 tmp->size=1;

 /* copy it at the end of the existing Sshellcode */
 ret=shellcode_cat(destination,tmp);
 shellcode_free(tmp);
 return ret;
}


/* read a Sshellcode from a binary file */
/* ==================================== */
int shellcode_read_binary(struct Sshellcode *shellcode,char *filename) {
 FILE *f;
 int size;

 if (shellcode==NULL) return -1;

 if ((f=fopen(filename,"r+b"))==NULL) return -1;

 fseek(f,0,SEEK_END);
 size=(int)ftell(f);
 fseek(f,0,SEEK_SET);

 if ((shellcode->opcodes=(unsigned char*)realloc(shellcode->opcodes,shellcode->size+size))==NULL) return -1;
 if (fread(shellcode->opcodes+shellcode->size,size,1,f)!=1) {
  shellcode_zero(shellcode);
  return -1;
 }
 shellcode->size+=size;
 fclose(f);
 return shellcode->size;
}


/* read a Sshellcode from a C file */
/* =============================== */
#define LINE_SIZE 80*256
#define HEXADECIMALS "0123456789ABCDEF"

int shellcode_read_C(struct Sshellcode *shellcode,char *filename,char *variable) {
 FILE *f;
 struct Sshellcode *binary;
 unsigned char *hex,*p,c;
 int i;

 if (shellcode==NULL) return -1;

 hex=HEXADECIMALS;
 binary=shellcode_malloc();
 if (shellcode_read_binary(binary,filename)==-1) {
  shellcode_free(binary);
  return -1;
 }
 shellcode_db(binary,0); /* for string searching */
 p=binary->opcodes;

 while (p=strstr(p,"char ")) { /* "char " founded */
  p+=5;
  while (*p==' ') p++;
  if (!variable) { /* if no variable was specified */ /*then the first char array would be read as input*/
   while ((*p!=0)&&(*p!='[')) p++; /* search for the '[' */
   if (*p==0) {
   shellcode_free(binary);
    return -1;
   }
  }
  else { /* a variable was specified */
   if (memcmp(p,variable,strlen(variable))) continue; /* compare the variable */
   p+=strlen(variable);
   if (*p!='[') continue;
  }
  /* *p='[' */
  p++;
  if (*p!=']') continue;
  /* *p=']' */
  p++;
  while ((*p==' ')||(*p=='\r')||(*p=='\n')||(*p=='\t')) p++;
  if (*p!='=') continue;
  /* *p='=' */
  p++;
  while (1) { /* search for the beginning of a "string" */
   while ((*p==' ')||(*p=='\r')||(*p=='\n')||(*p=='\t')) p++;

   while ((*p=='/')&&(*(p+1)=='*')) { /* loop until the beginning of a comment */
    p+=2;
    while ((*p!='*')||(*(p+1)!='/')) p++; /* search for the end of the comment */
    p+=2;
    while ((*p==' ')||(*p=='\r')||(*p=='\n')||(*p=='\t')) p++;
   }

   if (*p!='"') break; /* if this is the end of all "string" */
   /* *p=begin '"' */
   p++;
   while (*p!='"') { /* loop until the end of the "string" */
    if (*p!='\\') {
     shellcode_db(shellcode,*p);
    }
    else {
     /* *p='\' */
     p++;
     if (*p=='x') {
      /* *p='x' */
      p++;
      *p=toupper(*p);
      for (i=0;i<strlen(hex);i++) if (hex[i]==*p) c=i<<4; /* first digit */
      p++;
      *p=toupper(*p);
      for (i=0;i<strlen(hex);i++) if (hex[i]==*p) c=c|i; /* second digit */
      shellcode_db(shellcode,c); 
     }  
    }
    p++;
   }
   /* end of a "string" */
   p++;
  }
  /* end of all "string" */
  shellcode_free(binary);
  return shellcode->size;
 }
 shellcode_free(binary);
 return -1;
}


/* write a Sshellcode to a binary file */
/* =================================== */
int shellcode_write_binary(struct Sshellcode *shellcode,char *filename) {
 FILE *f;

 if (shellcode==NULL) return -1;

 if ((f=fopen(filename,"w+b"))==NULL) return -1;

 if (fwrite(shellcode->opcodes,shellcode->size,1,f)!=1) return -1;
 fclose(f);
 return shellcode->size;
}


/* write a Sshellcode to a C file */
/* ============================== */
int shellcode_write_C(struct Sshellcode *shellcode,char *filename) {
 FILE *f;
 char *tmp;
 int size;

 if (shellcode==NULL) return -1;

 if ((tmp=shellcode_malloc_string(shellcode))==NULL) return -1;

 if ((f=fopen(filename,"w+b"))==NULL) return -1; 

 fprintf(f,"#include<stdio.h>\n");
 fprintf(f,"#include<string.h>\n");	
 fprintf(f,"char shellcode[]=\"%s\";\n",tmp);
 free(tmp);
 fprintf(f,"\n");
 fprintf(f,"int main() {\n");
 //fprintf(f," int *ret;\n");

 size=1;
 while (shellcode->size*2>size) size*=2;

 fprintf(f,"\tprintf(\"Length:%%d\", strlen(shellcode));");
 fprintf(f,"\n");
 /*fprintf(f," strcpy(buffer,shellcode);\n");
 fprintf(f," ret=(int*)&ret+2;\n");*/
 fprintf(f,"\t(*(void(*)())shellcode)();\n");
 fprintf(f,"\treturn 0; \n");
 fprintf(f,"}\n");

 fclose(f);
 return shellcode->size;
}


/* print a Sshellcode on the screen */
/* ================================ */
int shellcode_print(struct Sshellcode *shellcode) {
 char *tmp;

 if (shellcode==NULL) return -1;

 if ((tmp=shellcode_malloc_string(shellcode))==NULL) return -1;
 printf("%s\n",tmp);
 free(tmp);
 return shellcode->size;
}

void shellcode_hex_print(struct Sshellcode* shellcode){
	if(shellcode == NULL)
		return;
	if(shellcode->opcodes == NULL)
		return;
	int i = 0;
	for(; i < shellcode->size; ++i){
		printf("%2x ", shellcode->opcodes[i]);
	}
	printf("\n");
}
