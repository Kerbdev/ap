/*
 * sd.c
 *
 *  Created on: Feb 26, 2014
 *      Author: ivan
 */

#include "crypto.h"
/*int main(){
char *p="Hewlefwecpowkfpwkepofkwpfkwp";
char *z="NENNEFNEOIFEOIF";
char *hash=malloc(32);
char *out=malloc(32);
gost_get_hash(z,hash);
enc_gost(hash,p,out);
printf("%s",out);
char *aaa;
dec_gost(hash,out,&aaa);
printf("%s",aaa);
free(aaa);
return 0;



}*/
void gost_get_hash(char *set_string,char *get_hash){
	  hash_256((unsigned char *) set_string,strlen(set_string),(unsigned char *)get_hash);
}
void enc_gost(char *set_hash,char *in,char *out,int n_blocks){
	  gost_ctx *c=(gost_ctx *)malloc(sizeof(gost_ctx));
	  gost_subst_block *b=NULL;
	  gost_init(c,b);
	  gost_key(c,(byte *)set_hash);
	  	  gost_enc(c,(byte *)in,(byte *)out,n_blocks);
	free(c);}
void dec_gost(char *set_hash,char *in,char **out,int n_blocks){
		  gost_ctx *c=(gost_ctx *)malloc(sizeof(gost_ctx));
		  gost_subst_block *b=NULL;
		  gost_init(c,b);
		  gost_key(c,(byte *)set_hash);
		  	  //*out=NULL;
		  	  //*out=(char *)malloc(n_blocks*8);
		  gost_dec(c,(byte *)in,(byte *) *out,n_blocks);
}

