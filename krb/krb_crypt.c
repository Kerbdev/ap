/*
 * krb_crypt.c
 *
 *  Created on: Apr 4, 2014
 *      Author: ivan
 */
#include "../crypto/crypto.h"
#include "krb.h"
#include <stdlib.h>
#include <openssl/rand.h>
void change_bit(char **data,int *size);
void restore_bit(char **data,int *size);
void krb5_crypt_enc_data(krb5_enc_data *data,char *pass){
	char *get_hash=malloc(sizeof(int)*8);
	int len_enc_data=0;
	char bufff[512];
	int c=snprintf(bufff,256,"%d ",data->enctype);
	c=snprintf(bufff+c,256-c,"%d ",data->kvno)+c;
	c=snprintf(bufff+c,256-c,"%d ",data->ciphertext.magic)+c;
	c=snprintf(bufff+c,256-c,"%d ",data->ciphertext.length)+c;
	c=strlen(bufff);

	gost_get_hash(pass,get_hash);
	if(data->ciphertext.data==NULL)
	len_enc_data=c;
	else len_enc_data=c+strlen(data->ciphertext.data)+1;
	int n_blocks=1;
	while(len_enc_data>8){
		len_enc_data-=8;
			  		  n_blocks++;}
	char *array=malloc(n_blocks*8);
	memcpy(array,bufff,c);
	if(data->ciphertext.data!=NULL){
	memcpy(array+c,data->ciphertext.data,strlen(data->ciphertext.data));
	memset(array+c+strlen(data->ciphertext.data),'\0',1);}
	int l=n_blocks*8;
					char *out=malloc(l);
					enc_gost(get_hash,array,out,n_blocks);
					change_bit(&out,&l);
	if(data->ciphertext.data!=NULL)
	free(data->ciphertext.data);
	memset(data,'\0',sizeof(krb5_enc_data));
		data->ciphertext.data=realloc(data->ciphertext.data,l+1);
		memcpy(data->ciphertext.data,out,l+1);
		memset(data->ciphertext.data+l,'\0',1);
	free(get_hash);
	free(out);
	free(array);


}
void krb5_decrypt_enc_data(krb5_enc_data *data,char *pass){
	char *get_hash=malloc(sizeof(int)*8);
	int len_enc_data=0;
	len_enc_data=strlen(data->ciphertext.data);
	restore_bit(&data->ciphertext.data,&len_enc_data);
		int n_blocks=1;
		while(len_enc_data>8){
			len_enc_data-=8;
				  		  n_blocks++;}
		char *array=malloc(n_blocks*8);
		memcpy(array,data->ciphertext.data,n_blocks*8);
		gost_get_hash(pass,get_hash);
		char *out=malloc(n_blocks*8);
		dec_gost(get_hash,array,&out,n_blocks);
		if(data->ciphertext.data!=NULL)
			free(data->ciphertext.data);
		memset(data,'\0',sizeof(krb5_enc_data));
		char *pc=strtok(out," ");
		data->enctype=atoi(pc);
		pc=strtok(NULL," ");
		data->kvno=atoi(pc);
		pc=strtok(NULL," ");
		data->ciphertext.length=atoi(pc);
		pc=strtok(NULL," ");
		data->ciphertext.magic=atoi(pc);
		pc=strtok(NULL,"");
		if(pc!=NULL){
			data->ciphertext.data=malloc(strlen(pc)+1);
			strcpy(data->ciphertext.data,pc);
		}
		free(get_hash);
		free(out);
		free(array);
}
void krb5_crypt_tkt_part(krb5_enc_tkt_part *data,char *pass){
	char *get_hash=malloc(sizeof(int)*8);
		int len_enc_data=0;
		char bufff[512];
		int c=snprintf(bufff,256,"%d ",data->times.authtime);
		c=snprintf(bufff+c,256-c,"%d ",data->times.endtime)+c;
		c=snprintf(bufff+c,256-c,"%d ",data->times.renew_till)+c;
		c=snprintf(bufff+c,256-c,"%d ",data->times.starttime)+c;
		c=snprintf(bufff+c,256-c,"%d ",data->authorization_data->magic)+c;
		c=snprintf(bufff+c,256-c,"%d ",data->authorization_data->ad_type)+c;
		c=snprintf(bufff+c,256-c,"%d ",data->authorization_data->length)+c;
		c=strlen(bufff);
		gost_get_hash(pass,get_hash);
			if(data->authorization_data->contents==NULL)
			len_enc_data=c;
			else len_enc_data=c+strlen(data->authorization_data->contents);
			int n_blocks=1;
			while(len_enc_data>8){
				len_enc_data-=8;
					  		  n_blocks++;}
			char *array=malloc(n_blocks*8);
			memset(array,'\0',n_blocks*8);
			memcpy(array,bufff,c);
			if(data->authorization_data->contents!=NULL){
			memcpy(array+c,data->authorization_data->contents,strlen(data->authorization_data->contents));
			memset(array+c+strlen(data->authorization_data->contents),'\0',1);}
			int l=n_blocks*8;
							char *out=malloc(l);
							enc_gost(get_hash,array,out,n_blocks);
							change_bit(&out,&l);
			if(data->authorization_data->contents!=NULL)
				free(data->authorization_data->contents);
			memset(data->authorization_data,'\0',sizeof(krb5_authdata));
			data->authorization_data->contents=realloc(data->authorization_data->contents,l+1);
				memcpy(data->authorization_data->contents,out,l+1);
				memset(data->authorization_data->contents+l,'\0',1);
			free(get_hash);
			free(out);
			free(array);
			krb5_crypt_keyblocks(data->session,pass);
						krb5_crypt_address(data->caddrs,pass);
						krb5_crypt_principal_data(data->client,pass);
						krb5_crypt_transited(&data->transited,pass);


		}
void krb5_crypt_keyblocks(krb5_keyblock *data,char *pass){
	char *get_hash=malloc(sizeof(int)*8);
		int len_enc_data=0;
		char bufff[512];
		int c=snprintf(bufff,256,"%d ",data->magic);
		c=snprintf(bufff+c,256-c,"%d ",data->enctype)+c;
		c=snprintf(bufff+c,256-c,"%d ",data->length)+c;
		c=strlen(bufff);
		gost_get_hash(pass,get_hash);
			if(data->contents==NULL)
			len_enc_data=c;
			else len_enc_data=c+strlen(data->contents);
			int n_blocks=1;
			while(len_enc_data>8){
				len_enc_data-=8;
					  		  n_blocks++;}
			char *array=malloc(n_blocks*8);
			memset(array,'\0',n_blocks*8);
			memcpy(array,bufff,c);
			if(data->contents!=NULL){
			memcpy(array+c,data->contents,strlen(data->contents));
			memset(array+c+strlen(data->contents),'\0',1);}
			int l=n_blocks*8;
							char *out=malloc(l);
							enc_gost(get_hash,array,out,n_blocks);
							change_bit(&out,&l);
			if(data->contents!=NULL)
				free(data->contents);
			memset(data,'\0',sizeof(krb5_keyblock));
				data->contents=realloc(data->contents,l+1);
				memcpy(data->contents,out,l+1);
				memset(data->contents+l,'\0',1);
			free(get_hash);
			free(out);
			free(array);
}

void krb5_decrypt_keyblocks(krb5_keyblock *data,char *pass){
	char *get_hash=malloc(sizeof(int)*8);
		int len_enc_data=0;
		len_enc_data=strlen(data->contents);
		restore_bit(&data->contents,&len_enc_data);
			int n_blocks=1;
			while(len_enc_data>8){
				len_enc_data-=8;
					  		  n_blocks++;}
			char *array=malloc(n_blocks*8);
			memcpy(array,data->contents,n_blocks*8);
			gost_get_hash(pass,get_hash);
			char *out=malloc(n_blocks*8);
			dec_gost(get_hash,array,&out,n_blocks);
			memset(data,'\0',sizeof(krb5_keyblock));
			char *pc=strtok(out," ");
			data->magic=atoi(pc);
			pc=strtok(NULL," ");
			data->enctype=atoi(pc);
			pc=strtok(NULL," ");
			data->length=atoi(pc);
			pc=strtok(NULL,"");
			if(pc!=NULL){
				data->contents=malloc(strlen(pc)+1);
				strcpy(data->contents,pc);
			}
			free(get_hash);
			free(out);
			free(array);
	}
void krb5_crypt_address(krb5_address *data,char *pass){
	char *get_hash=malloc(sizeof(int)*8);
		int len_enc_data=0;
		char bufff[512];
		int c=snprintf(bufff,256,"%d ",data->magic);
		c=snprintf(bufff+c,256-c,"%d ",data->addrtype)+c;
		c=snprintf(bufff+c,256-c,"%d ",data->length)+c;
		c=strlen(bufff);
		gost_get_hash(pass,get_hash);
			if(data->contents==NULL)
			len_enc_data=c;
			else len_enc_data=c+strlen(data->contents);
			int n_blocks=1;
			while(len_enc_data>8){
				len_enc_data-=8;
					  		  n_blocks++;}
			char *array=malloc(n_blocks*8);
			memset(array,'\0',n_blocks*8);
			memcpy(array,bufff,c);
			if(data->contents!=NULL){
			memcpy(array+c,data->contents,strlen(data->contents));
			memset(array+c+strlen(data->contents),'\0',1);}
			int l=n_blocks*8;
			char *out3=malloc(l);
			memset(out3,'\0',l);
			enc_gost(get_hash,array,out3,n_blocks);
			change_bit(&out3,&l);
			memset(data,'\0',sizeof(krb5_address));
				data->contents=realloc(data->contents,l+1);
				memcpy(data->contents,out3,l+1);
				memset(data->contents+l,'\0',1);
			free(get_hash);
			free(out3);
			free(array);
}
void krb5_decrypt_address(krb5_address *data,char *pass){
	char *get_hash=malloc(sizeof(int)*8);
			int len_enc_data=0;
			len_enc_data=strlen(data->contents);
			restore_bit(&data->contents,&len_enc_data);
				int n_blocks=1;
				while(len_enc_data>8){
					len_enc_data-=8;
						  		  n_blocks++;}
				char *array=malloc(n_blocks*8+1);
				memset(array,'\0',n_blocks*8+1);
				memcpy(array,data->contents,n_blocks*8);
				gost_get_hash(pass,get_hash);
				char *out=malloc(n_blocks*8);
				dec_gost(get_hash,array,&out,n_blocks);
				memset(data,'\0',sizeof(krb5_address));
				char *pc=strtok(out," ");
				data->magic=atoi(pc);
				pc=strtok(NULL," ");
				data->addrtype=atoi(pc);
				pc=strtok(NULL," ");
				data->length=atoi(pc);
				pc=strtok(NULL,"");
				if(pc!=NULL){
					data->contents=malloc(strlen(pc)+1);
					strcpy(data->contents,pc);
				}
				free(get_hash);
				free(out);
				free(array);
		}
void krb5_crypt_principal_data(krb5_principal_data *data,char *pass){
	char *get_hash=malloc(sizeof(int)*8);
			int len_enc_data=0;
			int len_enc_data2=0;
			char bufff[512];
			char bufff2[512];
			int c=snprintf(bufff,256,"%d ",data->magic);
			c=snprintf(bufff+c,256-c,"%d ",data->length)+c;
			c=snprintf(bufff+c,256-c,"%d ",data->type)+c;
			c=snprintf(bufff+c,256-c,"%d ",data->realm.length)+c;
			c=snprintf(bufff+c,256-c,"%d ",data->realm.magic)+c;
			c=strlen(bufff);
			int c2=snprintf(bufff2,256,"%d ",data->magic);
			c2=snprintf(bufff2+c2,256-c2,"%d ",data->length)+c2;
			c2=strlen(bufff2);
			gost_get_hash(pass,get_hash);
				if(data->realm.data==NULL)
				len_enc_data=c;
				else len_enc_data=c+strlen(data->realm.data)+1;
				if(data->data->data==NULL)
					len_enc_data2=c2;
				else len_enc_data2=c2+strlen(data->data->data)+1;
				int n_blocks=1;
				while(len_enc_data>8){
					len_enc_data-=8;
						  		  n_blocks++;}
				int n_blockd=1;
								while(len_enc_data2>8){
									len_enc_data2-=8;
										  		  n_blockd++;}
				char *array=malloc(n_blocks*8);
				memset(array,'\0',n_blocks*8);

				char *array2=malloc(n_blockd*8);
				memset(array2,'\0',n_blockd*8);
				memcpy(array,bufff,c);
				memcpy(array2,bufff2,c);
				if(data->realm.data!=NULL){
				memcpy(array+c,data->realm.data,strlen(data->realm.data));
				memset(array+c+strlen(data->realm.data),'\0',1);}
				if(data->data->data!=NULL){
				memcpy(array2+c2,data->data->data,strlen(data->data->data));
				memset(array+c+strlen(data->data->data),'\0',1);}
				int l=n_blocks*8;
				int l2=n_blockd*8;
				char *out=malloc(l);
								char *out2=malloc(l2);
								enc_gost(get_hash,array,out,n_blocks);
								change_bit(&out,&l);
								enc_gost(get_hash,array2,out2,n_blockd);
								change_bit(&out2,&l2);
				memset(data->data,'\0',sizeof(krb5_data));
				memset(data,'\0',sizeof(krb5_principal_data));

				data->data=malloc(sizeof(krb5_data));
					data->realm.data=realloc(data->realm.data,l+1);
					memcpy(data->realm.data,out,l+1);
					memset(data->realm.data+l,'\0',1);
					data->data->data=malloc(l2+1);
					memcpy(data->data->data,out2,l2+1);
					memset(data->data->data+l2,'\0',1);
				free(get_hash);
				free(out);
				free(array);
				free(out2);
								free(array2);

}
void krb5_decrypt_principal_data(krb5_principal_data *data,char *pass){
	char *get_hash=malloc(sizeof(int)*8);
				int len_enc_data=0;
				len_enc_data=strlen(data->realm.data);
				restore_bit(&data->realm.data,&len_enc_data);
				int len_enc_data2=0;
				len_enc_data2=strlen(data->data->data);
				restore_bit(&data->data->data,&len_enc_data2);
					int n_blocks=1;
					while(len_enc_data>8){
						len_enc_data-=8;
							  		  n_blocks++;}
					int n_blocks2=1;
					while(len_enc_data2>8){
						len_enc_data2-=8;
							  		  n_blocks2++;}
					char *array=malloc(n_blocks*8);
					char *array2=malloc(n_blocks2*8);
					memcpy(array,data->realm.data,n_blocks*8);
					memcpy(array2,data->data->data,n_blocks2*8);
					gost_get_hash(pass,get_hash);
					char *out=malloc(n_blocks*8);
					char *out2=malloc(n_blocks2*8);
					dec_gost(get_hash,array,&out,n_blocks);
					dec_gost(get_hash,array2,&out2,n_blocks2);
					memset(data,'\0',sizeof(krb5_principal_data));
					data->data=malloc(sizeof(krb5_data));
					char *pc=strtok(out," ");
					data->magic=atoi(pc);
					pc=strtok(NULL," ");
					data->length=atoi(pc);
					pc=strtok(NULL," ");
					data->type=atoi(pc);
					pc=strtok(NULL," ");
					data->realm.length=atoi(pc);
					pc=strtok(NULL," ");
					data->realm.magic=atoi(pc);
					pc=strtok(NULL,"");
					if(pc!=NULL){
						data->realm.data=malloc(strlen(pc)+1);
						strcpy(data->realm.data,pc);
					}
					char *pc2=strtok(out2," ");
					data->data->magic=atoi(pc2);
					pc2=strtok(NULL," ");
					data->data->length=atoi(pc2);
					pc2=strtok(NULL,"");
										if(pc2!=NULL){
											data->data->data=malloc(strlen(pc2)+1);
											strcpy(data->data->data,pc2);
										}
					free(get_hash);
					free(out);
					free(array);
					free(out2);
				free(array2);
			}
void krb5_crypt_transited(krb5_transited *data,char *pass){
	char *get_hash=malloc(sizeof(int)*8);
		int len_enc_data=0;
		char bufff[512];
		int c=snprintf(bufff,256,"%d ",data->magic);
		c=snprintf(bufff+c,256-c,"%d ",data->tr_type)+c;
		c=snprintf(bufff+c,256-c,"%d ",data->tr_contents.magic)+c;
		c=snprintf(bufff+c,256-c,"%d ",data->tr_contents.length)+c;
		c=strlen(bufff);
		gost_get_hash(pass,get_hash);
			if(data->tr_contents.data==NULL)
			len_enc_data=c;
			else len_enc_data=c+strlen(data->tr_contents.data)+1;
			int n_blocks=1;
			while(len_enc_data>8){
				len_enc_data-=8;
					  		  n_blocks++;}
			char *array=malloc(n_blocks*8);
			memcpy(array,bufff,c);
			if(data->tr_contents.data!=NULL){
			memcpy(array+c,data->tr_contents.data,strlen(data->tr_contents.data));
			memset(array+c+strlen(data->tr_contents.data),'\0',1);}
			int l=n_blocks*8;
							char *out=malloc(l);
							enc_gost(get_hash,array,out,n_blocks);
							change_bit(&out,&l);

			memset(data,'\0',sizeof(krb5_transited));
			data->tr_contents.data=realloc(data->tr_contents.data,l+1);
				memcpy(data->tr_contents.data,out,l+1);
				memset(data->tr_contents.data+l,'\0',1);
				data->magic=0;
				data->tr_type=0;
				data->tr_contents.magic=0;
				data->tr_contents.length=0;
			free(get_hash);
			free(out);
			free(array);
}

void krb5_decrypt_transited(krb5_transited *data,char *pass){
	char *get_hash=malloc(sizeof(int)*8);
		int len_enc_data=0;
		len_enc_data=strlen(data->tr_contents.data);
		restore_bit(&data->tr_contents.data,&len_enc_data);
			int n_blocks=1;
			while(len_enc_data>8){
				len_enc_data-=8;
					  		  n_blocks++;}
			char *array=malloc(n_blocks*8);
			memcpy(array,data->tr_contents.data,n_blocks*8);
			gost_get_hash(pass,get_hash);
			char *out=malloc(n_blocks*8);
			dec_gost(get_hash,array,&out,n_blocks);
			memset(data,'\0',sizeof(krb5_transited));
			char *pc=strtok(out," ");
			data->magic=atoi(pc);
			pc=strtok(NULL," ");
			data->tr_type=atoi(pc);
			pc=strtok(NULL," ");
			data->tr_contents.magic=atoi(pc);
			pc=strtok(NULL," ");
			data->tr_contents.length=atoi(pc);
			pc=strtok(NULL,"");
			if(pc!=NULL){
				data->tr_contents.data=malloc(strlen(pc)+1);
				strcpy(data->tr_contents.data,pc);
			}
			free(get_hash);
			free(out);
			free(array);
	}
void krb5_decrypt_tkt_part(krb5_enc_tkt_part *data,char *pass){
	char *get_hash=malloc(sizeof(int)*8);
		int len_enc_data=0;
		len_enc_data=strlen(data->authorization_data->contents);
		restore_bit(&data->authorization_data->contents,&len_enc_data);
			int n_blocks=1;
			while(len_enc_data>8){
				len_enc_data-=8;
					  		  n_blocks++;}
			char *array=malloc(n_blocks*8);
			memcpy(array,data->authorization_data->contents,n_blocks*8);
			gost_get_hash(pass,get_hash);
			char *out=malloc(n_blocks*8);
			krb5_decrypt_keyblocks(data->session,pass);
			krb5_decrypt_address(data->caddrs,pass);
			krb5_decrypt_principal_data(data->client,pass);
			krb5_decrypt_transited(&data->transited,pass);
			dec_gost(get_hash,array,&out,n_blocks);
			memset(data->authorization_data,'\0',sizeof(krb5_authdata));
			char *pc=strtok(out," ");
			data->times.authtime=atoi(pc);
			pc=strtok(NULL," ");
			data->times.endtime=atoi(pc);
			pc=strtok(NULL," ");
			data->times.renew_till=atoi(pc);
			pc=strtok(NULL," ");
			data->times.starttime=atoi(pc);
			pc=strtok(NULL," ");
			data->authorization_data->magic=atoi(pc);
			pc=strtok(NULL," ");
			data->authorization_data->ad_type=atoi(pc);
			pc=strtok(NULL," ");
			data->authorization_data->length=atoi(pc);
			pc=strtok(NULL,"");
			if(pc!=NULL){
				data->authorization_data->contents=malloc(strlen(pc)+1);
				strcpy(data->authorization_data->contents,pc);
			}
			free(get_hash);
			free(out);
			free(array);
	}

void krb5_crypt_kdc_rep_part(krb5_enc_kdc_rep_part *data,char *pass){
	char *get_hash=malloc(sizeof(int)*8);
			int len_enc_data=0;
			char bufff[512];
			int c=snprintf(bufff,512,"%d ",data->magic);
			c=snprintf(bufff+c,512-c,"%d ",data->msg_type)+c;
			c=snprintf(bufff+c,512-c,"%d ",data->last_req->magic)+c;
			c=snprintf(bufff+c,512-c,"%d ",data->last_req->lr_type)+c;
			c=snprintf(bufff+c,512-c,"%d ",data->last_req->value)+c;
			c=snprintf(bufff+c,512-c,"%d ",data->nonce)+c;
			c=snprintf(bufff+c,512-c,"%d ",data->key_exp)+c;
			c=snprintf(bufff+c,512-c,"%d ",data->flags)+c;
			c=snprintf(bufff+c,512-c,"%d ",data->times.authtime)+c;
			c=snprintf(bufff+c,512-c,"%d ",data->times.endtime)+c;
			c=snprintf(bufff+c,512-c,"%d ",data->times.renew_till)+c;
			c=snprintf(bufff+c,512-c,"%d ",data->times.starttime)+c;
			c=snprintf(bufff+c,512-c,"%d ",data->session->magic)+c;
			c=snprintf(bufff+c,512-c,"%d ",data->session->length)+c;
			c=snprintf(bufff+c,512-c,"%d ",data->session->enctype)+c;
			c=strlen(bufff);
			gost_get_hash(pass,get_hash);
				if(data->session->contents==NULL)
				len_enc_data=c;
				else len_enc_data=c+strlen(data->session->contents)+1;
				int n_blocks=1;
				while(len_enc_data>8){
					len_enc_data-=8;
						  		  n_blocks++;}
				//if(len_enc_data!=0)
					//n_blocks++;
				char *array=malloc(n_blocks*8);
				memcpy(array,bufff,c);
				if(data->session->contents!=NULL){
				memcpy(array+c,data->session->contents,strlen(data->session->contents));
				memset(array+c+strlen(data->session->contents),'\0',1);}
				int l=n_blocks*8;
				char *out=malloc(l);
				enc_gost(get_hash,array,out,n_blocks);
				change_bit(&out,&l);
				krb5_crypt_address(data->aaddrs,pass);
				krb5_crypt_principal_data(data->server,pass);
				memset(data->session,'\0',sizeof(krb5_keyblock));
				data->session->contents=realloc(data->session->contents,l+1);
					memcpy(data->session->contents,out,l+1);
					memset(data->session->contents+l,'\0',1);
					data->magic=0;
							data->msg_type=0;
							data->last_req->magic=0;
							data->last_req->lr_type=0;
							data->last_req->value=0;
							data->nonce=0;
							data->key_exp=0;
							data->flags=0;
							data->times.authtime=0;
							data->times.endtime=0;
							data->times.renew_till=0;
							data->times.starttime=0;
							data->session->magic=0;
							data->session->length=0;
							data->session->enctype=0;
				free(get_hash);
				free(out);
				free(array);
			}
void krb5_decrypt_kdc_rep_part(krb5_enc_kdc_rep_part *data,char *pass){
	char *get_hash=malloc(sizeof(int)*8);
		int len_enc_data=0;
		len_enc_data=strlen(data->session->contents);
		restore_bit(&data->session->contents,&len_enc_data);
			int n_blocks=1;
			while(len_enc_data>8){
				len_enc_data-=8;
				  		  n_blocks++;}
			char *array=malloc(n_blocks*8+1);
			memset(array,'\0',n_blocks*8+1);
			memcpy(array,data->session->contents,n_blocks*8);
			gost_get_hash(pass,get_hash);
			char *out=malloc(n_blocks*8);
			krb5_decrypt_address(data->aaddrs,pass);
			krb5_decrypt_principal_data(data->server,pass);
			dec_gost(get_hash,array,&out,n_blocks);
			memset(data->session,'\0',sizeof(krb5_keyblock));
			char *pc=strtok(out," ");
			data->magic=atoi(pc);
			pc=strtok(NULL," ");
			data->msg_type=atoi(pc);
			pc=strtok(NULL," ");
			data->last_req->magic=atoi(pc);
			pc=strtok(NULL," ");
			data->last_req->lr_type=atoi(pc);
			pc=strtok(NULL," ");
			data->last_req->value=atoi(pc);
			pc=strtok(NULL," ");
			data->nonce=atoi(pc);
			pc=strtok(NULL," ");
			data->key_exp=atoi(pc);
			pc=strtok(NULL," ");
			data->flags=atoi(pc);
			pc=strtok(NULL," ");
			data->times.authtime=atoi(pc);
			pc=strtok(NULL," ");
			data->times.endtime=atoi(pc);
			pc=strtok(NULL," ");
			data->times.renew_till=atoi(pc);
			pc=strtok(NULL," ");
			data->times.starttime=atoi(pc);
			pc=strtok(NULL," ");
			data->session->magic=atoi(pc);
			pc=strtok(NULL," ");
			data->session->length=atoi(pc);
			pc=strtok(NULL," ");
			data->session->enctype=atoi(pc);
			pc=strtok(NULL,"");
			if(pc!=NULL){
				data->session->contents=malloc(strlen(pc)+1);
				strcpy(data->session->contents,pc);
			}
			free(get_hash);
			free(out);
			free(array);
	}
void krb5_crypt_ap_rep_enc_part(krb5_ap_rep_enc_part *data,char *pass){
	char *get_hash=malloc(sizeof(int)*8);
				int len_enc_data=0;
				char bufff[512];
				int c=snprintf(bufff,512,"%d ",data->magic);
				c=snprintf(bufff+c,512-c,"%d ",data->ctime)+c;
				c=snprintf(bufff+c,512-c,"%d ",data->cusec)+c;
				c=snprintf(bufff+c,512-c,"%d ",data->seq_number)+c;
				c=snprintf(bufff+c,512-c,"%d ",data->subkey->magic)+c;
				c=snprintf(bufff+c,512-c,"%d ",data->subkey->length)+c;
				c=snprintf(bufff+c,512-c,"%d ",data->subkey->enctype)+c;
				c=strlen(bufff);
				gost_get_hash(pass,get_hash);
					if(data->subkey->contents==NULL)
					len_enc_data=c;
					else len_enc_data=c+strlen(data->subkey->contents)+1;
					int n_blocks=1;
					while(len_enc_data>8){
						len_enc_data-=8;
							  		  n_blocks++;}
					char *array=malloc(n_blocks*8);
					memcpy(array,bufff,c);
					if(data->subkey->contents!=NULL){
					memcpy(array+c,data->subkey->contents,strlen(data->subkey->contents));
					memset(array+c+strlen(data->subkey->contents),'\0',1);}
					int l=n_blocks*8;
										char *out=malloc(l);
										enc_gost(get_hash,array,out,n_blocks);
										change_bit(&out,&l);

					if(data->subkey->contents!=NULL)
						free(data->subkey->contents);
					data->ctime=0;
					data->cusec=0;
					data->magic=0;
					data->seq_number=0;
					data->subkey->contents=malloc(l+1);
						memcpy(data->subkey->contents,out,l+1);
						memset(data->subkey->contents+l,'\0',1);
					free(get_hash);
					free(out);
					free(array);
				}
void krb5_decrypt_ap_rep_enc_part(krb5_ap_rep_enc_part *data,char *pass){
	char *get_hash=malloc(sizeof(int)*8);
			int len_enc_data=0;
			len_enc_data=strlen(data->subkey->contents);
			restore_bit(&data->subkey->contents,&len_enc_data);
				int n_blocks=1;
				while(len_enc_data>8){
					len_enc_data-=8;
						  		  n_blocks++;}
				char *array=malloc(n_blocks*8);
				memcpy(array,data->subkey->contents,n_blocks*8);
				gost_get_hash(pass,get_hash);
				char *out=malloc(n_blocks*8);
				dec_gost(get_hash,array,&out,n_blocks);
				if(data->subkey->contents!=NULL)
										free(data->subkey->contents);
									data->ctime=0;
									data->cusec=0;
									data->magic=0;
									data->seq_number=0;
				char *pc=strtok(out," ");
				data->magic=atoi(pc);
				pc=strtok(NULL," ");
				data->ctime=atoi(pc);
				pc=strtok(NULL," ");
				data->cusec=atoi(pc);
				pc=strtok(NULL," ");
				data->seq_number=atoi(pc);
				pc=strtok(NULL," ");
				data->subkey->magic=atoi(pc);
				pc=strtok(NULL," ");
				data->subkey->length=atoi(pc);
				pc=strtok(NULL," ");
				data->subkey->enctype=atoi(pc);
				pc=strtok(NULL,"");
				if(pc!=NULL){
					data->subkey->contents=malloc(strlen(pc)+1);
					strcpy(data->subkey->contents,pc);
				}
				free(get_hash);
				free(out);
				free(array);
		}
void krb5_crypt_pa_data(krb5_pa_data *data,char *pass){
	char *get_hash=malloc(sizeof(int)*8);
					int len_enc_data=0;
					char bufff[512];
					int c=snprintf(bufff,512,"%d ",data->magic);
					c=snprintf(bufff+c,512-c,"%d ",data->length)+c;
					c=snprintf(bufff+c,512-c,"%d ",data->pa_type)+c;
					c=strlen(bufff);
					gost_get_hash(pass,get_hash);
						if(data->contents==NULL)
						len_enc_data=c;
						else len_enc_data=c+strlen(data->contents)+1;
						int n_blocks=1;
						while(len_enc_data>8){
							len_enc_data-=8;
								  		  n_blocks++;}
						char *array=malloc(n_blocks*8);
						memcpy(array,bufff,c);
						if(data->contents!=NULL){
						memcpy(array+c,data->contents,strlen(data->contents));
						memset(array+c+strlen(data->contents),'\0',1);}
						int l=n_blocks*8;
											char *out=malloc(l);
											enc_gost(get_hash,array,out,n_blocks);
											change_bit(&out,&l);
						if(data->contents!=NULL)
							free(data->contents);
						memset(data,'\0',sizeof(krb5_pa_data));
						data->contents=realloc(data->contents,l*8+1);
							memcpy(data->contents,out,l+1);
							memset(data->contents+l,'\0',1);
						free(get_hash);
						free(out);
						free(array);
					}
void krb5_decrypt_pa_data(krb5_pa_data *data,char *pass){
	char *get_hash=malloc(sizeof(int)*8);
			int len_enc_data=0;
			len_enc_data=strlen(data->contents);
			restore_bit(&data->contents,&len_enc_data);
				int n_blocks=1;
				while(len_enc_data>8){
					len_enc_data-=8;
						  		  n_blocks++;}
				char *array=malloc(n_blocks*8);
				memcpy(array,data->contents,n_blocks*8);
				gost_get_hash(pass,get_hash);
				char *out=malloc(n_blocks*8);
				dec_gost(get_hash,array,&out,n_blocks);
				if(data->contents!=NULL)
					free(data->contents);
				memset(data,'\0',sizeof(krb5_pa_data));
				char *pc=strtok(out," ");
				data->magic=atoi(pc);
				pc=strtok(NULL," ");
				data->length=atoi(pc);
				pc=strtok(NULL," ");
				data->pa_type=atoi(pc);
				pc=strtok(NULL,"");
				if(pc!=NULL){
					data->contents=malloc(strlen(pc)+1);
					strcpy(data->contents,pc);
				}
				free(get_hash);
				free(out);
				free(array);
		}
void krb5_crypt_checksum(krb5_checksum *data,char *pass){
	char *get_hash=malloc(sizeof(int)*8);
					int len_enc_data=0;
					char bufff[512];
					int c=snprintf(bufff,512,"%d ",data->length);
					c=snprintf(bufff+c,512-c,"%d ",data->magic)+c;
					c=snprintf(bufff+c,512-c,"%d ",data->checksum_type)+c;;
					c=strlen(bufff);
					gost_get_hash(pass,get_hash);
						if(data->contents==NULL)
						len_enc_data=c;
						else len_enc_data=c+strlen(data->contents)+1;
						int n_blocks=1;
						while(len_enc_data>8){
							len_enc_data-=8;
								  		  n_blocks++;}
						char *array=malloc(n_blocks*8);
						memcpy(array,bufff,c);
						if(data->contents!=NULL){
						memcpy(array+c,data->contents,strlen(data->contents));
						memset(array+c+strlen(data->contents),'\0',1);}
						int l=n_blocks*8;
											char *out=malloc(l);
											enc_gost(get_hash,array,out,n_blocks);
											change_bit(&out,&l);
						memset(data,'\0',sizeof(krb5_checksum));
						data->contents=realloc(data->contents,l+1);
							memcpy(data->contents,out,l+1);
							memset(data->contents+l,0,1);
						free(get_hash);
						free(out);
						free(array);
					}
void krb5_decrypt_checksum(krb5_checksum *data,char *pass){
	char *get_hash=malloc(sizeof(int)*8);
			int len_enc_data=0;
			len_enc_data=strlen(data->contents);
			restore_bit(&data->contents,&len_enc_data);
				int n_blocks=1;
				while(len_enc_data>8){
					len_enc_data-=8;
						  		  n_blocks++;}
				char *array=malloc(n_blocks*8);
				memcpy(array,data->contents,n_blocks*8);
				gost_get_hash(pass,get_hash);
				char *out=malloc(n_blocks*8);
				dec_gost(get_hash,array,&out,n_blocks);
				memset(data,'\0',sizeof(krb5_checksum));
				char *pc=strtok(out," ");
				data->length=atoi(pc);
				pc=strtok(NULL," ");
				data->magic=atoi(pc);
				pc=strtok(NULL," ");
				data->checksum_type=atoi(pc);
				pc=strtok(NULL,"");
				if(pc!=NULL){
					data->contents=malloc(strlen(pc)+1);
					strcpy(data->contents,pc);
				}
				free(get_hash);
				free(out);
				free(array);
		}
void krb5_crypt_authenticator(krb5_authenticator *data,char *pass){
	char *get_hash=malloc(sizeof(int)*8);
	int len_enc_data=0;
	char bufff[512];
	int c=snprintf(bufff,256,"%d ",data->magic);
	c=snprintf(bufff+c,256-c,"%d ",data->cusec)+c;
	c=snprintf(bufff+c,256-c,"%d ",data->ctime)+c;
	c=snprintf(bufff+c,256-c,"%d ",data->seq_number)+c;
	c=snprintf(bufff+c,256-c,"%d ",data->authorization_data->ad_type)+c;
	c=snprintf(bufff+c,256-c,"%d ",data->authorization_data->length)+c;
	c=snprintf(bufff+c,256-c,"%d ",data->authorization_data->magic)+c;
	c=strlen(bufff);

	gost_get_hash(pass,get_hash);
	if(data->authorization_data->contents==NULL)
	len_enc_data=c;
	else len_enc_data=c+strlen(data->authorization_data->contents)+1;
	int n_blocks=1;
	while(len_enc_data>8){
		len_enc_data-=8;
			  		  n_blocks++;}
	char *array=malloc(n_blocks*8);
	memcpy(array,bufff,c);
	if(data->authorization_data->contents!=NULL){
	memcpy(array+c,data->authorization_data->contents,strlen(data->authorization_data->contents));
	memset(array+c+strlen(data->authorization_data->contents),'\0',1);}
	int l=n_blocks*8;
					char *out=malloc(l);
					enc_gost(get_hash,array,out,n_blocks);
					change_bit(&out,&l);

	memset(data->authorization_data,'\0',sizeof(krb5_authdata));
	data->authorization_data->contents=realloc(data->authorization_data->contents,l+1);
		memcpy(data->authorization_data->contents,out,l+1);
		memset(data->authorization_data->contents+l,0,1);
	free(get_hash);
	free(out);
	free(array);
	krb5_crypt_checksum(data->checksum,pass);
	krb5_crypt_keyblocks(data->subkey,pass);
	krb5_crypt_principal_data(data->client,pass);
}
void krb5_decrypt_authenticator(krb5_authenticator *data,char *pass){
	char *get_hash=malloc(sizeof(int)*8);
			int len_enc_data=0;
			len_enc_data=strlen(data->authorization_data->contents);
			restore_bit(&data->authorization_data->contents,&len_enc_data);
				int n_blocks=1;
				while(len_enc_data>8){
					len_enc_data-=8;
						  		  n_blocks++;}
				char *array=malloc(n_blocks*8);
				memcpy(array,data->authorization_data->contents,n_blocks*8);
				gost_get_hash(pass,get_hash);
				char *out=malloc(n_blocks*8);
				krb5_decrypt_checksum(data->checksum,pass);
				krb5_decrypt_keyblocks(data->subkey,pass);
				krb5_decrypt_principal_data(data->client,pass);
				dec_gost(get_hash,array,&out,n_blocks);
				memset(data->authorization_data,'\0',sizeof(krb5_authdata));
				char *pc=strtok(out," ");
				data->magic=atoi(pc);
				pc=strtok(NULL," ");
				data->cusec=atoi(pc);
				pc=strtok(NULL," ");
				data->ctime=atoi(pc);
				pc=strtok(NULL," ");
				data->seq_number=atoi(pc);
				pc=strtok(NULL," ");
				data->authorization_data->ad_type=atoi(pc);
				pc=strtok(NULL," ");
				data->authorization_data->length=atoi(pc);
				pc=strtok(NULL," ");
				data->authorization_data->magic=atoi(pc);
				pc=strtok(NULL,"");
				if(pc!=NULL){
					data->authorization_data->contents=malloc(strlen(pc)+1);
					strcpy(data->authorization_data->contents,pc);
				}
				free(get_hash);
				free(out);
				free(array);
		}


void change_bit(char **data,int *size){

	int l=(*size);
	char buff[l+100];
	//strncpy(buff,data,size);
	int i=0,j=0;
	for(;i<l;i++,j++){
		if((*data)[i]=='\0'){
			buff[j]='c';
		j++;buff[j]='c';}
		else buff[j]=(*data)[i];
	}
	buff[j]='\0';
	(*size)=j;
	free(*data);
	*data=malloc(j+1);
	strcpy((*data),buff);

}
void restore_bit(char **data,int *size){
	int l=*size;
	char buff[l+3];
		//strncpy(buff,data,size);
		int i=0,c=0,k=1;
		for(;i<l;i++,c++,k++){
			if((*data)[c]=='c' && (*data)[k]=='c'){
				buff[i]='\0';
			c++;k++;l--;}
			else buff[i]=(*data)[c];
		}
		buff[i]='\0';
		(*size)=i;
		free(*data);
		*data=malloc(i+1);
		memcpy((*data),buff,i+1);

}


void generate_session_key(char *session_key,int size){

	RAND_bytes((unsigned char *)session_key,size);

}
