/*
 * usefull.c
 *
 *  Created on: Feb 21, 2014
 *      Author: ivan
 */
#include <stdarg.h>
#include "usefull.h"
int int_to_bit(unsigned int b,int c){
	b=(b>>c)&1;
	return b;
}
void set_bit(unsigned int *b,int c,int set){
	if(set==1)
		*b|=(1U<<c);
	if(set==0)
		*b&=(~(1U<<c));
}
int min(int a, ...)
{
	int i;
	int minimum = 0;
	va_list list;
	va_start(list, a);
	if (a != -1)
		minimum = a;
	while ((i = va_arg(list, int)) != -1)
	{
		if (i < minimum)
			minimum = i;
	}
	va_end(list);
	return minimum;
}
void make_copy_enc_part(krb5_enc_kdc_rep_part *d,krb5_enc_tkt_part *s){
		d->magic=s->magic;
		d->flags=s->flags;
		//session
		d->session->contents=realloc(d->session->contents,strlen(s->session->contents)+1);
		memcpy(d->session->contents,s->session->contents,KEY_LENGHT+1);
		d->session->enctype=s->session->enctype;
		d->session->length=s->session->length;
		d->session->magic=s->session->magic;

		d->times.authtime=s->times.authtime;
		d->times.endtime=s->times.endtime;
		d->times.renew_till=s->times.renew_till;
		d->times.starttime=s->times.starttime;
}
