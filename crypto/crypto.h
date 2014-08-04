/*
 * crypto.h
 *
 *  Created on: Apr 4, 2014
 *      Author: ivan
 */

#ifndef CRYPTO_H_
#define CRYPTO_H_

#include <gost89.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stribog.h"
void enc_gost(char *set_hash,char *in,char *out,int n_blocks);
void dec_gost(char *set_hash,char *in,char **out,int n_blocks);
void gost_get_hash(char *,char *);

#endif /* CRYPTO_H_ */
