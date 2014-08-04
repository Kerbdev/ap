/*
 * create.c
 *
 *  Created on: Feb 17, 2014
 *      Author: ivan
 */
#include "dynamic.h"
void malloc_krb5_kdc_req(krb5_kdc_req *as_rep){
	as_rep->padata=calloc(1,sizeof(krb5_pa_data));
	if(as_rep->padata == NULL){
	            	perror("Out of memory");
	                exit(-1);
	                }
	as_rep->client=calloc(1,sizeof(krb5_principal_data));
	if(as_rep->client == NULL){
	        	            	perror("Out of memory");
	        	                exit(-1);
	        	                }
	malloc_krb5_principal(as_rep->client);
	as_rep->server=calloc(1,sizeof(krb5_principal_data));
	 if(as_rep->server == NULL){
	        	   perror("Out of memory");
	        	   exit(-1);
	        	   }
	 malloc_krb5_principal(as_rep->server);
	as_rep->addresses=calloc(1,sizeof(krb5_address));
	if(as_rep->addresses == NULL){
	            	perror("Out of memory");
	                exit(-1);
	                }
	as_rep->unenc_authdata=calloc(1,sizeof(krb5_authdata));
	if(as_rep->unenc_authdata == NULL){
	            	perror("Out of memory");
	                exit(-1);
	                }
	as_rep->second_ticket=calloc(1,sizeof(krb5_ticket));
	if(as_rep->second_ticket == NULL){
	            	perror("Out of memory");
	                exit(-1);
	                }
	as_rep->second_ticket->server=calloc(1,sizeof(krb5_principal_data));
	 if(as_rep->second_ticket->server == NULL){
	        	    perror("Out of memory");
	        	    exit(-1);
	        	     }
	 malloc_krb5_principal(as_rep->second_ticket->server);
	as_rep->second_ticket->enc_part2=calloc(1,sizeof(krb5_enc_tkt_part));
	 if(as_rep->second_ticket->enc_part2== NULL){
	        	     perror("Out of memory");
	        	     exit(-1);
	        	     }
	 as_rep->second_ticket->enc_part2->session=calloc(1,sizeof(krb5_keyblock));
	 	 if(as_rep->second_ticket->enc_part2->session== NULL){
	 	        	     perror("Out of memory");
	 	        	     exit(-1);
	 	        	     }
	 	as_rep->second_ticket->enc_part2->client=calloc(1,sizeof(krb5_principal_data));
	 		 if(as_rep->second_ticket->enc_part2->client== NULL){
	 		        	     perror("Out of memory");
	 		        	     exit(-1);
	 		        	     }
	 		malloc_krb5_principal(as_rep->second_ticket->enc_part2->client);
	 		 as_rep->second_ticket->enc_part2->caddrs=calloc(1,sizeof(krb5_address));
	 		 	 if(as_rep->second_ticket->enc_part2->caddrs== NULL){
	 		 	        	     perror("Out of memory");
	 		 	        	     exit(-1);
	 		 	        	     }
	 		 	as_rep->second_ticket->enc_part2->authorization_data=calloc(1,sizeof(krb5_authdata));
	 		 		 if(as_rep->second_ticket->enc_part2->authorization_data== NULL){
	 		 		        	     perror("Out of memory");
	 		 		        	     exit(-1);
	 		 		        	     }

}
void
malloc_krb5_principal(krb5_principal_data *val)
{
	val->data=calloc(1,sizeof(krb5_data));
	 if(val->data == NULL){
	        	    perror("Out of memory");
	        	    exit(-1);
	        	     }
}
void malloc_krb5_enc_tkt_part(krb5_enc_tkt_part *val){
	val->session=calloc(1,sizeof(krb5_keyblock));
	if(val->session == NULL){
		        	    perror("Out of memory");
		        	    exit(-1);
		        	     }
	val->client=calloc(1,sizeof(krb5_principal_data));
			 if(val->client == NULL){
			        	    perror("Out of memory");
			        	    exit(-1);
			        	     }
		malloc_krb5_principal(val->client);
		val->caddrs=calloc(1,sizeof(krb5_address));
				 if(val->caddrs == NULL){
				        	    perror("Out of memory");
				        	    exit(-1);
				        	     }

		val->authorization_data=calloc(1,sizeof(krb5_authdata));
		 if(val->authorization_data == NULL){
		        	    perror("Out of memory");
		        	    exit(-1);
		        	     }


}
void malloc_krb5_ticket(krb5_ticket *p){
	p->server=calloc(1,sizeof(krb5_principal_data));
		 if(p->server == NULL){
		        	    perror("Out of memory");
		        	    exit(-1);
		        	     }
	malloc_krb5_principal(p->server);
			 p->enc_part2=calloc(1,sizeof(krb5_enc_tkt_part));
			 		 if(p->enc_part2 == NULL){
			 		        	    perror("Out of memory");
			 		        	    exit(-1);
			 		        	     }
	malloc_krb5_enc_tkt_part(p->enc_part2);
}

void malloc_krb5_authenticator(krb5_authenticator *val){
	val->client=calloc(1,sizeof(krb5_principal_data));
		 if(val->client == NULL){
		        	    perror("Out of memory");
		        	    exit(-1);
		        	     }
	malloc_krb5_principal(val->client);
	val->authorization_data=calloc(1,sizeof(krb5_authdata));
		 if(val->authorization_data == NULL){
		        	    perror("Out of memory");
		        	    exit(-1);
		        	     }
	val->subkey=calloc(1,sizeof(krb5_keyblock));
		 if(val->subkey == NULL){
		        	    perror("Out of memory");
		        	    exit(-1);
		        	     }
	val->checksum=calloc(1,sizeof(krb5_checksum));
		 if(val->checksum == NULL){
		        	    perror("Out of memory");
		        	    exit(-1);
		        	     }
}
void malloc_krb5_creds(krb5_creds *val){
	val->client=calloc(1,sizeof(krb5_principal_data));
			 if(val->client == NULL){
			        	    perror("Out of memory");
			        	    exit(-1);
			        	     }
		malloc_krb5_principal(val->client);
	val->server=calloc(1,sizeof(krb5_principal_data));
		if(val->server == NULL){
				        	    perror("Out of memory");
				        	    exit(-1);
				        	     }
		malloc_krb5_principal(val->server);

		val->addresses=calloc(1,sizeof(krb5_address));
				 if(val->addresses== NULL){
				        	    perror("Out of memory");
				        	    exit(-1);
				        	     }
		val->authdata=calloc(1,sizeof(krb5_authdata));
			 if(val->authdata == NULL){
			        	    perror("Out of memory");
			        	    exit(-1);
			        	     }
}
void malloc_krb5_enc_kdc_rep_part(krb5_enc_kdc_rep_part *val){
	val->session=calloc(1,sizeof(krb5_keyblock));
	if(val->session == NULL){
		        	    perror("Out of memory");
		        	    exit(-1);
		        	     }
	val->last_req=calloc(1,sizeof(krb5_last_req_entry));
				 if(val->last_req== NULL){
				        	    perror("Out of memory");
				        	    exit(-1);
				        	     }
	val->server=calloc(1,sizeof(krb5_principal_data));
		if(val->server == NULL){
								 perror("Out of memory");
								 exit(-1);
								 }
	malloc_krb5_principal(val->server);

	val->aaddrs=calloc(1,sizeof(krb5_address));
				if(val->aaddrs== NULL){
						 perror("Out of memory");
					     exit(-1);
								         }
}

void malloc_krb5_kdc_rep(krb5_kdc_rep *val){
	val->padata=calloc(1,sizeof(krb5_pa_data));
			 if(val->padata == NULL){
			        	    perror("Out of memory");
			        	    exit(-1);
			        	     }
	val->client=calloc(1,sizeof(krb5_principal_data));
			 			 if(val->client == NULL){
			 			        	    perror("Out of memory");
			 			        	    exit(-1);
			 			        	     }
    malloc_krb5_principal(val->client);
		val->ticket=calloc(1,sizeof(krb5_ticket));
			  if(val->ticket == NULL){
			 					       perror("Out of memory");
			 					       exit(-1);
			 					        	 }
	malloc_krb5_ticket(val->ticket);
		val->enc_part2=calloc(1,sizeof(krb5_enc_kdc_rep_part));
			 if(val->enc_part2 == NULL){
			 			 perror("Out of memory");
			 				 exit(-1);
			 				}
	malloc_krb5_enc_kdc_rep_part(val->enc_part2);

}
void malloc_krb5_error(krb5_error *val){
	val->client=calloc(1,sizeof(krb5_principal_data));
			 			 if(val->client == NULL){
			 			        	    perror("Out of memory");
			 			        	    exit(-1);
			 			        	     }
    malloc_krb5_principal(val->client);
	val->server=calloc(1,sizeof(krb5_principal_data));
			 			 if(val->server == NULL){
			 			        	    perror("Out of memory");
			 			        	    exit(-1);
			 			        	     }
    malloc_krb5_principal(val->server);


}
void malloc_krb5_cred_info(krb5_cred_info *val){
	val->session=calloc(1,sizeof(krb5_keyblock));
			if(val->session == NULL){
				        	    perror("Out of memory");
				        	    exit(-1);
				        	     }
	val->client=calloc(1,sizeof(krb5_principal_data));
			if(val->client == NULL){
					 			perror("Out of memory");
					 			exit(-1);
					 			  }
	malloc_krb5_principal(val->client);
	val->server=calloc(1,sizeof(krb5_principal_data));
			if(val->server == NULL){
					 			 perror("Out of memory");
					 			 exit(-1);
					 			    }
	malloc_krb5_principal(val->server);
	val->caddrs=calloc(1,sizeof(krb5_address));
				if(val->caddrs== NULL){
						 perror("Out of memory");
					     exit(-1);
								         }



}
void malloc_krb5_cred_enc_part(krb5_cred_enc_part *val){
	val->s_address=calloc(1,sizeof(krb5_address));
				if(val->s_address== NULL){
						 perror("Out of memory");
					     exit(-1);
								         }
	val->r_address=calloc(1,sizeof(krb5_address));
				if(val->r_address== NULL){
						 perror("Out of memory");
						exit(-1);
										}
	val->ticket_info=calloc(1,sizeof(krb5_cred_info));
				if(val->ticket_info == NULL){
						 perror("Out of memory");
						 exit(-1);
						 			    }
			    malloc_krb5_cred_info(val->ticket_info);
}

void malloc_krb5_cred(krb5_cred *val){
	val->tickets=calloc(1,sizeof(krb5_ticket));
		  if(val->tickets == NULL){
		 					       perror("Out of memory");
		 					       exit(-1);
		 					        	 }
    malloc_krb5_ticket(val->tickets);
    val->enc_part2=calloc(1,sizeof(krb5_cred_enc_part));
    		  if(val->enc_part2 == NULL){
    		 					       perror("Out of memory");
    		 					       exit(-1);
    		 					        	 }
        malloc_krb5_cred_enc_part(val->enc_part2);

}
void malloc_krb5_safe(krb5_safe *val){
	val->s_address=calloc(1,sizeof(krb5_address));
				if(val->s_address== NULL){
						 perror("Out of memory");
					     exit(-1);
								         }
	val->r_address=calloc(1,sizeof(krb5_address));
				if(val->r_address== NULL){
						 perror("Out of memory");
						exit(-1);
										}

	val->checksum=calloc(1,sizeof(krb5_checksum));
				 if(val->checksum == NULL){
					     perror("Out of memory");
					      exit(-1);
					        	     }
}
void malloc_krb5_priv_enc_part(krb5_priv_enc_part *priv_enc){
	priv_enc->s_address=calloc(1,sizeof(krb5_address));
				if(priv_enc->s_address== NULL){
						 perror("Out of memory");
					     exit(-1);
								         }
	priv_enc->r_address=calloc(1,sizeof(krb5_address));
				if(priv_enc->r_address== NULL){
						 perror("Out of memory");
						exit(-1);	}



}
void malloc_krb5_priv(krb5_priv *val){
	malloc_krb5_priv_enc_part(&val->enc_part);
}

void malloc_krb5_ap_req(krb5_ap_req *val){
	val->ticket=calloc(1,sizeof(krb5_ticket));
	malloc_krb5_ticket(val->ticket);
	val->authenticator=calloc(1,sizeof(krb5_authenticator));
	malloc_krb5_authenticator(val->authenticator);

}
void malloc_krb5_ap_rep(krb5_ap_rep *val){
	val->enc_part.subkey=calloc(1,sizeof(krb5_keyblock));
}



