#include <stdio.h>
#include <string.h>
#include <time.h>
#include <math.h>
char* hashsum(void)
{
	return "4hi3hi354rji4j4i4joj";
}
char* KDC_ERR_C_PRINCIPAL_UNKNOWN_CHECK(char* Client, char* Principal)
	{
		if(!(strcmp(Client, Principal)))
			return "KDC_ERR_C_PRINCIPAL_UNKNOWN";
		else return "";
	}
char* KDC_ERR_S_PRINCIPAL_UNKNOWN_CHECK(char* TGS_ID, char* Server)
	{
		if(!(strcmp(TGS_ID, Server)))
			return "KDC_ERR_S_PRINCIPAL_UNKNOWN";
		else return "";
	}
char* KDC_ERR_PRINCIPAL_NOT_UNIQUE_CHECK(int Count)
	{
		if (Count > 1)
			return "KDC_ERR_PRINCIPAL_NOT_UNIQUE";
		else return "";
	}
char* KDC_ERR_CANNOT_POSTDATE_CHECK(int time, int MAY_POSTDATE)
	{
		if ((time < 0) || (MAY_POSTDATE == 0))
			return "KDC_ERR_CANNOT_POSTDATE";
		else return "";
	}
char* KRB_AP_ERR_TKT_EXPIRED_CHECK(time_t ticket_start, time_t ticket_end)
	{
		if (difftime(ticket_end,ticket_start) < 0.0)
			return "KRB_AP_ERR_TKT_EXPIRED";
		else return "";
	}
//char* KRB_AP_ERR_BAD_INTEGRITY_CHECK(char* field, char* hash)
	//{
	//	if(!(hashsum(field) == hash))
	//		return "KRB_AP_ERR_BAD_INTEGRITY";
	//	else return "";
	//}
char* KRB_AP_ERR_TKT_NYV_CHECK(time_t server_time, time_t ticket_time, int TICKET_VALID, double TIME_SKEW)
	{
		if (((difftime(server_time, ticket_time) < 0.0) && difftime(server_time, ticket_time) > TIME_SKEW) || (TICKET_VALID == 1))
			return "KRB_AP_ERR_TKT_NYV";
		else return "";
	}
char* KRB_AP_ERR_REPEAT_CHECK(int REQUEST_COUNT_SET, int REQUEST_COUNT_CURR)
	{
		if (REQUEST_COUNT_CURR > REQUEST_COUNT_SET)
			return "KRB_AP_ERR_REPEAT";
		else return "";
	}
char* KRB_AP_ERR_SKEW_CHECK(time_t server_time, time_t client_time, double TIME_SKEW)
	{
		if(fabs(difftime(server_time, client_time)) > TIME_SKEW)
			return "KRB_AP_ERR_SKEW";
		else
			return "";
	}
char* KRB_AP_ERR_BADADDR_CHECK(char* IP_CURR, char* IP_SET)
	{
		if (!(IP_CURR == IP_SET))
			return "KRB_AP_ERR_BADADDR";
		else return "";
	}
char* KRB_AP_ERR_BADVERSION_CHECK(char VERSION_CURR, char VERSION_SET)
	{
		if(!(VERSION_CURR == VERSION_SET))
			return "KRB_AP_ERR_BADVERSION";
		else return "";
	}
char* KRB_AP_ERR_MSG_TYPE(char MSG_CURR, char MSG_SET)
	{
		if(!(MSG_CURR == MSG_SET))
			return "KRB_AP_ERR_MSG_TYPE";
		else return "";
	}
char* KRB_AP_ERR_MODIFIED_CHECK(char* req_cname, char* resp_cname, char* req_realm, char* resp_crealm, char* req_sname, char* resp_sname, char* resp_realm, char* req_nonce, char* resp_nonce, char* req_addresses, char* resp_caddr)
	{
		if (/*decryption_error() or*/
            (req_cname != resp_cname) ||
            (req_realm != resp_crealm) ||
            (req_sname != resp_sname) ||
            (req_realm != resp_realm) ||
            (req_nonce != resp_nonce) ||
            (req_addresses != resp_caddr))
                return "KRB_AP_ERR_MODIFIED";
		else return "";		
	}
char* KRB_AP_ERR_INAPP_CKSUM_CHECK(char* ck_type_set, char* ck_type_curr)
	{
		if(!(ck_type_curr == ck_type_set))
			return "KRB_AP_ERR_INAPP_CKSUM";
		else return "";
	}
/* int decrypt_error()
	{
		return 0;
	} */
