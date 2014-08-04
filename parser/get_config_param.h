#ifndef GET_CONF_H_
#define GET_CONG_H_
typedef struct
{
	char *name;
    char *key;
} configuration;
int get_config_param(configuration *config);



#endif
