#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ini.h"
#include "get_config_param.h"
static int handler(void* user, const char* section, const char* name,
                   const char* value)
{
    configuration* pconfig = (configuration*)user;

    #define MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0
    if (MATCH("marsh", pconfig->name)) {
        pconfig->key = strdup(value);

    } else {
        return 0;  /* unknown section/name, error */
    }
    return 1;
}

int get_config_param(configuration *conf)
{
    if (ini_parse("config.ini", handler, conf) < 0) {
        printf("Can't load 'test.ini'\n");
        return 1;
    }
    printf("Config loaded from 'test.ini': key=%s\n",
        conf->key);
    return 0;
}
