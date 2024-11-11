#ifndef __PARSE_PARAM_H__
#define __PARSE_PARAM_H__

#include <rte_kvargs.h>
#include <rte_common.h>
#include <errno.h>

static inline int
open_str(const char *key __rte_unused, const char *value, void *extra_args)
{
	const char **str_name = extra_args;

	if (value == NULL)
		return -1;

	*str_name = value;

	return 0;
}

static inline int
open_int(const char *key __rte_unused, const char *value, void *extra_args)
{
	uint16_t *n = extra_args;

	if (value == NULL || extra_args == NULL)
		return -EINVAL;

	*n = (uint16_t)strtoul(value, NULL, 0);
	if (*n == USHRT_MAX && errno == ERANGE)
		return -1;

	return 0;
}

static inline int
parse_kvargs(struct rte_kvargs *kvlist, const char *key_match, 
        arg_handler_t handler, void *opaque)
{
    int ret = 0;
    ret = rte_kvargs_count(kvlist, key_match);
    if(ret != 1)
		return -1;
    
    ret = rte_kvargs_process(kvlist, key_match, handler, opaque);
    if(ret < 0) 
        return ret;
    
    return 0;
}

#endif // !__PARSE_PARAM_H__