#include <ctype.h>

#include <stdlib.h>

#include "elev.h"

bool
valid_env_name(const char *name)
{
	const unsigned char *p = (const unsigned char *)name;

	if (!name || !*name)
		return false;
	if (!(isalpha(*p) || *p == '_'))
		return false;

	for (p++; *p; p++) {
		if (!(isalnum(*p) || *p == '_'))
			return false;
	}

	return true;
}

void
free_env_list(char **env)
{
	int i;

	if (!env)
		return;

	for (i = 0; env[i]; i++)
		free(env[i]);
	free(env);
}
