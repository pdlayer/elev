#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "elev.h"

extern char **environ;

bool valid_env_name(const char *name) {
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

void free_env_list(char **env) {
	int i;
	if (!env)
		return;
	for (i = 0; env[i]; i++)
		free(env[i]);
	free(env);
}

void *xcalloc(size_t nmemb, size_t size) {
	void *ptr = calloc(nmemb, size);
	if (!ptr)
		die("calloc: %s", strerror(errno));
	return ptr;
}

char *xstrdup(const char *s) {
	char *copy = strdup(s);
	if (!copy)
		die("strdup: %s", strerror(errno));
	return copy;
}

bool clear_environment(void) {
#if defined(__GLIBC__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
	if (clearenv() == 0)
		return true;
	if (errno != ENOSYS)
		return false;
#endif

	while (environ && environ[0]) {
		char *entry = environ[0];
		char *eq = strchr(entry, '=');
		size_t len;
		char *name;

		if (!eq)
			return false;
		len = (size_t)(eq - entry);
		name = xcalloc(len + 1, sizeof(char));
		memcpy(name, entry, len);
		if (unsetenv(name) != 0) {
			free(name);
			return false;
		}
		free(name);
	}
	return true;
}

static int set_cloexec_flag(int fd) {
	int flags = fcntl(fd, F_GETFD);
	if (flags == -1)
		return -1;
	return fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

int pipe_cloexec(int pipefd[2]) {
#ifdef __linux__
	if (pipe2(pipefd, O_CLOEXEC) == 0)
		return 0;
	if (errno != ENOSYS && errno != EINVAL)
		return -1;
#endif

	if (pipe(pipefd) != 0)
		return -1;
	if (set_cloexec_flag(pipefd[0]) != 0 || set_cloexec_flag(pipefd[1]) != 0) {
		int saved_errno = errno;
		close(pipefd[0]);
		close(pipefd[1]);
		errno = saved_errno;
		return -1;
	}
	return 0;
}
