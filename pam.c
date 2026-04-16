#include <security/pam_appl.h>
#include <security/pam_misc.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "elev.h"

static struct pam_conv conv = {
	misc_conv,
	NULL
};

static void
get_tty_path(const char *user, char *buf, size_t len)
{
	char *tty = ttyname(STDIN_FILENO);
	char *p;

	if (tty) {
		if (strncmp(tty, "/dev/", 5) == 0)
			tty += 5;
		snprintf(buf, len, "%s/%s_%s", ELEV_RUN, user, tty);
		for (p = buf + strlen(ELEV_RUN) + 1; *p; p++)
			if (*p == '/')
				*p = '_';
	} else {
		snprintf(buf, len, "%s/%s_notty", ELEV_RUN, user);
	}
}

static bool
check_persist(const char *user, long limit)
{
	struct stat st;
	time_t now = time(NULL);
	char path[PATH_MAX];

	get_tty_path(user, path, sizeof(path));

	if (lstat(path, &st) != 0)
		return false;

	if (!S_ISREG(st.st_mode)) {
		unlink(path);
		return false;
	}

	if (limit == -1)
		return true;

	if (now - st.st_mtime > limit) {
		unlink(path);
		return false;
	}

	return true;
}

static void
update_persist(const char *user)
{
	char path[PATH_MAX];
	struct stat st;
	int fd;

	if (mkdir(ELEV_RUN, 0700) == -1) {
		if (errno != EEXIST)
			die("mkdir: %s: %s", ELEV_RUN, strerror(errno));
		if (stat(ELEV_RUN, &st) == 0 && st.st_uid != 0)
			die("security: %s: not owned by root", ELEV_RUN);
	}
	get_tty_path(user, path, sizeof(path));

	unlink(path);
	fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (fd == -1)
		die("open: %s: %s", path, strerror(errno));
	close(fd);
}

int
authenticate_pam(const char *user, bool nopass, long persist)
{
	pam_handle_t *pamh = NULL;
	int retval;

	if (nopass)
		return 0;

	if (persist != 0 && check_persist(user, persist))
		return 0;

	retval = pam_start("elev", user, &conv, &pamh);
	if (retval != PAM_SUCCESS)
		return -1;

	retval = pam_authenticate(pamh, 0);
	if (retval != PAM_SUCCESS) {
		pam_end(pamh, retval);
		return -1;
	}

	retval = pam_acct_mgmt(pamh, 0);
	if (retval != PAM_SUCCESS) {
		pam_end(pamh, retval);
		return -1;
	}

	pam_end(pamh, PAM_SUCCESS);

	if (persist != 0)
		update_persist(user);

	return 0;
}
