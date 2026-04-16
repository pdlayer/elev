#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "elev.h"

static struct pam_conv conv = {
	misc_conv,
	NULL
};

static bool
check_persist(const char *user, long limit)
{
	char path[PATH_MAX];
	struct stat st;
	time_t now = time(NULL);

	snprintf(path, sizeof(path), "%s/%s", ELEV_RUN, user);

	if (stat(path, &st) != 0)
		return false;

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
	int fd;

	mkdir(ELEV_RUN, 0700);
	snprintf(path, sizeof(path), "%s/%s", ELEV_RUN, user);

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd != -1)
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
