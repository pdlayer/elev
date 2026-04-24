#include <security/pam_appl.h>
#include <security/pam_misc.h>

#include <dirent.h>
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

static bool
get_tty_path(const char *user, const char *scope, char *buf, size_t len)
{
	char *tty = ttyname(STDIN_FILENO);
	char *p;
	int n;

	if (!tty)
		return false;

	if (strncmp(tty, "/dev/", 5) == 0)
		tty += 5;
	if (scope && scope[0])
		n = snprintf(buf, len, "%s/%s_%s_%s", ELEV_RUN, user, tty, scope);
	else
		n = snprintf(buf, len, "%s/%s_%s", ELEV_RUN, user, tty);
	if (n < 0 || (size_t)n >= len)
		return false;
	for (p = buf + strlen(ELEV_RUN) + 1; *p; p++)
		if (*p == '/')
			*p = '_';

	return true;
}

static void
get_legacy_notty_path(const char *user, char *buf, size_t len)
{
	snprintf(buf, len, "%s/%s_notty", ELEV_RUN, user);
}

static void
validate_persist_dir(void)
{
	struct stat st;

	if (lstat(ELEV_RUN, &st) != 0) {
		if (errno == ENOENT)
			return;
		die("lstat: %s: %s", ELEV_RUN, strerror(errno));
	}

	if (!S_ISDIR(st.st_mode))
		die("security: %s: not a directory", ELEV_RUN);
	if (st.st_uid != 0)
		die("security: %s: not owned by root", ELEV_RUN);
	if (st.st_mode & (S_IWGRP | S_IWOTH))
		die("security: %s: writable by group or others", ELEV_RUN);
}

static bool
check_persist(const char *user, const char *scope, long limit)
{
	struct stat st;
	time_t now = time(NULL);
	char path[PATH_MAX];

	validate_persist_dir();
	if (!get_tty_path(user, scope, path, sizeof(path)))
		return false;

	if (lstat(path, &st) != 0)
		return false;

	if (!S_ISREG(st.st_mode) || st.st_uid != 0 ||
	    (st.st_mode & (S_IRWXG | S_IRWXO)))
		return false;

	if (limit == -1)
		return true;
	if (limit < 0)
		return false;
	if (now == (time_t)-1)
		return false;
	if (st.st_mtime > now)
		return false;

	if (now - st.st_mtime > limit)
		return false;

	return true;
}

static void
update_persist(const char *user, const char *scope)
{
	char path[PATH_MAX];
	struct stat st;
	int fd;

	validate_persist_dir();
	if (mkdir(ELEV_RUN, 0700) == -1) {
		if (errno != EEXIST)
			die("mkdir: %s: %s", ELEV_RUN, strerror(errno));
		if (lstat(ELEV_RUN, &st) != 0)
			die("lstat: %s: %s", ELEV_RUN, strerror(errno));
		if (!S_ISDIR(st.st_mode))
			die("security: %s: not a directory", ELEV_RUN);
		if (st.st_uid != 0)
			die("security: %s: not owned by root", ELEV_RUN);
		if (st.st_mode & (S_IWGRP | S_IWOTH))
			die("security: %s: writable by group or others", ELEV_RUN);
	}
	if (!get_tty_path(user, scope, path, sizeof(path)))
		return;

	fd = open(path, O_WRONLY | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (fd == -1)
		die("open: %s: %s", path, strerror(errno));
	if (fstat(fd, &st) != 0) {
		close(fd);
		die("fstat: %s: %s", path, strerror(errno));
	}
	if (!S_ISREG(st.st_mode) || st.st_uid != 0 ||
	    (st.st_mode & (S_IRWXG | S_IRWXO))) {
		close(fd);
		die("security: insecure persistence file: %s", path);
	}
	if (write(fd, "1", 1) != 1) {
		close(fd);
		die("write: %s: %s", path, strerror(errno));
	}
	if (ftruncate(fd, 0) != 0) {
		close(fd);
		die("ftruncate: %s: %s", path, strerror(errno));
	}
	close(fd);
}

void
reset_persistence(const char *user)
{
	char path[PATH_MAX];
	char prefix[PATH_MAX];
	char *prefix_name;
	DIR *dir;
	struct dirent *ent;
	size_t prefix_len;
	size_t prefix_name_len;

	validate_persist_dir();
	if (get_tty_path(user, NULL, prefix, sizeof(prefix))) {
		prefix_len = strlen(prefix);
		if (prefix_len + 1 >= sizeof(prefix))
			goto legacy;
		prefix[prefix_len++] = '_';
		prefix[prefix_len] = '\0';
		prefix_name = prefix + strlen(ELEV_RUN) + 1;
		prefix_name_len = strlen(prefix_name);

		dir = opendir(ELEV_RUN);
		if (dir) {
			while ((ent = readdir(dir)) != NULL) {
				if (strncmp(ent->d_name, prefix_name, prefix_name_len) != 0)
					continue;
				snprintf(path, sizeof(path), "%s/%s", ELEV_RUN, ent->d_name);
				if (unlink(path) == -1 && errno != ENOENT) {
					closedir(dir);
					die("unlink: %s: %s", path, strerror(errno));
				}
			}
			closedir(dir);
		} else if (errno != ENOENT) {
			die("opendir: %s: %s", ELEV_RUN, strerror(errno));
		}
	}

legacy:
	if (get_tty_path(user, NULL, path, sizeof(path)) &&
	    unlink(path) == -1 && errno != ENOENT)
		die("unlink: %s: %s", path, strerror(errno));

	get_legacy_notty_path(user, path, sizeof(path));
	if (unlink(path) == -1 && errno != ENOENT)
		die("unlink: %s: %s", path, strerror(errno));
}

int
authenticate_pam(const char *user, const char *cache_scope,
	bool nopass, long persist,
	pam_handle_t **pamh_out, bool *session_open, bool *creds_established)
{
	pam_handle_t *pamh = NULL;
	int retval;
	bool opened = false;
	bool creds = false;

	*pamh_out = NULL;
	*session_open = false;
	*creds_established = false;

	if (nopass)
		return 0;

	if (persist != 0 && check_persist(user, cache_scope, persist))
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

	retval = pam_setcred(pamh, PAM_ESTABLISH_CRED);
	if (retval != PAM_SUCCESS) {
		pam_end(pamh, retval);
		return -1;
	}
	creds = true;

	retval = pam_open_session(pamh, 0);
	if (retval != PAM_SUCCESS) {
		pam_setcred(pamh, PAM_DELETE_CRED);
		pam_end(pamh, retval);
		return -1;
	}
	opened = true;

	if (persist != 0)
		update_persist(user, cache_scope);

	*pamh_out = pamh;
	*session_open = opened;
	*creds_established = creds;

	return 0;
}

void
cleanup_pam(pam_handle_t *pamh, bool session_open,
	bool creds_established, int pam_status)
{
	if (!pamh)
		return;

	if (session_open)
		pam_close_session(pamh, 0);
	if (creds_established)
		pam_setcred(pamh, PAM_DELETE_CRED);
	pam_end(pamh, pam_status);
}
