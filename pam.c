#include <security/pam_appl.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "elev.h"

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

static int
open_prompt_fd(void)
{
	int fd;

	fd = open("/dev/tty", O_RDONLY | O_CLOEXEC);
	if (fd != -1)
		return fd;
	if (!isatty(STDIN_FILENO))
		return -1;
	return STDIN_FILENO;
}

static bool
get_controlling_tty_path(char *buf, size_t len)
{
	const char *tty = NULL;
	int fd;
	int n;

	fd = open("/dev/tty", O_RDONLY | O_CLOEXEC);
	if (fd != -1) {
		tty = ttyname(fd);
		close(fd);
	} else if (isatty(STDIN_FILENO)) {
		tty = ttyname(STDIN_FILENO);
	}
	if (!tty)
		return false;
	n = snprintf(buf, len, "%s", tty);
	return n >= 0 && (size_t)n < len;
}

static void
restore_terminal_mode(int fd, const struct termios *old_termios, bool changed)
{
	if (!changed)
		return;
	tcsetattr(fd, TCSANOW, old_termios);
	fputc('\n', stderr);
	fflush(stderr);
}

static char *
read_pam_tty_secret(const char *prompt)
{
	struct termios old_termios, new_termios;
	char *line = NULL;
	FILE *stream = NULL;
	size_t cap = 0;
	bool changed = false;
	ssize_t nread;
	int fd = -1;

	fd = open_prompt_fd();
	if (fd == -1)
		return NULL;

	if (prompt && fputs(prompt, stderr) == EOF)
		goto fail;
	fflush(stderr);

	if (tcgetattr(fd, &old_termios) != 0)
		goto fail;
	new_termios = old_termios;
	new_termios.c_lflag &= ~ECHO;
	if (tcsetattr(fd, TCSAFLUSH, &new_termios) != 0)
		goto fail;
	changed = true;

	if (fd == STDIN_FILENO) {
		stream = stdin;
	} else {
		stream = fdopen(fd, "r");
		if (!stream)
			goto fail;
	}

	nread = getline(&line, &cap, stream);
	if (nread == -1)
		goto fail;
	if (nread > 0 && line[nread - 1] == '\n')
		line[nread - 1] = '\0';

	restore_terminal_mode(fd, &old_termios, changed);
	if (stream && stream != stdin)
		fclose(stream);
	else if (fd != STDIN_FILENO)
		close(fd);
	return line;

fail:
	restore_terminal_mode(fd, &old_termios, changed);
	if (stream && stream != stdin)
		fclose(stream);
	else if (fd != -1 && fd != STDIN_FILENO)
		close(fd);
	free(line);
	return NULL;
}

static char *
read_pam_line(int echo, const char *prompt)
{
	char *line = NULL;
	FILE *stream = NULL;
	size_t cap = 0;
	ssize_t nread;
	int fd = -1;

	if (!echo)
		return read_pam_tty_secret(prompt);

	fd = open_prompt_fd();
	if (fd == -1)
		return NULL;

	if (prompt && fputs(prompt, stderr) == EOF)
		goto fail;
	fflush(stderr);

	if (fd == STDIN_FILENO) {
		stream = stdin;
	} else {
		stream = fdopen(fd, "r");
		if (!stream)
			goto fail;
	}

	nread = getline(&line, &cap, stream);
	if (nread == -1) {
		goto fail;
	}
	if (nread > 0 && line[nread - 1] == '\n')
		line[nread - 1] = '\0';

	if (stream && stream != stdin)
		fclose(stream);
	return line;

fail:
	if (stream && stream != stdin)
		fclose(stream);
	else if (fd != -1 && fd != STDIN_FILENO)
		close(fd);
	free(line);
	return NULL;
}

static char *
format_password_prompt(const char *user, const char *prompt)
{
	int n;

	if (!user || !*user)
		return prompt ? xstrdup(prompt) : NULL;
	if (prompt && strcmp(prompt, "Password: ") != 0 &&
	    strcmp(prompt, "Password:") != 0)
		return xstrdup(prompt);

	n = snprintf(NULL, 0, "Password for %s: ", user);
	if (n < 0)
		return NULL;

	char *formatted = xcalloc((size_t)n + 1, sizeof(char));
	snprintf(formatted, (size_t)n + 1, "Password for %s: ", user);
	return formatted;
}

static int
pam_conversation(int num_msg, const struct pam_message **msg,
	struct pam_response **resp, void *appdata_ptr)
{
	struct pam_response *replies;
	const char *user = appdata_ptr;
	int i;

	if (num_msg <= 0 || !msg || !resp)
		return PAM_CONV_ERR;

	replies = xcalloc((size_t)num_msg, sizeof(*replies));
	for (i = 0; i < num_msg; i++) {
		switch (msg[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF: {
			char *prompt = format_password_prompt(user, msg[i]->msg);
			replies[i].resp = read_pam_line(0, prompt);
			free(prompt);
			if (!replies[i].resp)
				goto fail;
			break;
		}
		case PAM_PROMPT_ECHO_ON:
			replies[i].resp = read_pam_line(1, msg[i]->msg);
			if (!replies[i].resp)
				goto fail;
			break;
		case PAM_ERROR_MSG:
			if (msg[i]->msg) {
				fprintf(stderr, "%s\n", msg[i]->msg);
				fflush(stderr);
			}
			break;
		case PAM_TEXT_INFO:
			if (msg[i]->msg) {
				fprintf(stdout, "%s\n", msg[i]->msg);
				fflush(stdout);
			}
			break;
		default:
			goto fail;
		}
	}

	*resp = replies;
	return PAM_SUCCESS;

fail:
	for (i = 0; i < num_msg; i++) {
		free(replies[i].resp);
		replies[i].resp = NULL;
	}
	free(replies);
	return PAM_CONV_ERR;
}

static mode_t
set_private_umask(void)
{
	return umask(077);
}

static void
restore_umask(mode_t old_umask)
{
	umask(old_umask);
}

static bool
get_tty_path(const char *user, const char *scope, char *buf, size_t len)
{
	char tty_path[PATH_MAX];
	char *tty = tty_path;
	char *p;
	int n;

	if (!get_controlling_tty_path(tty_path, sizeof(tty_path)))
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
is_valid_persist_file(const struct stat *st)
{
	return S_ISREG(st->st_mode) && st->st_uid == 0 &&
	    !(st->st_mode & (S_IRWXG | S_IRWXO));
}

static bool
same_file_object(const struct stat *a, const struct stat *b)
{
	return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}

static void
validate_persist_path_identity(const char *path, int fd)
{
	struct stat lst, fst;

	if (lstat(path, &lst) != 0)
		die("lstat: %s: %s", path, strerror(errno));
	if (S_ISLNK(lst.st_mode))
		die("security: symbolic links are not allowed: %s", path);
	if (fstat(fd, &fst) != 0)
		die("fstat: %s: %s", path, strerror(errno));
	if (!same_file_object(&lst, &fst))
		die("security: path changed while opening: %s", path);
}

static int
open_persist_existing(const char *path, int flags)
{
	struct stat lst;
	int fd;

	if (lstat(path, &lst) != 0)
		return -1;
	if (S_ISLNK(lst.st_mode)) {
		errno = ELOOP;
		return -1;
	}
#ifdef O_NOFOLLOW
	flags |= O_NOFOLLOW;
#endif
	fd = open(path, flags);
	if (fd == -1)
		return -1;
	validate_persist_path_identity(path, fd);
	return fd;
}

static void
ensure_persist_dir(void)
{
	mode_t old_umask;

	validate_persist_dir();
	old_umask = set_private_umask();
	if (mkdir(ELEV_RUN, 0700) == -1) {
		restore_umask(old_umask);
		if (errno != EEXIST)
			die("mkdir: %s: %s", ELEV_RUN, strerror(errno));
		if (lstat(ELEV_RUN, &(struct stat){0}) != 0)
			die("lstat: %s: %s", ELEV_RUN, strerror(errno));
		validate_persist_dir();
		return;
	}
	restore_umask(old_umask);
}

static bool
check_persist(const char *user, const char *scope_key,
	const char *scope_data, long limit)
{
	struct stat st;
	time_t now = time(NULL);
	char path[PATH_MAX];
	int fd;
	size_t expected_len;
	ssize_t nread;
	char buf[512];
	size_t offset = 0;

	validate_persist_dir();
	if (!get_tty_path(user, scope_key, path, sizeof(path)))
		return false;

	if (lstat(path, &st) != 0)
		return false;

	if (!is_valid_persist_file(&st))
		return false;

	fd = open_persist_existing(path, O_RDONLY | O_CLOEXEC);
	if (fd == -1)
		return false;
	if (fstat(fd, &st) != 0 || !is_valid_persist_file(&st)) {
		close(fd);
		return false;
	}

	expected_len = strlen(scope_data);
	if ((size_t)st.st_size != expected_len) {
		close(fd);
		return false;
	}

	while ((nread = read(fd, buf, sizeof(buf))) > 0) {
		if ((size_t)nread > expected_len - offset) {
			close(fd);
			return false;
		}
		if (memcmp(scope_data + offset, buf, (size_t)nread) != 0) {
			close(fd);
			return false;
		}
		offset += (size_t)nread;
	}
	close(fd);
	if (nread < 0 || offset != expected_len)
		return false;

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

static int
set_pam_context_items(pam_handle_t *pamh, const char *user)
{
	char tty_path[PATH_MAX];
	int retval;

	retval = pam_set_item(pamh, PAM_RUSER, user);
	if (retval != PAM_SUCCESS)
		return retval;
	if (!get_controlling_tty_path(tty_path, sizeof(tty_path)))
		return PAM_SUCCESS;
	return pam_set_item(pamh, PAM_TTY, tty_path);
}

static void
update_persist(const char *user, const char *scope_key,
	const char *scope_data)
{
	char path[PATH_MAX];
	struct stat st;
	int fd;
	mode_t old_umask;
	size_t scope_len = strlen(scope_data);

	ensure_persist_dir();
	if (!get_tty_path(user, scope_key, path, sizeof(path)))
		return;

	old_umask = set_private_umask();
	fd = open(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	restore_umask(old_umask);
	if (fd == -1 && errno == EEXIST)
		fd = open_persist_existing(path, O_RDWR | O_CLOEXEC);
	if (fd == -1)
		die("open: %s: %s", path, strerror(errno));
	if (fstat(fd, &st) != 0) {
		close(fd);
		die("fstat: %s: %s", path, strerror(errno));
	}
	if (!is_valid_persist_file(&st)) {
		close(fd);
		die("security: insecure persistence file: %s", path);
	}
	if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
		close(fd);
		die("lseek: %s: %s", path, strerror(errno));
	}
	if (scope_len != 0 &&
	    write(fd, scope_data, scope_len) != (ssize_t)scope_len) {
		close(fd);
		die("write: %s: %s", path, strerror(errno));
	}
	if (ftruncate(fd, (off_t)scope_len) != 0) {
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

void
reset_all_persistence(const char *user)
{
	char path[PATH_MAX];
	char prefix[PATH_MAX];
	char *prefix_name;
	DIR *dir;
	struct dirent *ent;
	size_t prefix_name_len;

	validate_persist_dir();
	snprintf(prefix, sizeof(prefix), "%s/%s_", ELEV_RUN, user);
	prefix_name = prefix + strlen(ELEV_RUN) + 1;
	prefix_name_len = strlen(prefix_name);

	dir = opendir(ELEV_RUN);
	if (!dir) {
		if (errno == ENOENT)
			return;
		die("opendir: %s: %s", ELEV_RUN, strerror(errno));
	}

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

	get_legacy_notty_path(user, path, sizeof(path));
	if (unlink(path) == -1 && errno != ENOENT)
		die("unlink: %s: %s", path, strerror(errno));
}

int
authenticate_pam(const char *user, const char *cache_scope,
	const char *cache_scope_data,
	bool nopass, long persist,
	pam_handle_t **pamh_out, bool *session_open, bool *creds_established)
{
	pam_handle_t *pamh = NULL;
	struct pam_conv conv = {
		pam_conversation,
		(void *)user
	};
	int retval;
	bool opened = false;
	bool creds = false;
	bool skip_auth = false;

	*pamh_out = NULL;
	*session_open = false;
	*creds_established = false;

	if (nopass)
		skip_auth = true;
	else if (persist != 0 &&
	    check_persist(user, cache_scope, cache_scope_data, persist))
		skip_auth = true;

	retval = pam_start("elev", user, &conv, &pamh);
	if (retval != PAM_SUCCESS)
		return -1;

	retval = set_pam_context_items(pamh, user);
	if (retval != PAM_SUCCESS) {
		pam_end(pamh, retval);
		return -1;
	}

	if (!skip_auth) {
		retval = pam_authenticate(pamh, 0);
		if (retval != PAM_SUCCESS) {
			pam_end(pamh, retval);
			return -1;
		}
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
		update_persist(user, cache_scope, cache_scope_data);

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
