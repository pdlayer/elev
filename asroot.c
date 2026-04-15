#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <getopt.h>

#include "asroot.h"

extern char **environ;

void
die(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	exit(1);
}

static void
usage(void)
{
	fprintf(stderr, "asroot 0.1\n");
	fprintf(stderr, "usage: asroot [-v] [-e] [-u user] command [args...]\n");
	exit(1);
}

static void
secure_env(struct rule *match)
{
	char *keep_vals[MAX_ENV_KEEP];
	for (int i = 0; i < match->keepenv_count; i++) {
		char *v = getenv(match->keepenv[i]);
		keep_vals[i] = v ? strdup(v) : NULL;
	}

	char *path = getenv("PATH");
	char *term = getenv("TERM");
	char *saved_path = path ? strdup(path) : NULL;
	char *saved_term = term ? strdup(term) : NULL;

	clearenv();

	setenv("PATH", saved_path ? saved_path : "/usr/bin:/bin", 1);
	if (saved_term) setenv("TERM", saved_term, 1);

	for (int i = 0; i < match->keepenv_count; i++) {
		if (keep_vals[i]) {
			setenv(match->keepenv[i], keep_vals[i], 1);
			free(keep_vals[i]);
		}
	}
	free(saved_path);
	free(saved_term);
}

static void
check_config_security(const char *path)
{
	struct stat st;
	if (stat(path, &st) != 0)
		die("cannot stat config");
	if (st.st_uid != 0 || (st.st_mode & (S_IWGRP | S_IWOTH)))
		die("config must be owned by root and not writable by others");
}

int
main(int argc, char **argv)
{
	struct context ctx = {0};
	struct rule *rules, *r, *match = NULL;
	struct passwd *pw;
	int ch, edit_mode = 0;
	char *edit_argv[3];

	static struct option long_options[] = {
		{"edit-config", no_argument, 0, 'e'},
		{"help", no_argument, 0, 'h'},
		{"version", no_argument, 0, 'v'},
		{0, 0, 0, 0}
	};

	openlog("asroot", LOG_CONS | LOG_PID, LOG_AUTHPRIV);

	ctx.target_user = "root";
	while ((ch = getopt_long(argc, argv, "+u:vhe", long_options, NULL)) != -1) {
		switch (ch) {
		case 'u': ctx.target_user = optarg; break;
		case 'v': printf("asroot 0.1\n"); exit(0);
		case 'e': edit_mode = 1; break;
		case 'h': usage(); break;
		default: usage();
		}
	}

	if (edit_mode) {
		char *editor = getenv("EDITOR");
		if (!editor) editor = getenv("VISUAL");
		if (!editor) editor = "vi";
		edit_argv[0] = editor;
		edit_argv[1] = ASROOT_CONF;
		edit_argv[2] = NULL;
		ctx.cmd_argv = edit_argv;
		ctx.cmd_argc = 2;
	} else {
		argc -= optind;
		argv += optind;
		if (argc < 1) usage();
		ctx.cmd_argv = argv;
		ctx.cmd_argc = argc;
	}

	if (!(pw = getpwuid(getuid()))) die("who are you?");
	ctx.user = strdup(pw->pw_name);
	ctx.uid = pw->pw_uid;
	
	ctx.group_count = getgroups(0, NULL);
	ctx.groups = calloc(ctx.group_count, sizeof(gid_t));
	getgroups(ctx.group_count, ctx.groups);

	if (!(pw = getpwnam(ctx.target_user))) die("unknown user: %s", ctx.target_user);
	ctx.target_uid = pw->pw_uid;
	ctx.target_gid = pw->pw_gid;

	check_config_security(ASROOT_CONF);
	rules = parse_config(ASROOT_CONF);
	if (!rules) die("config error");

	for (r = rules; r; r = r->next) {
		if (match_rule(r, &ctx)) match = r;
	}

	if (!match || match->type == RULE_DENY) {
		syslog(LOG_WARNING, "denied: %s as %s: %s", ctx.user, ctx.target_user, ctx.cmd_argv[0]);
		die("permission denied");
	}

	if (authenticate_pam(ctx.user, match->nopass, match->persist) != 0) {
		syslog(LOG_WARNING, "auth failed: %s as %s", ctx.user, ctx.target_user);
		die("auth failed");
	}

	if (initgroups(ctx.target_user, ctx.target_gid) != 0) die("initgroups failed");
	if (setgid(ctx.target_gid) != 0) die("setgid failed");
	if (setuid(ctx.target_uid) != 0) die("setuid failed");

	syslog(LOG_INFO, "success: %s as %s: %s", ctx.user, ctx.target_user, ctx.cmd_argv[0]);
	secure_env(match);

	execvp(ctx.cmd_argv[0], ctx.cmd_argv);
	die("exec failed: %s", strerror(errno));
	return 0;
}
