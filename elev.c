#define _GNU_SOURCE

#include <errno.h>
#include <getopt.h>
#include <grp.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include "elev.h"

extern char **environ;

static const char *forbidden_env[] = {
	"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "LD_DEBUG",
	"PYTHONPATH", "PYTHONHOME", "PERL5LIB", "PERL5OPT",
	"RUBYLIB", "RUBYOPT", "GEM_HOME", "GEM_PATH",
	"XDG_CONFIG_DIRS", "XDG_DATA_DIRS",
	NULL
};

void
die(const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "elev: ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	exit(1);
}

static void
usage(void)
{
	fprintf(stderr, "        .__               \n");
	fprintf(stderr, "  ____ |  |   _______  __\n");
	fprintf(stderr, "_/ __ \\|  | _/ __ \\  \\/ /\n");
	fprintf(stderr, "\\  ___/|  |_\\  ___/\\   / \n");
	fprintf(stderr, " \\___  >____/\\___  >\\_/  \n");
	fprintf(stderr, "     \\/          \\/      \n\n");
	fprintf(stderr, "elev 0.1\n");
	fprintf(stderr, "usage: elev [-v] [-k] [-u user] command [args...]\n");
	exit(1);
}

static bool
is_forbidden(const char *var)
{
	int i;

	for (i = 0; forbidden_env[i]; i++) {
		if (strcmp(var, forbidden_env[i]) == 0)
			return true;
	}
	return false;
}

static void
secure_env(struct rule *match)
{
	char *keep_vals[MAX_ENV_KEEP];
	char *term, *saved_term;
	int i;

	for (i = 0; i < match->keepenv_count; i++) {
		if (is_forbidden(match->keepenv[i])) {
			keep_vals[i] = NULL;
			continue;
		}
		char *v = getenv(match->keepenv[i]);
		if (v) {
			keep_vals[i] = strdup(v);
			if (!keep_vals[i])
				die("malloc");
		} else {
			keep_vals[i] = NULL;
		}
	}

	term = getenv("TERM");
	if (term) {
		saved_term = strdup(term);
		if (!saved_term)
			die("malloc");
	} else {
		saved_term = NULL;
	}

	clearenv();

	
	setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
	if (saved_term)
		setenv("TERM", saved_term, 1);

	for (i = 0; i < match->keepenv_count; i++) {
		if (keep_vals[i]) {
			setenv(match->keepenv[i], keep_vals[i], 1);
			free(keep_vals[i]);
		}
	}
	free(saved_term);
}

static void
check_config_security(const char *path)
{
	struct stat st;
	char dir[1024];
	char *p;

	if (stat(path, &st) != 0)
		die("stat: %s: %s", path, strerror(errno));
	if (st.st_uid != 0 || (st.st_mode & (S_IWGRP | S_IWOTH)))
		die("config: insecure ownership or permissions");

	strncpy(dir, path, sizeof(dir) - 1);
	dir[sizeof(dir) - 1] = '\0';
	if ((p = strrchr(dir, '/'))) {
		if (p == dir)
			p[1] = '\0';
		else
			*p = '\0';
		if (stat(dir, &st) == 0) {
			if (st.st_uid != 0 || (st.st_mode & (S_IWGRP | S_IWOTH)))
				die("config directory: insecure ownership or permissions");
		}
	}
}

int
main(int argc, char **argv)
{
	struct context ctx = {0};
	struct rule *rules, *r, *match = NULL;
	struct passwd *pw;
	int ch;
	bool reset_ts = false;

	static struct option long_options[] = {
		{"help", no_argument, 0, 'h'},
		{"version", no_argument, 0, 'v'},
		{"reset-timestamp", no_argument, 0, 'k'},
		{0, 0, 0, 0}
	};

	openlog("elev", LOG_CONS | LOG_PID, LOG_AUTHPRIV);

	ctx.target_user = "root";
	while ((ch = getopt_long(argc, argv, "+u:vhk", long_options, NULL)) != -1) {
		switch (ch) {
		case 'k':
			reset_ts = true;
			break;
		case 'u':
			ctx.target_user = optarg;
			break;
		case 'v':
			printf("        .__               \n");
			printf("  ____ |  |   _______  __\n");
			printf("_/ __ \\|  | _/ __ \\  \\/ /\n");
			printf("\\  ___/|  |_\\  ___/\\   / \n");
			printf(" \\___  >____/\\___  >\\_/  \n");
			printf("     \\/          \\/      \n\n");
			printf("elev 0.1\n");
			exit(0);
		case 'h':
			usage();
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;
	if (argc < 1 && !reset_ts)
		usage();
	ctx.cmd_argv = argv;
	ctx.cmd_argc = argc;

	if (!(pw = getpwuid(getuid())))
		die("getpwuid");
	ctx.user = strdup(pw->pw_name);
	if (!ctx.user)
		die("malloc");
	ctx.uid = pw->pw_uid;

	if (reset_ts) {
		reset_persistence(ctx.user);
		if (argc < 1) {
			free(ctx.user);
			return 0;
		}
	}
	
	ctx.group_count = getgroups(0, NULL);
	if (ctx.group_count == -1)
		die("getgroups");
	ctx.groups = calloc(ctx.group_count, sizeof(gid_t));
	if (!ctx.groups)
		die("malloc");
	if (getgroups(ctx.group_count, ctx.groups) == -1)
		die("getgroups");

	if (!(pw = getpwnam(ctx.target_user)))
		die("unknown user: %s", ctx.target_user);
	ctx.target_uid = pw->pw_uid;
	ctx.target_gid = pw->pw_gid;

	check_config_security(ELEV_CONF);
	rules = parse_config(ELEV_CONF);
	if (!rules)
		die("config: parse error");

	for (r = rules; r; r = r->next) {
		if (match_rule(r, &ctx))
			match = r;
	}

	if (!match || match->type == RULE_DENY) {
		syslog(LOG_WARNING, "denied: %s as %s: %s", ctx.user, ctx.target_user, ctx.cmd_argv[0]);
		die("access denied");
	}

	if (authenticate_pam(ctx.user, match->nopass, match->persist) != 0) {
		syslog(LOG_WARNING, "auth failed: %s as %s", ctx.user, ctx.target_user);
		die("auth failed");
	}

	if (initgroups(ctx.target_user, ctx.target_gid) != 0)
		die("initgroups");
	if (setgid(ctx.target_gid) != 0)
		die("setgid");
	if (setuid(ctx.target_uid) != 0)
		die("setuid");

	syslog(LOG_INFO, "success: %s as %s: %s", ctx.user, ctx.target_user, ctx.cmd_argv[0]);
	secure_env(match);

	free(ctx.user);
	free(ctx.groups);
	free_rules(rules);

	execvp(ctx.cmd_argv[0], ctx.cmd_argv);
	die("execvp: %s: %s", ctx.cmd_argv[0], strerror(errno));
	return 0;
}
