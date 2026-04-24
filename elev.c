#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <syslog.h>
#include <sys/wait.h>
#include <unistd.h>

#include "elev.h"

static const char *forbidden_env[] = {
	"BASH_ENV", "CHARSET", "ENV", "GCONV_PATH",
	"GEM_HOME", "GEM_PATH",
	"GIT_CONFIG", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
	"HOME", "HOSTALIASES", "IFS", "INPUTRC",
	"JAVA_TOOL_OPTIONS",
	"LD_AUDIT", "LD_DEBUG", "LD_LIBRARY_PATH", "LD_PRELOAD",
	"LESSOPEN", "LOCALDOMAIN", "LUA_CPATH", "LUA_PATH",
	"LOGNAME", "NLSPATH", "NODE_OPTIONS",
	"PERL5LIB", "PERL5OPT", "PERLLIB",
	"PYTHONHOME", "PYTHONINSPECT", "PYTHONPATH",
	"PYTHONSTARTUP", "PYTHONUSERBASE",
	"RES_OPTIONS", "RUBYLIB", "RUBYOPT",
	"SHELL", "TERMINFO", "TERMINFO_DIRS", "TMPDIR",
	"USER",
	"XDG_CONFIG_DIRS", "XDG_DATA_DIRS",
	NULL
};

static const char *forbidden_env_prefixes[] = {
	"BASH_FUNC_",
	"LD_",
	NULL
};

static void __attribute__((noreturn))
child_die(const char *fmt, ...)
{
	va_list ap;

	dprintf(STDERR_FILENO, "elev: ");
	va_start(ap, fmt);
	vdprintf(STDERR_FILENO, fmt, ap);
	va_end(ap);
	dprintf(STDERR_FILENO, "\n");
	_exit(1);
}

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
	fprintf(stderr, "elev 1.0.0\n");
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
	for (i = 0; forbidden_env_prefixes[i]; i++) {
		if (strncmp(var, forbidden_env_prefixes[i],
		    strlen(forbidden_env_prefixes[i])) == 0)
			return true;
	}
	return false;
}

static void
free_keep_vals(char *keep_vals[], int count)
{
	int i;

	for (i = 0; i < count; i++)
		free(keep_vals[i]);
}

static bool
safe_setenv(const char *name, const char *value)
{
	return setenv(name, value, 1) == 0;
}

static bool
is_allowed_pam_env(const char *name)
{
	return strcmp(name, "TERM") == 0;
}

static bool
apply_pam_env_entry(const char *entry)
{
	const char *sep;
	size_t name_len;
	char name[256];

	sep = strchr(entry, '=');
	if (!sep)
		return true;

	name_len = (size_t)(sep - entry);
	if (name_len == 0 || name_len >= sizeof(name))
		return true;

	memcpy(name, entry, name_len);
	name[name_len] = '\0';

	if (!valid_env_name(name) || is_forbidden(name))
		return true;
	if (!is_allowed_pam_env(name))
		return true;

	return safe_setenv(name, sep + 1);
}

static bool
set_target_env(const struct context *ctx)
{
	const char *shell = ctx->target_shell && ctx->target_shell[0] ?
	    ctx->target_shell : "/bin/sh";
	const char *home = ctx->target_home ? ctx->target_home : "/";

	return safe_setenv("HOME", home) &&
	    safe_setenv("USER", ctx->target_name) &&
	    safe_setenv("LOGNAME", ctx->target_name) &&
	    safe_setenv("SHELL", shell);
}

static bool
secure_env(struct rule *match, const struct context *ctx, char **pam_env)
{
	char *keep_vals[MAX_ENV_KEEP] = {0};
	char *term, *saved_term = NULL;
	int saved_errno = 0;
	int i;
	bool ok = false;

	for (i = 0; i < match->keepenv_count; i++) {
		if (is_forbidden(match->keepenv[i])) {
			keep_vals[i] = NULL;
			continue;
		}
		char *v = getenv(match->keepenv[i]);
		if (v) {
			keep_vals[i] = strdup(v);
			if (!keep_vals[i]) {
				saved_errno = ENOMEM;
				goto out;
			}
		} else {
			keep_vals[i] = NULL;
		}
	}

	term = getenv("TERM");
	if (term) {
		saved_term = strdup(term);
		if (!saved_term) {
			saved_errno = ENOMEM;
			goto out;
		}
	} else {
		saved_term = NULL;
	}

	if (clearenv() != 0) {
		saved_errno = errno;
		goto out;
	}

	if (!safe_setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")) {
		saved_errno = errno;
		goto out;
	}
	if (saved_term && !safe_setenv("TERM", saved_term)) {
		saved_errno = errno;
		goto out;
	}

	for (i = 0; i < match->keepenv_count; i++) {
		if (keep_vals[i] && !safe_setenv(match->keepenv[i], keep_vals[i])) {
			saved_errno = errno;
			goto out;
		}
	}

	if (pam_env) {
		for (i = 0; pam_env[i]; i++) {
			if (!apply_pam_env_entry(pam_env[i])) {
				saved_errno = errno;
				goto out;
			}
		}
	}

	if (!set_target_env(ctx)) {
		saved_errno = errno;
		goto out;
	}

	ok = true;

	out:
	free_keep_vals(keep_vals, MAX_ENV_KEEP);
	free(saved_term);
	free_env_list(pam_env);
	if (!ok && saved_errno != 0)
		errno = saved_errno;
	return ok;
}

static void
free_context(struct context *ctx)
{
	free(ctx->user);
	free(ctx->groups);
	free(ctx->target_name);
	free(ctx->target_home);
	free(ctx->target_shell);
}

static void
close_fds_except(int keep_fd)
{
	DIR *dir;
	struct dirent *ent;
	struct rlimit rl;
	long max_fd;
	long fd;
	char *end;

	dir = opendir("/proc/self/fd");
	if (dir) {
		int dir_fd = dirfd(dir);

		while ((ent = readdir(dir)) != NULL) {
			errno = 0;
			fd = strtol(ent->d_name, &end, 10);
			if (errno != 0 || end == ent->d_name || *end != '\0')
				continue;
			if (fd > 2 && fd != keep_fd && fd != dir_fd)
				close((int)fd);
		}
		closedir(dir);
		return;
	}

	if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY)
		max_fd = (long)rl.rlim_cur;
	else
		max_fd = 1024;

	for (fd = 3; fd < max_fd; fd++) {
		if (fd != keep_fd)
			close(fd);
	}
}

static unsigned long
hash_bytes(unsigned long h, const char *s)
{
	const unsigned char *p = (const unsigned char *)s;

	if (!s)
		s = "";
	for (p = (const unsigned char *)s; *p; p++) {
		h ^= *p;
		h *= 1099511628211UL;
	}
	h ^= 0xff;
	h *= 1099511628211UL;
	return h;
}

static void
build_cache_scope(const struct context *ctx, const struct rule *match,
	char *buf, size_t len)
{
	unsigned long h = 1469598103934665603UL;
	int i;

	h = hash_bytes(h, ctx->target_name);
	h = hash_bytes(h, match->who);
	h = hash_bytes(h, match->as_user);
	h = hash_bytes(h, match->cmd);
	h = hash_bytes(h, match->deny_cmd);
	for (i = 0; i < match->argc; i++)
		h = hash_bytes(h, match->args[i]);
	h = hash_bytes(h, ctx->cmd_argv[0]);
	for (i = 1; i < ctx->cmd_argc; i++)
		h = hash_bytes(h, ctx->cmd_argv[i]);

	snprintf(buf, len, "%016lx", h);
}

static int
wait_for_child(pid_t pid)
{
	int status;

	while (waitpid(pid, &status, 0) == -1) {
		if (errno != EINTR)
			die("waitpid: %s", strerror(errno));
	}
	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	if (WIFSIGNALED(status))
		return 128 + WTERMSIG(status);
	return 1;
}

int
main(int argc, char **argv)
{
	struct context ctx = {0};
	struct rule *rules, *r, *match = NULL;
	struct passwd *pw;
	pid_t pid;
	pam_handle_t *pamh = NULL;
	char **pam_env = NULL;
	char cache_scope[32];
	int exec_pipe[2] = {-1, -1};
	int exec_errno = 0;
	int ch;
	int status;
	bool reset_ts = false;
	bool pam_session_open = false;
	bool pam_creds_established = false;

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
			printf("elev 1.0.0\n");
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
			free_context(&ctx);
			return 0;
		}
	}
	
	ctx.group_count = getgroups(0, NULL);
	if (ctx.group_count == -1)
		die("getgroups");
	if (ctx.group_count > 0) {
		ctx.groups = calloc(ctx.group_count, sizeof(gid_t));
		if (!ctx.groups)
			die("malloc");
		if (getgroups(ctx.group_count, ctx.groups) == -1)
			die("getgroups");
	}

	if (!(pw = getpwnam(ctx.target_user)))
		die("unknown user: %s", ctx.target_user);
	ctx.target_uid = pw->pw_uid;
	ctx.target_gid = pw->pw_gid;
	ctx.target_name = strdup(pw->pw_name);
	ctx.target_home = strdup(pw->pw_dir ? pw->pw_dir : "/");
	ctx.target_shell = strdup(pw->pw_shell ? pw->pw_shell : "/bin/sh");
	if (!ctx.target_name || !ctx.target_home || !ctx.target_shell)
		die("malloc");

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

	build_cache_scope(&ctx, match, cache_scope, sizeof(cache_scope));

	if (authenticate_pam(ctx.user, cache_scope, match->nopass, match->persist,
	    &pamh, &pam_session_open, &pam_creds_established) != 0) {
		syslog(LOG_WARNING, "auth failed: %s as %s", ctx.user, ctx.target_user);
		die("auth failed");
	}
	pam_env = pamh ? pam_getenvlist(pamh) : NULL;

	if (pipe2(exec_pipe, O_CLOEXEC) == -1) {
		free_env_list(pam_env);
		cleanup_pam(pamh, pam_session_open, pam_creds_established, PAM_ABORT);
		die("pipe2: %s", strerror(errno));
	}

	pid = fork();
	if (pid == -1) {
		close(exec_pipe[0]);
		close(exec_pipe[1]);
		free_env_list(pam_env);
		cleanup_pam(pamh, pam_session_open, pam_creds_established, PAM_ABORT);
		die("fork: %s", strerror(errno));
	}
	if (pid == 0) {
		close(exec_pipe[0]);
		if (setgid(ctx.target_gid) != 0) {
			exec_errno = errno;
			(void)write(exec_pipe[1], &exec_errno, sizeof(exec_errno));
			child_die("setgid");
		}
		if (initgroups(ctx.target_user, ctx.target_gid) != 0) {
			exec_errno = errno;
			(void)write(exec_pipe[1], &exec_errno, sizeof(exec_errno));
			child_die("initgroups");
		}
		if (setuid(ctx.target_uid) != 0) {
			exec_errno = errno;
			(void)write(exec_pipe[1], &exec_errno, sizeof(exec_errno));
			child_die("setuid");
		}

		if (!secure_env(match, &ctx, pam_env)) {
			exec_errno = errno;
			(void)write(exec_pipe[1], &exec_errno, sizeof(exec_errno));
			child_die("secure_env: %s", strerror(errno));
		}

		close_fds_except(exec_pipe[1]);
		execvp(ctx.cmd_argv[0], ctx.cmd_argv);
		exec_errno = errno;
		(void)write(exec_pipe[1], &exec_errno, sizeof(exec_errno));
		child_die("execvp: %s: %s", ctx.cmd_argv[0], strerror(exec_errno));
	}

	close(exec_pipe[1]);
	if (read(exec_pipe[0], &exec_errno, sizeof(exec_errno)) == 0) {
		syslog(LOG_INFO, "started: %s as %s: %s", ctx.user, ctx.target_user,
		    ctx.cmd_argv[0]);
	} else {
		syslog(LOG_WARNING, "start failed: %s as %s: %s: %s", ctx.user,
		    ctx.target_user, ctx.cmd_argv[0], strerror(exec_errno));
	}
	close(exec_pipe[0]);

	free_context(&ctx);
	free_rules(rules);
	free_env_list(pam_env);
	status = wait_for_child(pid);
	cleanup_pam(pamh, pam_session_open, pam_creds_established,
	    status == 0 ? PAM_SUCCESS : PAM_ABORT);
	return status;
}
