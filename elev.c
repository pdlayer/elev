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
	"ARGV0", "BASHOPTS", "BASH_ENV", "CDPATH", "CHARSET", "DYLD_FALLBACK_LIBRARY_PATH",
	"DYLD_FALLBACK_FRAMEWORK_PATH", "DYLD_FRAMEWORK_PATH", "DYLD_INSERT_LIBRARIES",
	"DYLD_LIBRARY_PATH", "ENV", "FPATH", "GCC_EXEC_PREFIX", "GCONV_PATH", "GEM_HOME",
	"GEM_PATH", "GETCONF_DIR", "GIT_CONFIG", "GIT_CONFIG_COUNT", "GIT_CONFIG_GLOBAL",
	"GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_SYSTEM", "GIT_EXEC_PATH",
	"GLIBC_TUNABLES", "HOME", "HOSTALIASES", "IFS", "INPUTRC", "INSIDE_EMACS",
	"JAVA_TOOL_OPTIONS", "LESSCLOSE", "LESSOPEN", "LOCALDOMAIN", "LOGNAME", "LPATH",
	"LUA_CPATH", "LUA_INIT", "LUA_INIT_5_1", "LUA_INIT_5_2", "LUA_INIT_5_3", "LUA_INIT_5_4",
	"LUA_PATH", "MALLOC_ARENA_MAX", "MALLOC_CHECK_", "MALLOC_CONF", "MALLOC_TRACE", "NLSPATH",
	"NODE_OPTIONS", "PERL5DB", "PERL5LIB", "PERL5OPT", "PERLIO_DEBUG", "PERLLIB",
	"PYTHONBREAKPOINT", "PYTHONDONTWRITEBYTECODE", "PYTHONHOME", "PYTHONINSPECT",
	"PYTHONPATH", "PYTHONPROFILEIMPORTTIME", "PYTHONSTARTUP", "PYTHONUSERBASE", "RBENV_DIR",
	"RBENV_HOOK_PATH", "RBENV_ROOT", "RES_OPTIONS", "RUBYLIB", "RUBYOPT", "SHELL", "TERM",
	"TERMINFO", "TERMINFO_DIRS", "TERMPATH", "TMPDIR", "USER", "XDG_CONFIG_DIRS",
	"XDG_DATA_DIRS", "ZDOTDIR", NULL
};
static const char *forbidden_env_prefixes[] = {
	"BASH_FUNC_", "DYLD_", "LD_", "LIBPATH", "LOCPATH", "MALLOC_", "PERLIO_",
	"PYTHON", "RUBY", NULL
};

static void print_banner(FILE *stream);
static void close_fds_except(int keep_fd);
static char *serialize_cache_scope(const struct context *ctx, const struct rule *match);
static void write_errno_to_pipe(int fd, int err);

static void write_errno_to_pipe(int fd, int err) {
	while (write(fd, &err, sizeof(err)) == -1 && errno == EINTR)
		;
}

static void __attribute__((noreturn)) child_die(const char *fmt, ...) {
	va_list ap;
	dprintf(STDERR_FILENO, "elev: ");
	va_start(ap, fmt);
	vdprintf(STDERR_FILENO, fmt, ap);
	va_end(ap);
	dprintf(STDERR_FILENO, "\n");
	_exit(1);
}

void die(const char *fmt, ...) {
	va_list ap;
	fprintf(stderr, "elev: ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	exit(1);
}

static void usage(void) {
	print_banner(stderr);
	fprintf(stderr, "usage: elev [-v] [-k] [-u user] command [args...]\n");
	exit(1);
}

static void print_banner(FILE *stream) {
	fprintf(stream, "        .__               \n");
	fprintf(stream, "  ____ |  |   _______  __\n");
	fprintf(stream, "_/ __ \\|  | _/ __ \\  \\/ /\n");
	fprintf(stream, "\\  ___/|  |_\\  ___/\\   / \n");
	fprintf(stream, " \\___  >____/\\___  >\\_/  \n");
	fprintf(stream, "     \\/          \\/      \n\n");
	fprintf(stream, "elev 1.0.0\n");
}

static void print_version(void) {
	print_banner(stdout);
}

static bool is_forbidden(const char *var) {
	int i;
	for (i = 0; forbidden_env[i]; i++) {
		if (strcmp(var, forbidden_env[i]) == 0)
			return true;
	}
	for (i = 0; forbidden_env_prefixes[i]; i++) {
		if (strncmp(var, forbidden_env_prefixes[i],
		    strlen(forbidden_env_prefixes[i])) == 0)
			return true;
	} return false;
}

static void free_keep_vals(char *keep_vals[], int count) {
	int i;
	for (i = 0; i < count; i++)
		free(keep_vals[i]);
}

static bool safe_setenv(const char *name, const char *value) {
	return setenv(name, value, 1) == 0;
}

static bool is_allowed_pam_env(const char *name) {
	return strcmp(name, "TERM") == 0;
}

static bool apply_pam_env_entry(const char *entry) {
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

static bool set_target_env(const struct context *ctx) {
	const char *shell = ctx->target_shell && ctx->target_shell[0] ?
	    ctx->target_shell : "/bin/sh";
	const char *home = ctx->target_home ? ctx->target_home : "/";
	return safe_setenv("HOME", home) &&
	    safe_setenv("USER", ctx->target_name) &&
	    safe_setenv("LOGNAME", ctx->target_name) &&
	    safe_setenv("SHELL", shell);
}

static bool secure_env(struct rule *match, const struct context *ctx, char **pam_env) {
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

	if (!clear_environment()) {
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

static void free_context(struct context *ctx) {
	int i;
	free(ctx->user);
	free(ctx->groups);
	if (ctx->group_names) {
		for (i = 0; i < ctx->group_count; i++)
			free(ctx->group_names[i]);
	}
	free(ctx->group_names);
	free(ctx->target_name);
	free(ctx->target_home);
	free(ctx->target_shell);
}

static void init_current_user(struct context *ctx) {
	struct passwd *pw = getpwuid(getuid());
	if (!pw)
		die("getpwuid");
	ctx->user = xstrdup(pw->pw_name);
	ctx->uid = pw->pw_uid;
}

static void init_user_groups(struct context *ctx) {
	int i;
	ctx->group_count = getgroups(0, NULL);
	if (ctx->group_count == -1)
		die("getgroups");
	if (ctx->group_count <= 0)
		return;
	ctx->groups = xcalloc(ctx->group_count, sizeof(gid_t));
	ctx->group_names = xcalloc(ctx->group_count, sizeof(char *));
	if (getgroups(ctx->group_count, ctx->groups) == -1)
		die("getgroups");
	for (i = 0; i < ctx->group_count; i++) {
		struct group *gr = getgrgid(ctx->groups[i]);
		if (!gr)
			continue;
		ctx->group_names[i] = xstrdup(gr->gr_name);
	}
}

static void init_target_user(struct context *ctx) {
	struct passwd *pw;
	char *end = NULL;
	unsigned long uid;

	errno = 0;
	uid = strtoul(ctx->target_user, &end, 10);
	if (errno == 0 && end && *end == '\0')
		pw = getpwuid((uid_t)uid);
	else
		pw = getpwnam(ctx->target_user);
	if (!pw)
		die("unknown user: %s", ctx->target_user);
	ctx->target_uid = pw->pw_uid;
	ctx->target_gid = pw->pw_gid;
	ctx->target_name = xstrdup(pw->pw_name);
	ctx->target_home = xstrdup(pw->pw_dir ? pw->pw_dir : "/");
	ctx->target_shell = xstrdup(pw->pw_shell ? pw->pw_shell : "/bin/sh");
}

static struct rule *find_matching_rule(struct rule *rules, const struct context *ctx) {
	struct rule *r;
	struct rule *match = NULL;
	for (r = rules; r; r = r->next) {
		if (match_rule(r, ctx))
			match = r;
	} 
	return match;
}

static void close_exec_pipe(int exec_pipe[2]) {
	if (exec_pipe[0] != -1)
		close(exec_pipe[0]);
	if (exec_pipe[1] != -1)
		close(exec_pipe[1]);
}

static void child_fail(int exec_pipe[2], int err, const char *msg) {
	write_errno_to_pipe(exec_pipe[1], err);
	child_die("%s: %s", msg, strerror(err));
}

static void run_child(const struct context *ctx, struct rule *match, char **pam_env, int exec_pipe[2]) {
	int exec_errno;
	close(exec_pipe[0]);
	if (initgroups(ctx->target_name, ctx->target_gid) != 0)
		child_fail(exec_pipe, errno, "initgroups");
	if (setgid(ctx->target_gid) != 0)
		child_fail(exec_pipe, errno, "setgid");
	if (setuid(ctx->target_uid) != 0)
		child_fail(exec_pipe, errno, "setuid");
	if (!secure_env(match, ctx, pam_env))
		child_fail(exec_pipe, errno, "secure_env");

	close_fds_except(exec_pipe[1]);
	execvp(ctx->cmd_argv[0], ctx->cmd_argv);
	exec_errno = errno;
	write_errno_to_pipe(exec_pipe[1], exec_errno);
	child_die("execvp: %s: %s", ctx->cmd_argv[0], strerror(exec_errno));
}

static void log_exec_result(const struct context *ctx, int exec_pipe[2]) {
	int exec_errno = 0;
	close(exec_pipe[1]);
	if (read(exec_pipe[0], &exec_errno, sizeof(exec_errno)) == 0) {
		syslog(LOG_INFO, "started: %s as %s: %s", ctx->user, ctx->target_user,
		    ctx->cmd_argv[0]);
	} else {
		syslog(LOG_WARNING, "start failed: %s as %s: %s: %s", ctx->user,
		    ctx->target_user, ctx->cmd_argv[0], strerror(exec_errno));
	}
	close(exec_pipe[0]);
	exec_pipe[0] = -1;
}

static void close_fds_except(int keep_fd) {
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

static unsigned long hash_bytes(unsigned long h, const char *s) {
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

static void write_scope_field(FILE *stream, const char *value) {
	size_t value_len = value ? strlen(value) : 0;
	if (fprintf(stream, "%zu:", value_len) < 0)
		die("open_memstream");
	if (value_len != 0 && fwrite(value, 1, value_len, stream) != value_len)
		die("open_memstream");
	if (fputc('\n', stream) == EOF)
		die("open_memstream");
}

static char *serialize_cache_scope(const struct context *ctx, const struct rule *match) {
	FILE *stream;
	char *buf = NULL;
	size_t len = 0;
	int i;

	stream = open_memstream(&buf, &len);
	if (!stream)
		die("open_memstream: %s", strerror(errno));

	write_scope_field(stream, ctx->target_name);
	write_scope_field(stream, match->who);
	write_scope_field(stream, match->as_user);
	write_scope_field(stream, match->cmd);
	write_scope_field(stream, match->deny_cmd);

	for (i = 0; i < match->argc; i++)
		write_scope_field(stream, match->args[i]);
	write_scope_field(stream, NULL);

	for (i = 0; i < ctx->cmd_argc; i++)
		write_scope_field(stream, ctx->cmd_argv[i]);

	if (fclose(stream) != 0) {
		free(buf);
		die("fclose: open_memstream: %s", strerror(errno));
	}
	return buf;
}

static void build_cache_scope(const char *scope_data, char *buf, size_t len) {
	unsigned long h = 1469598103934665603UL;

	h = hash_bytes(h, scope_data);
	snprintf(buf, len, "%016lx", h);
}

static int wait_for_child(pid_t pid) {
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
	struct rule *rules, *match = NULL;
	pid_t pid;
	pam_handle_t *pamh = NULL;
	char **pam_env = NULL;
	char cache_scope[32];
	char *cache_scope_data = NULL;
	int exec_pipe[2] = {-1, -1};
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
			print_version();
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

	init_current_user(&ctx);

	if (reset_ts) {
		reset_persistence(ctx.user);
		if (argc < 1) {
			free_context(&ctx);
			return 0;
		}
	}
	
	init_user_groups(&ctx);
	init_target_user(&ctx);

	rules = parse_config(ELEV_CONF);
	if (!rules)
		die("config: parse error");

	match = find_matching_rule(rules, &ctx);

	if (!match || match->type == RULE_DENY) {
		syslog(LOG_WARNING, "denied: %s as %s: %s", ctx.user, ctx.target_user, ctx.cmd_argv[0]);
		die("access denied");
	}

	cache_scope_data = serialize_cache_scope(&ctx, match);
	build_cache_scope(cache_scope_data, cache_scope, sizeof(cache_scope));

	if (authenticate_pam(ctx.user, cache_scope, cache_scope_data,
	    match->nopass, match->persist,
	    &pamh, &pam_session_open, &pam_creds_established) != 0) {
		syslog(LOG_WARNING, "auth failed: %s as %s", ctx.user, ctx.target_user);
		free(cache_scope_data);
		die("auth failed");
	}
	pam_env = pamh ? pam_getenvlist(pamh) : NULL;

	if (pipe_cloexec(exec_pipe) == -1) {
		free(cache_scope_data);
		free_env_list(pam_env);
		cleanup_pam(pamh, pam_session_open, pam_creds_established, PAM_ABORT);
		die("pipe: %s", strerror(errno));
	}

	pid = fork();
	if (pid == -1) {
		close_exec_pipe(exec_pipe);
		free(cache_scope_data);
		free_env_list(pam_env);
		cleanup_pam(pamh, pam_session_open, pam_creds_established, PAM_ABORT);
		die("fork: %s", strerror(errno));
	}
	if (pid == 0)
		run_child(&ctx, match, pam_env, exec_pipe);

	log_exec_result(&ctx, exec_pipe);

	free(cache_scope_data);
	free_context(&ctx);
	free_rules(rules);
	free_env_list(pam_env);
	status = wait_for_child(pid);
	cleanup_pam(pamh, pam_session_open, pam_creds_established,
	    status == 0 ? PAM_SUCCESS : PAM_ABORT);
	return status;
}
