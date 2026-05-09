#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "elev.h"

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

static char *trim(char *s) {
	char *end;
	while (isspace((unsigned char)*s))
		s++;
	if (*s == 0)
		return s;
	end = s + strlen(s) - 1;
	while (end > s && isspace((unsigned char)*end))
		end--;
	end[1] = '\0';
	return s;
}

static bool same_file_object(const struct stat *a, const struct stat *b) {
	return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}

static bool is_comment_or_empty(char *line) {
	char *p = trim(line);
	return *p == '\0' || *p == '#' || (p[0] == '/' && p[1] == '/');
}

static void free_rule_fields(struct rule *r) {
	int i;

	free(r->who);
	free(r->as_user);
	free(r->cmd);
	free(r->deny_cmd);
	for (i = 0; i < r->argc; i++)
		free(r->args[i]);
	for (i = 0; i < r->keepenv_count; i++)
		free(r->keepenv[i]);
}

static void config_error(size_t lineno, const char *fmt, ...) {
	va_list ap;

	fprintf(stderr, "elev: config:%zu: ", lineno);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

static char *next_token(char **s, bool *ok) {
	char *tok;
	char quote = 0;
	char *end;
	*ok = true;
	while (isspace((unsigned char)**s))
		(*s)++;
	if (**s == '\0')
		return NULL;
	if (**s == '"' || **s == '\'') {
		quote = **s;
		(*s)++;
	}
	tok = *s;
	if (quote) {
		while (**s && **s != quote)
			(*s)++;
		if (**s != quote) {
			*ok = false;
			return NULL;
		}
		**s = '\0';
		(*s)++;
	} else if (**s == '{') {
		while (**s && **s != '}')
			(*s)++;
		if (**s != '}') {
			*ok = false;
			return NULL;
		}
		(*s)++;
		end = *s;
		*end = '\0';
	} else {
		while (**s && !isspace((unsigned char)**s))
			(*s)++;
		if (**s) {
			**s = '\0';
			(*s)++;
		}
		return tok;
	}

	while (isspace((unsigned char)**s))
		(*s)++;
	return tok;
}

static bool parse_duration(const char *s, long *result) {
	char *end;
	long val, mult = 1;
	if (!s || !*s)
		return false;
	errno = 0;
	val = strtol(s, &end, 10);
	if (errno != 0 || end == s || val < 0)
		return false;
	if (*end == '\0') {
		*result = val;
		return true;
	}
	if (end[1] != '\0')
		return false;
	if (*end == 'm')
		mult = 60;
	else if (*end == 'h')
		mult = 3600;
	else if (*end == 'd')
		mult = 86400;
	else
		return false;
	if (val > LONG_MAX / mult)
		return false;
	*result = val * mult;
	return true;
}

static char *next_required_token(char **p, bool *ok, size_t lineno, const char *err) {
	char *tok = next_token(p, ok);
	if (!*ok) {
		config_error(lineno, "%s", err);
		return NULL;
	}
	if (!tok)
		config_error(lineno, "%s", err);
	return tok;
}

static bool set_denycmd(struct rule *r, char **p, bool *ok, size_t lineno) {
	char *denycmd;
	if (r->deny_cmd) {
		config_error(lineno, "duplicate denycmd");
		return false;
	}
	denycmd = next_required_token(p, ok, lineno, "denycmd requires a command path");
	if (!*ok || !denycmd)
		return false;
	r->deny_cmd = xstrdup(denycmd);
	return true;
}

static bool check_unterminated(bool ok, size_t lineno) {
	if (!ok)
		config_error(lineno, "unterminated token");
	return ok;
}

static bool parse_rule_type(const char *tok, struct rule *r, size_t lineno) {
	if (strcmp(tok, "permit") == 0)
		r->type = RULE_PERMIT;
	else if (strcmp(tok, "deny") == 0)
		r->type = RULE_DENY;
	else {
		config_error(lineno, "expected 'permit' or 'deny'");
		return false;
	}
	return true;
}

static char *canonicalize_user_token(const char *tok, size_t lineno) {
	struct passwd *pw;
	char *end = NULL;
	unsigned long uid;

	if (strcmp(tok, "*") == 0)
		return xstrdup(tok);

	errno = 0;
	uid = strtoul(tok, &end, 10);
	if (errno == 0 && end && *end == '\0')
		pw = getpwuid((uid_t)uid);
	else
		pw = getpwnam(tok);
	if (!pw) {
		config_error(lineno, "unknown user: %s", tok);
		return NULL;
	}
	return xstrdup(pw->pw_name);
}

static bool add_keepenv(struct rule *r, const char *name, size_t lineno) {
	char *value = xstrdup(name);
	char *trimmed = trim(value);
	if (!valid_env_name(trimmed)) {
		config_error(lineno, "invalid keepenv name: %s", trimmed);
		free(value);
		return false;
	}
	if (!is_safe_keepenv_name(trimmed)) {
		config_error(lineno, "unsafe keepenv name: %s", trimmed);
		free(value);
		return false;
	}
	if (trimmed != value)
		memmove(value, trimmed, strlen(trimmed) + 1);
	r->keepenv[r->keepenv_count++] = value;
	return true;
}

static bool parse_keepenv(struct rule *r, char **p, bool *ok, size_t lineno) {
	char *e = next_token(p, ok);
	char *inner, *saveptr, *v;
	if (!*ok) {
		config_error(lineno, "unterminated keepenv list");
		return false;
	}
	if (!e || e[0] != '{') {
		config_error(lineno, "keepenv requires a braced list");
		return false;
	}

	inner = xstrdup(e + 1);
	if (inner[0] != '\0' && inner[strlen(inner) - 1] == '}')
		inner[strlen(inner) - 1] = '\0';

	v = strtok_r(inner, ", ", &saveptr);
	while (v && r->keepenv_count < MAX_ENV_KEEP) {
		if (!add_keepenv(r, v, lineno)) {
			free(inner);
			return false;
		}
		v = strtok_r(NULL, ", ", &saveptr);
	}
	if (v) {
		config_error(lineno, "too many keepenv entries");
		free(inner);
		return false;
	}
	free(inner);
	return true;
}

static bool parse_rule_options(struct rule *r, char **p, char **tok, bool *ok, size_t lineno) {
	while ((*tok = next_token(p, ok))) {
		if (!check_unterminated(*ok, lineno))
			return false;
		if (strncmp(*tok, "persist=", 8) == 0) {
			if (!parse_duration(*tok + 8, &r->persist)) {
				config_error(lineno, "invalid persist duration: %s", *tok + 8);
				return false;
			}
		} else if (strcmp(*tok, "persist") == 0) {
			r->persist = DEFAULT_PERSIST_SECONDS;
		} else if (strcmp(*tok, "nopass") == 0) {
			r->nopass = true;
		} else if (strcmp(*tok, "keepenv") == 0) {
			if (!parse_keepenv(r, p, ok, lineno))
				return false;
		} else {
			return true;
		}
	}
	return check_unterminated(*ok, lineno);
}

static bool parse_subject(struct rule *r, char *tok, size_t lineno) {
	if (tok[0] == ':') {
		if (tok[1] == '\0') {
			config_error(lineno, "empty group name");
			return false;
		}
		r->is_group = true;
		r->who = xstrdup(tok + 1);
	} else {
		r->who = xstrdup(tok);
	}
	return true;
}

static bool parse_target_user(struct rule *r, char **p, bool *ok, size_t lineno) {
	char *tok = next_token(p, ok);
	if (!check_unterminated(*ok, lineno))
		return false;
	if (!tok || strcmp(tok, "as") != 0) {
		config_error(lineno, "expected 'as'");
		return false;
	}

	tok = next_token(p, ok);
	if (!check_unterminated(*ok, lineno))
		return false;
	if (!tok) {
		config_error(lineno, "missing target user");
		return false;
	}
	r->as_user = canonicalize_user_token(tok, lineno);
	if (!r->as_user)
		return false;
	return true;
}

static bool parse_command_args(struct rule *r, char **p, bool *ok, size_t lineno) {
	char *tok;

	while ((tok = next_token(p, ok))) {
		if (!check_unterminated(*ok, lineno))
			return false;
		if (strcmp(tok, "denycmd") == 0)
			return set_denycmd(r, p, ok, lineno);
		if (r->argc >= MAX_ARGC) {
			config_error(lineno, "too many command arguments");
			return false;
		}
		r->args[r->argc++] = xstrdup(tok);
	}
	return check_unterminated(*ok, lineno);
}

static bool parse_command_clause(struct rule *r, char **p, bool *ok, size_t lineno) {
	char *cmd_path = next_required_token(p, ok, lineno,
	    "cmd requires a command path");
	if (!*ok || !cmd_path)
		return false;
	if (cmd_path[0] != '/') {
		config_error(lineno, "absolute path required: %s", cmd_path);
		return false;
	}
	r->cmd = xstrdup(cmd_path);
	return parse_command_args(r, p, ok, lineno);
}

static bool parse_command_spec(struct rule *r, char **p, bool *ok, size_t lineno) {
	char *tok;

	while ((tok = next_token(p, ok))) {
		if (!check_unterminated(*ok, lineno))
			return false;
		if (strcmp(tok, "cmd") == 0)
			return parse_command_clause(r, p, ok, lineno);
		if (strcmp(tok, "denycmd") == 0) {
			if (!set_denycmd(r, p, ok, lineno))
				return false;
			continue;
		}
		config_error(lineno, "unexpected token: %s", tok);
		return false;
	}
	return check_unterminated(*ok, lineno);
}

static struct rule *parse_rule_line(char *line, size_t lineno) {
	struct rule *r;
	char *p, *tok;
	bool ok;
	if (is_comment_or_empty(line))
		return NULL;
	r = xcalloc(1, sizeof(*r));
	p = trim(line);
	tok = next_token(&p, &ok);
	if (!check_unterminated(ok, lineno)) {
		free(r);
		return NULL;
	}
	if (!tok) {
		config_error(lineno, "empty rule");
		free(r);
		return NULL;
	}
	if (!parse_rule_type(tok, r, lineno) ||
	    !parse_rule_options(r, &p, &tok, &ok, lineno)) {
		free_rule(r);
		return NULL;
	}
	if (!tok) {
		config_error(lineno, "missing subject");
		free_rule(r);
		return NULL;
	}
	if (!parse_subject(r, tok, lineno) ||
	    !parse_target_user(r, &p, &ok, lineno) ||
	    !parse_command_spec(r, &p, &ok, lineno)) {
		free_rule(r);
		return NULL;
	}
	return r;
}

static void validate_secure_fd(int fd, const char *path, bool final) {
	struct stat st;
	if (fstat(fd, &st) != 0)
		die("fstat: %s: %s", path, strerror(errno));
	if (st.st_uid != 0 || (st.st_mode & (S_IWGRP | S_IWOTH)))
		die("config: insecure ownership or permissions: %s", path);
	if (final) {
		if (!S_ISREG(st.st_mode))
			die("config: not a regular file: %s", path);
	} else if (!S_ISDIR(st.st_mode)) {
		die("config directory: not a directory: %s", path);
	}
}

static void validate_opened_path_identity(int fd, const char *path, bool final) {
	struct stat lst, fst;

	if (lstat(path, &lst) != 0)
		die("lstat: %s: %s", path, strerror(errno));
	if (S_ISLNK(lst.st_mode))
		die("security: symbolic links are not allowed: %s", path);
	if (fstat(fd, &fst) != 0)
		die("fstat: %s: %s", path, strerror(errno));
	if (!same_file_object(&lst, &fst))
		die("security: path changed while opening: %s", path);
	if (final) {
		if (!S_ISREG(lst.st_mode))
			die("config: not a regular file: %s", path);
	} else if (!S_ISDIR(lst.st_mode)) {
		die("config directory: not a directory: %s", path);
	}
}

static int open_secure_component(int dirfd, const char *name, const char *path, bool final) {
	int flags = O_CLOEXEC | (final ? O_RDONLY : O_RDONLY | O_DIRECTORY);
#ifdef O_NOFOLLOW
	flags |= O_NOFOLLOW;
#endif
	int fd = openat(dirfd, name, flags);
	if (fd == -1)
		die("openat: %s: %s", path, strerror(errno));
	validate_opened_path_identity(fd, path, final);
	validate_secure_fd(fd, path, final);
	return fd;
}

static FILE *open_config(const char *path) {
	FILE *fp;
	char current_path[PATH_MAX];
	char *copy;
	char *component;
	char *slash;
	int dirfd;
	int fd;
	if (!path || path[0] != '/')
		die("config: absolute path required");

	copy = xstrdup(path);
	dirfd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dirfd == -1) {
		free(copy);
		die("open: /: %s", strerror(errno));
	}
	validate_secure_fd(dirfd, "/", false);
	snprintf(current_path, sizeof(current_path), "/");

	component = copy + 1;
	while (*component == '/')
		component++;
	if (*component == '\0') {
		free(copy);
		close(dirfd);
		die("config: not a regular file: %s", path);
	}

	while ((slash = strchr(component, '/')) != NULL) {
		if (slash == component) {
			component++;
			continue;
		}
		*slash = '\0';
		if (strcmp(current_path, "/") != 0)
			strncat(current_path, "/", sizeof(current_path) - strlen(current_path) - 1);
		strncat(current_path, component, sizeof(current_path) - strlen(current_path) - 1);
		fd = open_secure_component(dirfd, component, current_path, false);
		close(dirfd);
		dirfd = fd;
		component = slash + 1;
		while (*component == '/')
			component++;
	}
	if (*component == '\0') {
		free(copy);
		close(dirfd);
		die("config: not a regular file: %s", path);
	}

	if (strcmp(current_path, "/") != 0)
		strncat(current_path, "/", sizeof(current_path) - strlen(current_path) - 1);
	strncat(current_path, component, sizeof(current_path) - strlen(current_path) - 1);
	fd = open_secure_component(dirfd, component, current_path, true);
	free(copy);
	close(dirfd);
	fp = fdopen(fd, "r");
	if (!fp) {
		close(fd);
		die("fdopen: %s: %s", path, strerror(errno));
	}
	return fp;
}

struct rule *parse_config(const char *path) {
	FILE *fp = open_config(path);
	struct rule *head = NULL, *last = NULL, *r;
	char *line = NULL;
	size_t len = 0;
	size_t lineno = 0;
	while (getline(&line, &len, fp) != -1) {
		lineno++;
		if (is_comment_or_empty(line))
			continue;
		r = parse_rule_line(line, lineno);
		if (!r)
			goto fail;

		if (last)
			last->next = r;
		else
			head = r;
		last = r;
		continue;
	fail:
		free_rules(r);
		free_rules(head);
		free(line);
		fclose(fp);
		return NULL;
	}

	free(line);
	fclose(fp);
	return head;
}

bool match_rule(const struct rule *r, const struct context *ctx) {
	bool user_match = false;
	int i;
	if (r->is_group) {
		for (i = 0; i < ctx->group_count; i++) {
			if (ctx->group_names[i] &&
			    strcmp(ctx->group_names[i], r->who) == 0) {
				user_match = true;
				break;
			}
		}
	} else if (strcmp(r->who, "*") == 0 || strcmp(r->who, ctx->user) == 0) {
		user_match = true;
	}
	if (!user_match)
		return false;
	if (strcmp(r->as_user, "*") != 0 && strcmp(r->as_user, ctx->target_name) != 0)
		return false;
	if (r->deny_cmd && strcmp(r->deny_cmd, ctx->cmd_argv[0]) == 0)
		return false;
	if (r->cmd) {
		if (strcmp(r->cmd, ctx->cmd_argv[0]) != 0)
			return false;
		for (i = 0; i < r->argc; i++) {
			char *arg_copy, *saveptr, *val;
			bool found = false;
			if (i + 1 >= ctx->cmd_argc)
				return false;
			arg_copy = strdup(r->args[i]);
			if (!arg_copy)
				die("malloc");
			val = strtok_r(arg_copy, ",", &saveptr);
			while (val) {
				if (strcmp(trim(val), ctx->cmd_argv[i+1]) == 0) {
					found = true;
					break;
				}
				val = strtok_r(NULL, ",", &saveptr);
			}
			free(arg_copy);
			if (!found)
				return false;
		}
		if (ctx->cmd_argc > r->argc + 1)
			return false;
	}
	return true;
}

void free_rule(struct rule *rule) {
	if (!rule)
		return;
	free_rule_fields(rule);
	free(rule);
}

void free_rules(struct rule *rules) {
	struct rule *next;
	while (rules) {
		next = rules->next;
		free_rule(rules);
		rules = next;
	}
}
