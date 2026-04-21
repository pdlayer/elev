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

static char *
trim(char *s)
{
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

static void
config_error(size_t lineno, const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "elev: config:%zu: ", lineno);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

static char *
next_token(char **s, bool *ok)
{
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

static bool
parse_duration(const char *s, long *result)
{
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

static char *
next_required_token(char **p, bool *ok, size_t lineno, const char *err)
{
	char *tok = next_token(p, ok);

	if (!*ok) {
		config_error(lineno, "%s", err);
		return NULL;
	}
	if (!tok)
		config_error(lineno, "%s", err);

	return tok;
}

static bool
set_denycmd(struct rule *r, char **p, bool *ok, size_t lineno)
{
	char *denycmd;

	if (r->deny_cmd) {
		config_error(lineno, "duplicate denycmd");
		return false;
	}

	denycmd = next_required_token(p, ok, lineno, "denycmd requires a command path");
	if (!*ok || !denycmd)
		return false;

	r->deny_cmd = strdup(denycmd);
	if (!r->deny_cmd)
		die("malloc");

	return true;
}

static void
check_secure_component(const char *path, bool final)
{
	struct stat st;

	if (lstat(path, &st) != 0)
		die("lstat: %s: %s", path, strerror(errno));
	if (st.st_uid != 0 || (st.st_mode & (S_IWGRP | S_IWOTH)))
		die("config: insecure ownership or permissions: %s", path);
	if (final) {
		if (!S_ISREG(st.st_mode))
			die("config: not a regular file: %s", path);
	} else if (!S_ISDIR(st.st_mode)) {
		die("config directory: not a directory: %s", path);
	}
}

static void
check_config_security(const char *path)
{
	char current[PATH_MAX];
	char *slash;
	char *next;

	if (!path || path[0] != '/')
		die("config: absolute path required");

	strncpy(current, path, sizeof(current) - 1);
	current[sizeof(current) - 1] = '\0';
	if (strlen(path) >= sizeof(current))
		die("config: path too long: %s", path);

	check_secure_component("/", false);
	for (slash = current + 1; (next = strchr(slash, '/')) != NULL; slash = next + 1) {
		*next = '\0';
		check_secure_component(current, false);
		*next = '/';
	}
	check_secure_component(path, true);
}

static FILE *
open_config(const char *path)
{
	FILE *fp;
	struct stat st;
	int fd;

	check_config_security(path);

	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd == -1)
		die("open: %s: %s", path, strerror(errno));
	if (fstat(fd, &st) != 0) {
		close(fd);
		die("fstat: %s: %s", path, strerror(errno));
	}
	if (!S_ISREG(st.st_mode) || st.st_uid != 0 ||
	    (st.st_mode & (S_IWGRP | S_IWOTH))) {
		close(fd);
		die("config: insecure opened file: %s", path);
	}

	fp = fdopen(fd, "r");
	if (!fp) {
		close(fd);
		die("fdopen: %s: %s", path, strerror(errno));
	}

	return fp;
}

struct rule *
parse_config(const char *path)
{
	FILE *fp = open_config(path);
	struct rule *head = NULL, *last = NULL, *r;
	char *line = NULL;
	size_t len = 0;
	size_t lineno = 0;
	char *p, *tok;
	bool ok;

	while (getline(&line, &len, fp) != -1) {
		lineno++;
		p = trim(line);
		if (*p == '\0' || *p == '#' || (p[0] == '/' && p[1] == '/'))
			continue;

		r = calloc(1, sizeof(*r));
		if (!r)
			die("malloc");

		tok = next_token(&p, &ok);
		if (!ok) {
			config_error(lineno, "unterminated token");
			goto fail;
		}
		if (!tok) {
			config_error(lineno, "empty rule");
			goto fail;
		}

		if (strcmp(tok, "permit") == 0)
			r->type = RULE_PERMIT;
		else if (strcmp(tok, "deny") == 0)
			r->type = RULE_DENY;
		else {
			config_error(lineno, "expected 'permit' or 'deny'");
			goto fail;
		}

		while ((tok = next_token(&p, &ok))) {
			if (!ok) {
				config_error(lineno, "unterminated token");
				goto fail;
			}
			if (strncmp(tok, "persist=", 8) == 0) {
				if (!parse_duration(tok + 8, &r->persist)) {
					config_error(lineno, "invalid persist duration: %s", tok + 8);
					goto fail;
				}
			} else if (strcmp(tok, "persist") == 0) {
				r->persist = -1;
			} else if (strcmp(tok, "nopass") == 0) {
				r->nopass = true;
			} else if (strcmp(tok, "keepenv") == 0) {
				char *e = next_token(&p, &ok);
				char *inner, *saveptr, *v;

				if (!ok) {
					config_error(lineno, "unterminated keepenv list");
					goto fail;
				}
				if (e && e[0] == '{') {
					inner = strdup(e + 1);
					if (!inner)
						die("malloc");
					if (inner[0] != '\0' && inner[strlen(inner) - 1] == '}')
						inner[strlen(inner) - 1] = '\0';
					v = strtok_r(inner, ", ", &saveptr);
					while (v && r->keepenv_count < MAX_ENV_KEEP) {
						char *val = strdup(trim(v));

						if (!val)
							die("malloc");
						if (!valid_env_name(val)) {
							config_error(lineno, "invalid keepenv name: %s", val);
							free(val);
							free(inner);
							goto fail;
						}
						r->keepenv[r->keepenv_count++] = val;
						v = strtok_r(NULL, ", ", &saveptr);
					}
					if (v) {
						config_error(lineno, "too many keepenv entries");
						free(inner);
						goto fail;
					}
					free(inner);
				} else {
					config_error(lineno, "keepenv requires a braced list");
					goto fail;
				}
			} else {
				break;
			}
		}
		if (!ok) {
			config_error(lineno, "unterminated token");
			goto fail;
		}

		if (!tok) {
			config_error(lineno, "missing subject");
			goto fail;
		}

		if (tok[0] == ':') {
			if (tok[1] == '\0') {
				config_error(lineno, "empty group name");
				goto fail;
			}
			r->is_group = true;
			r->who = strdup(tok + 1);
		} else {
			r->who = strdup(tok);
		}
		if (!r->who)
			die("malloc");

		tok = next_token(&p, &ok);
		if (!ok) {
			config_error(lineno, "unterminated token");
			goto fail;
		}
		if (!tok || strcmp(tok, "as") != 0) {
			config_error(lineno, "expected 'as'");
			goto fail;
		}

		tok = next_token(&p, &ok);
		if (!ok) {
			config_error(lineno, "unterminated token");
			goto fail;
		}
		if (!tok) {
			config_error(lineno, "missing target user");
			goto fail;
		}
		r->as_user = strdup(tok);
		if (!r->as_user)
			die("malloc");

		while ((tok = next_token(&p, &ok))) {
			if (!ok) {
				config_error(lineno, "unterminated token");
				goto fail;
			}
			if (strcmp(tok, "cmd") == 0) {
				char *cmd_path = next_required_token(&p, &ok, lineno,
				    "cmd requires a command path");

				if (!ok || !cmd_path)
					goto fail;
				if (cmd_path[0] != '/') {
					config_error(lineno, "absolute path required: %s", cmd_path);
					goto fail;
				}
				r->cmd = strdup(cmd_path);
				if (!r->cmd)
					die("malloc");
				while ((tok = next_token(&p, &ok))) {
					if (!ok) {
						config_error(lineno, "unterminated token");
						goto fail;
					}
					if (strcmp(tok, "denycmd") == 0) {
						if (!set_denycmd(r, &p, &ok, lineno))
							goto fail;
						break;
					}
					if (r->argc < MAX_ARGC) {
						r->args[r->argc] = strdup(tok);
						if (!r->args[r->argc])
							die("malloc");
						r->argc++;
					} else {
						config_error(lineno, "too many command arguments");
						goto fail;
					}
				}
				break;
			} else if (strcmp(tok, "denycmd") == 0) {
				if (!set_denycmd(r, &p, &ok, lineno))
					goto fail;
			} else {
				config_error(lineno, "unexpected token: %s", tok);
				goto fail;
			}
		}
		if (!ok) {
			config_error(lineno, "unterminated token");
			goto fail;
		}

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

bool
match_rule(const struct rule *r, const struct context *ctx)
{
	bool user_match = false;
	int i;

	if (r->is_group) {
		for (i = 0; i < ctx->group_count; i++) {
			struct group *gr = getgrgid(ctx->groups[i]);
			if (gr && strcmp(gr->gr_name, r->who) == 0) {
				user_match = true;
				break;
			}
		}
	} else if (strcmp(r->who, "*") == 0 || strcmp(r->who, ctx->user) == 0) {
		user_match = true;
	}

	if (!user_match)
		return false;

	if (strcmp(r->as_user, "*") != 0 && strcmp(r->as_user, ctx->target_user) != 0)
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

void
free_rules(struct rule *rules)
{
	struct rule *next;
	int i;

	while (rules) {
		next = rules->next;
		free(rules->who);
		free(rules->as_user);
		free(rules->cmd);
		free(rules->deny_cmd);
		for (i = 0; i < rules->argc; i++)
			free(rules->args[i]);
		for (i = 0; i < rules->keepenv_count; i++)
			free(rules->keepenv[i]);
		free(rules);
		rules = next;
	}
}
