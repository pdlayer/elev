#include <ctype.h>
#include <grp.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

static char *
next_token(char **s)
{
	char *tok;
	char quote = 0;

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
	} else if (**s == '{') {
		while (**s && **s != '}')
			(*s)++;
		if (**s == '}')
			(*s)++;
	} else {
		while (**s && !isspace((unsigned char)**s))
			(*s)++;
	}

	if (**s) {
		**s = '\0';
		(*s)++;
	}

	return tok;
}

static long
parse_duration(const char *s)
{
	char *end;
	long val = strtol(s, &end, 10);

	if (*end == 'm')
		return val * 60;
	if (*end == 'h')
		return val * 3600;
	if (*end == 'd')
		return val * 86400;

	return val;
}

struct rule *
parse_config(const char *path)
{
	FILE *fp = fopen(path, "r");
	struct rule *head = NULL, *last = NULL, *r;
	char *line = NULL;
	size_t len = 0;
	char *p, *tok;

	if (!fp)
		return NULL;

	while (getline(&line, &len, fp) != -1) {
		p = trim(line);
		if (*p == '\0' || *p == '#' || (p[0] == '/' && p[1] == '/'))
			continue;

		r = calloc(1, sizeof(*r));
		if (!r)
			die("malloc");

		tok = next_token(&p);
		if (!tok)
			goto skip;

		if (strcmp(tok, "permit") == 0)
			r->type = RULE_PERMIT;
		else if (strcmp(tok, "deny") == 0)
			r->type = RULE_DENY;
		else
			goto skip;

		while ((tok = next_token(&p))) {
			if (strncmp(tok, "persist=", 8) == 0) {
				r->persist = parse_duration(tok + 8);
			} else if (strcmp(tok, "persist") == 0) {
				r->persist = -1;
			} else if (strcmp(tok, "nopass") == 0) {
				r->nopass = true;
			} else if (strncmp(tok, "keepenv", 7) == 0) {
				char *e = next_token(&p);
				if (e && e[0] == '{') {
					char *inner = strdup(e + 1);
					char *saveptr;
					char *v;
					if (inner[strlen(inner)-1] == '}')
						inner[strlen(inner)-1] = '\0';
					v = strtok_r(inner, ", ", &saveptr);
					while (v && r->keepenv_count < MAX_ENV_KEEP) {
						char *val = strdup(trim(v));
						if (!val)
							die("malloc");
						r->keepenv[r->keepenv_count++] = val;
						v = strtok_r(NULL, ", ", &saveptr);
					}
					free(inner);
				}
			} else {
				break;
			}
		}

		if (!tok)
			goto skip;

		if (tok[0] == ':') {
			r->is_group = true;
			r->who = strdup(tok + 1);
		} else {
			r->who = strdup(tok);
		}
		if (!r->who)
			die("malloc");

		tok = next_token(&p);
		if (!tok || strcmp(tok, "as") != 0)
			goto skip;

		tok = next_token(&p);
		if (!tok)
			goto skip;
		r->as_user = strdup(tok);
		if (!r->as_user)
			die("malloc");

		while ((tok = next_token(&p))) {
			if (strcmp(tok, "cmd") == 0) {
				char *cmd_path = next_token(&p);
				if (!cmd_path)
					goto skip;
				if (cmd_path[0] != '/')
					die("config: absolute path required: %s", cmd_path);
				r->cmd = strdup(cmd_path);
				if (!r->cmd)
					die("malloc");
				while ((tok = next_token(&p))) {
					if (strcmp(tok, "denycmd") == 0) {
						r->deny_cmd = strdup(next_token(&p));
						if (!r->deny_cmd)
							die("malloc");
						break;
					}
					if (r->argc < MAX_ARGC) {
						r->args[r->argc] = strdup(tok);
						if (!r->args[r->argc])
							die("malloc");
						r->argc++;
					}
				}
				break;
			} else if (strcmp(tok, "denycmd") == 0) {
				r->deny_cmd = strdup(next_token(&p));
				if (!r->deny_cmd)
					die("malloc");
			}
		}

		if (last)
			last->next = r;
		else
			head = r;
		last = r;
		continue;

	skip:
		free_rules(r);
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
