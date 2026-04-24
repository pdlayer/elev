#ifndef ELEV_H
#define ELEV_H

#include <stdbool.h>
#include <security/pam_appl.h>
#include <stdint.h>
#include <sys/types.h>

#define ELEV_CONF "/etc/elev/conf"
#define ELEV_RUN "/run/elev"
#define MAX_ARGC 64
#define MAX_ENV_KEEP 64

enum rule_type {
	RULE_PERMIT,
	RULE_DENY,
};

struct rule {
	enum rule_type type;
	char *who;
	bool is_group;
	char *as_user;
	char *cmd;
	char *deny_cmd;
	char *args[MAX_ARGC];
	int argc;
	bool nopass;
	long persist;
	char *keepenv[MAX_ENV_KEEP];
	int keepenv_count;
	struct rule *next;
};

struct context {
	char *user;
	uid_t uid;
	gid_t gid;
	gid_t *groups;
	int group_count;
	char *target_user;
	uid_t target_uid;
	gid_t target_gid;
	char *target_name;
	char *target_home;
	char *target_shell;
	char **cmd_argv;
	int cmd_argc;
};

struct rule *parse_config(const char *path);
bool match_rule(const struct rule *r, const struct context *ctx);
void free_rules(struct rule *rules);
bool valid_env_name(const char *name);
void free_env_list(char **env);

int authenticate_pam(const char *user, const char *cache_scope,
	bool nopass, long persist,
	pam_handle_t **pamh, bool *session_open, bool *creds_established);
void cleanup_pam(pam_handle_t *pamh, bool session_open,
	bool creds_established, int pam_status);
void reset_persistence(const char *user);
void die(const char *fmt, ...) __attribute__((noreturn));


#endif
