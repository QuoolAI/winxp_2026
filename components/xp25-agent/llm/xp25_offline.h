/* XP25 AI runtime: offline assistant. A deterministic local planner that
   implements the provider interface without any network or model, using the
   same tools, permission policy and approvals as a remote provider. */
#ifndef XP25_OFFLINE_H
#define XP25_OFFLINE_H
#include "../runtime/xp25_agent.h"

typedef struct {
    unsigned long self_pid;      /* the assistant's own process is never proposed */
    int cpu_threshold;           /* percent of all CPUs that marks a runaway process */
    int cpu_single_threshold;    /* percent of one CPU: a single-threaded runaway on a multiprocessor */
    int memory_threshold;        /* system memory load percent that triggers memory advice */
    int disk_free_threshold;     /* percent free on the system drive */
} XP25_OFFLINE;

void xp25_offline_init(XP25_PROVIDER *provider, XP25_OFFLINE *settings);
/* Exposed for tests and for hosts that want the same wording. */
int xp25_offline_intent(const char *text);
const char *xp25_offline_intent_name(int intent);
/* File path named in a request ("quoted" or unquoted with trailing words). */
int xp25_offline_path(const char *text, char *path, size_t size);
/* Rule-based check of network settings in INI-style or hosts-style text.
   Writes findings; returns the number of problems. A single safe fix is
   reported through fix_line/fix_old/fix_new (fix_line 0 when none). */
int xp25_analyze_network_text(const char *text, XP25_BUF *findings, long *fix_line,
                              char *fix_old, char *fix_new, size_t fix_size);
#endif
