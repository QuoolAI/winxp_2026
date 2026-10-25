/* RoverAI query interpretation and grounded search. Portable C89.
   Natural language is reduced to structured criteria; results are always
   entries of the local index, never text produced by a model. */
#ifndef ROVER_QUERY_H
#define ROVER_QUERY_H
#include "../indexer/rover_index.h"

#define ROVER_MAX_TERMS 12
#define ROVER_MAX_EXTS 48

typedef enum {
    ROVER_SORT_RELEVANCE, ROVER_SORT_DATE_DESC, ROVER_SORT_DATE_ASC,
    ROVER_SORT_SIZE_DESC, ROVER_SORT_SIZE_ASC, ROVER_SORT_NAME
} ROVER_SORT;

typedef enum { ROVER_KIND_ANY, ROVER_KIND_FILES, ROVER_KIND_FOLDERS } ROVER_KIND;

typedef struct {
    char terms[ROVER_MAX_TERMS][40];  /* lowercase words matched against names, folders and content */
    size_t term_count;
    int terms_required;               /* every term must match (query with no other criteria) */
    char exts[ROVER_MAX_EXTS][8];     /* lowercase, without the dot */
    size_t ext_count;
    char type_label[32];
    ROVER_KIND kind;
    unsigned long after, before;      /* [after, before) seconds UTC; 0 = open */
    int created;                      /* date criteria apply to creation time */
    int year;                         /* named year; also matches a folder/file name containing it */
    xp25_u64 min_size, max_size;      /* max 0 = open */
    char location[260];               /* folder name or path fragment, lowercase */
    ROVER_SORT sort;
    int limit;
    int recognized;                   /* structured criteria found; 0 suggests asking the model */
    int config_names;                 /* also match extensionless system files such as hosts */
    int mine;                         /* "my ...": prefer files under home */
    char home[260];                   /* user profile path, set by the native caller */
    long bias;                        /* minutes; local time = UTC - bias */
} ROVER_CRITERIA;

typedef struct {
    const ROVER_ENTRY *entry;
    long score;
    int content_match;
} ROVER_HIT;

/* now: current UTC seconds; bias_minutes: local time = UTC - bias (Windows convention). */
void rover_query_parse(const char *query, unsigned long now, long bias_minutes, ROVER_CRITERIA *c);
/* Validate structured criteria produced by a model; rejects unknown fields
   and out-of-range values. Dates are "YYYY-MM-DD" in local time. */
int rover_criteria_from_json(const XP25_JNODE *object, unsigned long now, long bias_minutes,
                             ROVER_CRITERIA *c, char *error, size_t error_size);
void rover_criteria_json(const ROVER_CRITERIA *c, long bias_minutes, XP25_JW *w);
void rover_criteria_describe(const ROVER_CRITERIA *c, long bias_minutes, XP25_BUF *out);
/* scope: path prefix ("C:\Documents and Settings\XP25\My Documents"), or NULL for everything indexed. */
/* relaxed is set when no entry matched every term and the structured criteria alone were used. */
size_t rover_search(const ROVER_INDEX *index, const ROVER_CRITERIA *c, const char *scope,
                    ROVER_HIT *hits, size_t max_hits, size_t *total, int *relaxed);
const char *rover_type_name(const char *name, int directory);
extern const char rover_criteria_instructions[];

/* Calendar helpers (proleptic Gregorian, no time zone database). */
long rover_days_from_civil(long y, unsigned m, unsigned d);
void rover_civil_from_days(long z, long *y, unsigned *m, unsigned *d);
void rover_format_local(unsigned long utc, long bias_minutes, char out[20]);  /* YYYY-MM-DD HH:MM */
#endif
