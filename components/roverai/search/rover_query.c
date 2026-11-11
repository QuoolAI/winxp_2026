/* RoverAI query interpretation and grounded search. Portable C89. */
#include <stdlib.h>
#include <string.h>
#include "rover_query.h"

const char rover_criteria_instructions[] =
    "Convert the user's file search request into JSON search criteria for a local Windows XP file "
    "index. Reply with one JSON object only, no prose. Allowed keys: terms (array of short lowercase "
    "words that should appear in file names, folder names or text), extensions (array of file "
    "extensions without dots), kind (\"any\", \"files\" or \"folders\"), modified_after and "
    "modified_before (\"YYYY-MM-DD\", local dates, after inclusive, before exclusive), date_field "
    "(\"modified\" or \"created\"), year (integer), min_size_bytes, max_size_bytes, location (folder "
    "name or path fragment), sort (\"relevance\", \"date_desc\", \"date_asc\", \"size_desc\", "
    "\"size_asc\", \"name\") and limit (1-500). Omit keys that do not apply. Never invent file names "
    "or paths; the search runs locally against real files.";

long rover_days_from_civil(long y, unsigned m, unsigned d)
{
    long era;
    unsigned yoe, doy, doe;
    y -= m <= 2;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = (unsigned)(y - era * 400);
    doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (long)doe - 719468;
}

void rover_civil_from_days(long z, long *y, unsigned *m, unsigned *d)
{
    long era;
    unsigned doe, yoe, doy, mp;
    z += 719468;
    era = (z >= 0 ? z : z - 146096) / 146097;
    doe = (unsigned)(z - era * 146097);
    yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    mp = (5 * doy + 2) / 153;
    *d = doy - (153 * mp + 2) / 5 + 1;
    *m = mp < 10 ? mp + 3 : mp - 9;
    *y = (long)yoe + era * 400 + (*m <= 2);
}

static xp25_i64 local_seconds(unsigned long utc, long bias) { return (xp25_i64)utc - (xp25_i64)bias * 60; }

/* UTC seconds of local midnight starting the given civil date. */
static unsigned long utc_of_day(long days, long bias)
{
    xp25_i64 s = (xp25_i64)days * 86400 + (xp25_i64)bias * 60;
    return s < 0 ? 0UL : (unsigned long)s;
}

static long local_day(unsigned long utc, long bias)
{
    xp25_i64 s = local_seconds(utc, bias);
    return (long)(s >= 0 ? s / 86400 : (s - 86399) / 86400);
}

void rover_format_local(unsigned long utc, long bias_minutes, char out[20])
{
    xp25_i64 s = local_seconds(utc, bias_minutes);
    long days = local_day(utc, bias_minutes), y;
    unsigned m, d;
    long rem = (long)(s - (xp25_i64)days * 86400);
    rover_civil_from_days(days, &y, &m, &d);
    out[0] = (char)('0' + (y / 1000) % 10); out[1] = (char)('0' + (y / 100) % 10);
    out[2] = (char)('0' + (y / 10) % 10); out[3] = (char)('0' + y % 10); out[4] = '-';
    out[5] = (char)('0' + m / 10); out[6] = (char)('0' + m % 10); out[7] = '-';
    out[8] = (char)('0' + d / 10); out[9] = (char)('0' + d % 10); out[10] = ' ';
    out[11] = (char)('0' + (rem / 3600) / 10); out[12] = (char)('0' + (rem / 3600) % 10); out[13] = ':';
    out[14] = (char)('0' + ((rem / 60) % 60) / 10); out[15] = (char)('0' + (rem / 60) % 10); out[16] = 0;
}

typedef struct { const char *word; const char *label; const char *exts; int kind; } TYPEWORD;

static const TYPEWORD type_words[] = {
    { "pdf", "PDF files", "pdf", 0 },
    { "document", "documents", "doc,docx,rtf,txt,pdf,wri,odt,wpd,xls,xlsx,ppt,pptx", 0 },
    { "doc", "documents", "doc,docx,rtf,txt,pdf,wri,odt,wpd", 0 },
    { "word", "Word documents", "doc,docx,rtf", 0 },
    { "photo", "pictures", "jpg,jpeg,png,gif,bmp,tif,tiff", 0 },
    { "picture", "pictures", "jpg,jpeg,png,gif,bmp,tif,tiff", 0 },
    { "image", "pictures", "jpg,jpeg,png,gif,bmp,tif,tiff,ico", 0 },
    { "pic", "pictures", "jpg,jpeg,png,gif,bmp,tif,tiff", 0 },
    { "video", "videos", "avi,mpg,mpeg,wmv,asf,mp4,mov,mkv,m4v,3gp,vob,flv", 0 },
    { "movie", "videos", "avi,mpg,mpeg,wmv,asf,mp4,mov,mkv,m4v,3gp,vob,flv", 0 },
    { "clip", "videos", "avi,mpg,mpeg,wmv,asf,mp4,mov,mkv,m4v,3gp", 0 },
    { "music", "music", "mp3,wma,wav,mid,midi,ogg,flac,aac,m4a", 0 },
    { "song", "music", "mp3,wma,wav,mid,midi,ogg,flac,aac,m4a", 0 },
    { "audio", "audio", "mp3,wma,wav,mid,midi,ogg,flac,aac,m4a", 0 },
    { "spreadsheet", "spreadsheets", "xls,xlsx,csv,ods,wks", 0 },
    { "excel", "spreadsheets", "xls,xlsx,csv", 0 },
    { "presentation", "presentations", "ppt,pptx,pps,odp", 0 },
    { "powerpoint", "presentations", "ppt,pptx,pps", 0 },
    { "slide", "presentations", "ppt,pptx,pps,odp", 0 },
    { "archive", "archives", "zip,cab,rar,7z,tar,gz,arj", 0 },
    { "zip", "archives", "zip", 0 },
    { "program", "programs", "exe,msi,com,bat,cmd", 0 },
    { "executable", "programs", "exe,com", 0 },
    { "installer", "installers", "msi,exe", 0 },
    { "text", "text files", "txt,log,ini,csv,md,nfo", 0 },
    { "log", "log files", "log,txt", 0 },
    { "config", "configuration files", "ini,cfg,conf,inf,xml,reg,sam", 0 },
    { "configuration", "configuration files", "ini,cfg,conf,inf,xml,reg,sam", 0 },
    { "code", "source code", "c,h,cpp,hpp,cs,java,py,js,vb,vbs,pas,asm,bat,cmd,sln,dsp,dsw,vcproj,mak", 0 },
    { "source", "source code", "c,h,cpp,hpp,cs,java,py,js,vb,vbs,pas,asm,sln,dsp,dsw,vcproj,mak", 0 },
    { "email", "e-mail", "eml,msg,dbx,mbx", 0 },
    { "mail", "e-mail", "eml,msg,dbx,mbx", 0 },
    { "shortcut", "shortcuts", "lnk,url,pif", 0 },
    { "font", "fonts", "ttf,fon,otf", 0 },
    { "webpage", "web pages", "htm,html,mht,mhtml", 0 },
    { "folder", "folders", "", ROVER_KIND_FOLDERS },
    { "directory", "folders", "", ROVER_KIND_FOLDERS },
    { "directorie", "folders", "", ROVER_KIND_FOLDERS },
    { NULL, NULL, NULL, 0 }
};

static const char *stop_words[] = {
    "find", "show", "me", "my", "the", "a", "an", "all", "any", "some", "where", "are", "is", "was",
    "were", "i", "that", "which", "with", "for", "of", "please", "file", "files", "item", "items",
    "stuff", "did", "do", "have", "had", "at", "to", "and", "or", "look", "locate", "search", "get",
    "list", "give", "what", "whats", "can", "you", "there", "it", "them", "those", "these", "mine",
    "our", "your", "edited", "modified", "changed", "worked", "saved", "updated", "made", "wrote",
    "written", "opened", "used", "on", "in", "from", "by", "be", "been", "this", "last", "past",
    "need", "want", "help", "kept", "put", "stored", "store", "save", "named", "called", "about",
    "containing", "contain", "contains", "mention", "mentions", "mentioning", "regarding", "related",
    "one", "ones", "thing", "things", "computer", "pc", "machine", "everywhere", "anywhere", "lost",
    "taken", "created", "biggest", "largest", "smallest", "large", "big", "huge", "small", "tiny",
    "recent", "recently", "latest", "newest", "oldest", "new", "old", "first", "most", "least",
    "than", "over", "under", "more", "less", "above", "below", "before", "after", "since", "during",
    "around", "ago", "week", "weeks", "month", "months", "year", "years", "day", "days", "today",
    "yesterday", "tonight", "morning", "afternoon", "evening", "into", "inside", "drive", "see", "may",
    "explain", "wrong", "fix", "check", "why", "how", "tell", "analyze", "analyse", "open", "read",
    "problem", "problems", "issue", "issues", "broken", "not", "working", "whats", "doesn", "isn",
    "summarize", "review", "look", NULL
};

static const struct { const char *term; const char *alts; } synonyms[] = {
    { "vacation", "vacation,holiday,trip,travel,beach,summer" },
    { "holiday", "holiday,vacation,trip,travel" },
    { "insurance", "insurance,insur,policy,claim" },
    { "tax", "tax,taxes,irs,w2,1040" },
    { "resume", "resume,cv,curriculum" },
    { "invoice", "invoice,bill,receipt" },
    { "network", "network,net,tcpip,lan,wlan,wifi,dns,dhcp,hosts,lmhosts,ip" },
    { "photo", "photo,img,dsc,pic,picture" },
    { "project", "project,proj" },
    { NULL, NULL }
};

static int is_stop(const char *w)
{
    size_t i;
    for (i = 0; stop_words[i]; ++i) if (!strcmp(w, stop_words[i])) return 1;
    return 0;
}

static const char *month_names[] = { "january", "february", "march", "april", "may", "june", "july",
                                     "august", "september", "october", "november", "december" };

static int month_of(const char *w)
{
    int i;
    for (i = 0; i < 12; ++i)
        if (!strcmp(w, month_names[i]) || (strlen(w) == 3 && !strncmp(w, month_names[i], 3) && i != 4))
            return i + 1;
    if (!strcmp(w, "sept")) return 9;
    return 0;
}

#define MAX_TOKENS 64
typedef struct {
    char text[MAX_TOKENS][40];
    int used[MAX_TOKENS];
    size_t count;
} TOKENS;

static void add_ext(ROVER_CRITERIA *c, const char *ext, size_t n)
{
    size_t i;
    if (!n || n > 7) return;
    for (i = 0; i < c->ext_count; ++i)
        if (strlen(c->exts[i]) == n && xp25_strnieq(c->exts[i], ext, n)) return;
    if (c->ext_count == ROVER_MAX_EXTS) return;
    for (i = 0; i < n; ++i) c->exts[c->ext_count][i] = (char)xp25_lower((unsigned char)ext[i]);
    c->exts[c->ext_count][n] = 0;
    ++c->ext_count;
}

static void add_ext_list(ROVER_CRITERIA *c, const char *list)
{
    while (*list) {
        const char *comma = strchr(list, ',');
        size_t n = comma ? (size_t)(comma - list) : strlen(list);
        add_ext(c, list, n);
        list += n + (comma ? 1 : 0);
    }
}

static void add_term(ROVER_CRITERIA *c, const char *w)
{
    size_t n = strlen(w), i;
    char term[40];
    if (n < 2 || n >= sizeof(term) || c->term_count == ROVER_MAX_TERMS) return;
    strcpy(term, w);
    if (n > 4 && term[n - 1] == 's' && term[n - 2] != 's') term[n - 1] = 0;   /* simple plural */
    for (i = 0; i < c->term_count; ++i) if (!strcmp(c->terms[i], term)) return;
    strcpy(c->terms[c->term_count++], term);
}

static void tokenize(const char *q, TOKENS *t, ROVER_CRITERIA *c)
{
    const char *p = q;
    memset(t, 0, sizeof(*t));
    while (*p && t->count < MAX_TOKENS) {
        size_t n = 0;
        unsigned char ch = (unsigned char)*p;
        if (ch == '"') {
            /* "exact phrase": becomes one required name term */
            const char *end = strchr(p + 1, '"');
            if (end && end > p + 1 && (size_t)(end - p - 1) < 40) {
                char term[40];
                size_t i, len = (size_t)(end - p - 1);
                for (i = 0; i < len; ++i) term[i] = (char)xp25_lower((unsigned char)p[1 + i]);
                term[len] = 0;
                add_term(c, term);
                p = end + 1;
                continue;
            }
            ++p;
            continue;
        }
        if ((ch == '.' || ch == '*') && (p == q || xp25_is_space((unsigned char)p[-1]))) {
            const char *s = p + (ch == '*' && p[1] == '.' ? 2 : 1);
            const char *e = s;
            while (xp25_is_alpha((unsigned char)*e) || xp25_is_digit((unsigned char)*e)) ++e;
            if (e > s && e - s <= 7 && (ch == '.' || s[-1] == '.')) {
                add_ext(c, s, (size_t)(e - s));
                ++c->recognized;
                p = e;
                continue;
            }
        }
        if (xp25_is_alpha(ch) || xp25_is_digit(ch) || ch >= 0x80) {
            while ((xp25_is_alpha((unsigned char)p[n]) || xp25_is_digit((unsigned char)p[n]) ||
                    (unsigned char)p[n] >= 0x80 || (p[n] == ':' && n == 1 && xp25_is_alpha(ch))) && n < 39) {
                t->text[t->count][n] = (char)xp25_lower((unsigned char)p[n]);
                ++n;
            }
            t->text[t->count][n] = 0;
            ++t->count;
            p += n;
            while (xp25_is_alpha((unsigned char)*p) || xp25_is_digit((unsigned char)*p)) ++p;
            continue;
        }
        ++p;
    }
}

static int word_is(const TOKENS *t, size_t i, const char *w) { return i < t->count && !strcmp(t->text[i], w); }

static int number_at(const TOKENS *t, size_t i, xp25_u64 *v)
{
    return i < t->count && xp25_parse_u64(t->text[i], strlen(t->text[i]), v);
}

static xp25_u64 unit_of(const char *w)
{
    if (!strcmp(w, "kb") || !strcmp(w, "k") || !strcmp(w, "kilobytes")) return 1024;
    if (!strcmp(w, "mb") || !strcmp(w, "m") || !strcmp(w, "megs") || !strcmp(w, "megabytes")) return 1024 * 1024;
    if (!strcmp(w, "gb") || !strcmp(w, "g") || !strcmp(w, "gigs") || !strcmp(w, "gigabytes")) return (xp25_u64)1024 * 1024 * 1024;
    if (!strcmp(w, "bytes") || !strcmp(w, "b")) return 1;
    return 0;
}

/* Size phrase starting at token i ("10 mb", "10mb"); returns tokens consumed. */
static size_t size_at(const TOKENS *t, size_t i, xp25_u64 *bytes)
{
    xp25_u64 v, unit;
    const char *w;
    size_t n;
    if (i >= t->count) return 0;
    w = t->text[i];
    for (n = 0; xp25_is_digit((unsigned char)w[n]); ++n) {}
    if (!n || !xp25_parse_u64(w, n, &v)) return 0;
    if (w[n]) {
        unit = unit_of(w + n);
        if (!unit) return 0;
        *bytes = v * unit;
        return 1;
    }
    unit = i + 1 < t->count ? unit_of(t->text[i + 1]) : 0;
    if (!unit) return 0;
    *bytes = v * unit;
    return 2;
}

static void set_range(ROVER_CRITERIA *c, long first_day, long end_day, long bias)
{
    c->after = utc_of_day(first_day, bias);
    c->before = utc_of_day(end_day, bias);
    ++c->recognized;
}

static void type_label(ROVER_CRITERIA *c, const char *label)
{
    if (!c->type_label[0]) { strncpy(c->type_label, label, sizeof(c->type_label) - 1); return; }
    if (strcmp(c->type_label, label) && strlen(c->type_label) + strlen(label) + 3 < sizeof(c->type_label)) {
        strcat(c->type_label, " / ");
        strcat(c->type_label, label);
    }
}

void rover_query_parse(const char *query, unsigned long now, long bias, ROVER_CRITERIA *c)
{
    TOKENS t;
    size_t i, k;
    long today = local_day(now, bias), y;
    unsigned m, d;
    int created = 0;
    memset(c, 0, sizeof(*c));
    c->limit = 100;
    c->sort = ROVER_SORT_RELEVANCE;
    c->bias = bias;
    if (!query) return;
    tokenize(query, &t, c);
    rover_civil_from_days(today, &y, &m, &d);
    for (i = 0; i < t.count; ++i) {
        const char *w = t.text[i];
        xp25_u64 n, bytes;
        size_t used;
        int month;
        if (t.used[i]) continue;
        if (!strcmp(w, "created") || !strcmp(w, "taken") || !strcmp(w, "made")) created = 1;
        if (!strcmp(w, "today")) { set_range(c, today, today + 1, bias); t.used[i] = 1; continue; }
        if (!strcmp(w, "yesterday")) { set_range(c, today - 1, today, bias); t.used[i] = 1; continue; }
        if ((!strcmp(w, "this") || !strcmp(w, "last") || !strcmp(w, "past")) && i + 1 < t.count) {
            const char *u = t.text[i + 1];
            long monday = today - (long)((today + 3) % 7);    /* 1970-01-01 was a Thursday */
            int last = strcmp(w, "this") != 0;
            if (!strcmp(u, "week")) {
                /* "last week" covers the previous calendar week through today: people often mean the past few days. */
                set_range(c, last ? monday - 7 : monday, today + 1, bias);
                t.used[i] = t.used[i + 1] = 1;
                continue;
            }
            if (!strcmp(u, "month")) {
                long first = rover_days_from_civil(y, m, 1);
                if (last) {
                    long py = m == 1 ? y - 1 : y;
                    unsigned pm = m == 1 ? 12 : m - 1;
                    set_range(c, rover_days_from_civil(py, pm, 1), first, bias);
                } else set_range(c, first, today + 1, bias);
                t.used[i] = t.used[i + 1] = 1;
                continue;
            }
            if (!strcmp(u, "year")) {
                if (last) set_range(c, rover_days_from_civil(y - 1, 1, 1), rover_days_from_civil(y, 1, 1), bias);
                else set_range(c, rover_days_from_civil(y, 1, 1), today + 1, bias);
                t.used[i] = t.used[i + 1] = 1;
                continue;
            }
            if (number_at(&t, i + 1, &n) && n > 0 && n < 36500 && i + 2 < t.count &&
                (word_is(&t, i + 2, "days") || word_is(&t, i + 2, "day") ||
                 word_is(&t, i + 2, "weeks") || word_is(&t, i + 2, "week") ||
                 word_is(&t, i + 2, "months") || word_is(&t, i + 2, "month"))) {
                long span = (long)n * (t.text[i + 2][0] == 'w' ? 7 : t.text[i + 2][0] == 'm' ? 30 : 1);
                set_range(c, today - span + 1, today + 1, bias);
                c->before = 0;
                t.used[i] = t.used[i + 1] = t.used[i + 2] = 1;
                continue;
            }
        }
        if (!strcmp(w, "recent") || !strcmp(w, "recently") || !strcmp(w, "latest") || !strcmp(w, "newest")) {
            c->sort = ROVER_SORT_DATE_DESC; ++c->recognized; t.used[i] = 1; continue;
        }
        if (!strcmp(w, "oldest")) { c->sort = ROVER_SORT_DATE_ASC; ++c->recognized; t.used[i] = 1; continue; }
        if (!strcmp(w, "largest") || !strcmp(w, "biggest")) { c->sort = ROVER_SORT_SIZE_DESC; ++c->recognized; t.used[i] = 1; continue; }
        if (!strcmp(w, "smallest")) { c->sort = ROVER_SORT_SIZE_ASC; ++c->recognized; t.used[i] = 1; continue; }
        if (!strcmp(w, "huge")) { c->min_size = (xp25_u64)100 * 1024 * 1024; ++c->recognized; t.used[i] = 1; continue; }
        if ((!strcmp(w, "large") || !strcmp(w, "big")) && !c->min_size) {
            c->min_size = (xp25_u64)10 * 1024 * 1024; ++c->recognized; t.used[i] = 1; continue;
        }
        if (!strcmp(w, "small") || !strcmp(w, "tiny")) { c->max_size = 100 * 1024; ++c->recognized; t.used[i] = 1; continue; }
        if (!strcmp(w, "over") || !strcmp(w, "above") || !strcmp(w, "least") ||
            ((!strcmp(w, "larger") || !strcmp(w, "bigger") || !strcmp(w, "more")) && word_is(&t, i + 1, "than"))) {
            k = word_is(&t, i + 1, "than") ? i + 2 : i + 1;
            used = size_at(&t, k, &bytes);
            if (used) { c->min_size = bytes; ++c->recognized; for (; i < k + used; ++i) t.used[i] = 1; --i; continue; }
        }
        if (!strcmp(w, "under") || !strcmp(w, "below") ||
            ((!strcmp(w, "smaller") || !strcmp(w, "less")) && word_is(&t, i + 1, "than"))) {
            k = word_is(&t, i + 1, "than") ? i + 2 : i + 1;
            used = size_at(&t, k, &bytes);
            if (used) { c->max_size = bytes; ++c->recognized; for (; i < k + used; ++i) t.used[i] = 1; --i; continue; }
        }
        month = month_of(w);
        {
            xp25_u64 yy = 0;
            int with_year = number_at(&t, i + 1, &yy) && yy >= 1980 && yy <= 2100;
            if (month == 5 && !with_year) month = 0;   /* "may" is usually a verb */
            if (month) {
            long year = (unsigned)month <= m ? y : y - 1;
            if (with_year) { year = (long)yy; t.used[i + 1] = 1; }
            set_range(c, rover_days_from_civil(year, (unsigned)month, 1),
                      month == 12 ? rover_days_from_civil(year + 1, 1, 1) : rover_days_from_civil(year, (unsigned)month + 1, 1), bias);
            t.used[i] = 1;
            continue;
            }
        }
        if (number_at(&t, i, &n) && n >= 1980 && n <= 2100 && strlen(w) == 4) {
            if (i > 0 && word_is(&t, i - 1, "before")) {
                c->before = utc_of_day(rover_days_from_civil((long)n, 1, 1), bias);
                ++c->recognized;
            } else if (i > 0 && (word_is(&t, i - 1, "after") || word_is(&t, i - 1, "since"))) {
                c->after = utc_of_day(rover_days_from_civil((long)n + (word_is(&t, i - 1, "after") ? 1 : 0), 1, 1), bias);
                ++c->recognized;
            } else {
                c->year = (int)n;
                ++c->recognized;
            }
            t.used[i] = 1;
            continue;
        }
        if (!strcmp(w, "desktop") || (!strcmp(w, "documents") && i > 0 && word_is(&t, i - 1, "my")) ||
            ((!strcmp(w, "pictures") || !strcmp(w, "music") || !strcmp(w, "videos")) && i > 0 && word_is(&t, i - 1, "my") &&
             (i + 1 >= t.count || word_is(&t, i + 1, "folder")))) {
            if (!strcmp(w, "desktop")) strcpy(c->location, "desktop");
            else { strcpy(c->location, "my "); strcat(c->location, w); }
            ++c->recognized;
            t.used[i] = 1;
            continue;
        }
        if (strlen(w) == 2 && w[1] == ':' && xp25_is_alpha((unsigned char)w[0])) {
            c->location[0] = w[0]; c->location[1] = ':'; c->location[2] = '\\'; c->location[3] = 0;
            ++c->recognized;
            t.used[i] = 1;
            continue;
        }
        if (!strcmp(w, "drive") && i + 1 < t.count && strlen(t.text[i + 1]) == 1 && xp25_is_alpha((unsigned char)t.text[i + 1][0])) {
            c->location[0] = t.text[i + 1][0]; c->location[1] = ':'; c->location[2] = '\\'; c->location[3] = 0;
            ++c->recognized;
            t.used[i] = t.used[i + 1] = 1;
            continue;
        }
        if ((!strcmp(w, "in") || !strcmp(w, "inside") || !strcmp(w, "under")) && i + 1 < t.count && !t.used[i + 1] &&
            word_is(&t, i + 2, "folder") && !is_stop(t.text[i + 1])) {
            strncpy(c->location, t.text[i + 1], sizeof(c->location) - 1);
            ++c->recognized;
            t.used[i] = t.used[i + 1] = t.used[i + 2] = 1;
            continue;
        }
        {
            size_t len = strlen(w);
            char singular[40];
            const TYPEWORD *tw;
            strcpy(singular, w);
            if (len > 3 && singular[len - 1] == 's' && singular[len - 2] != 's') singular[len - 1] = 0;
            for (tw = type_words; tw->word; ++tw)
                if (!strcmp(singular, tw->word) || !strcmp(w, tw->word)) break;
            if (tw->word) {
                if (tw->kind) c->kind = (ROVER_KIND)tw->kind;
                else { add_ext_list(c, tw->exts); c->kind = ROVER_KIND_FILES; }
                if (!strncmp(tw->word, "config", 6)) c->config_names = 1;
                type_label(c, tw->label);
                ++c->recognized;
                t.used[i] = 1;
                continue;
            }
            /* "mp3 files", "xls" */
            if (len >= 2 && len <= 4 && (word_is(&t, i + 1, "files") || word_is(&t, i + 1, "file"))) {
                add_ext(c, w, len);
                type_label(c, w);
                c->kind = ROVER_KIND_FILES;
                ++c->recognized;
                t.used[i] = 1;
                continue;
            }
        }
    }
    c->created = created;
    /* "my ..." or "I edited/worked on/created ..." asks for the user's own files. */
    for (i = 0; i < t.count; ++i) {
        static const char *acts[] = { "edited", "worked", "modified", "changed", "saved", "created", "wrote", "made",
                                      "opened", "used", "downloaded", "took", "scanned", NULL };
        size_t a;
        if (!strcmp(t.text[i], "my") || !strcmp(t.text[i], "mine")) c->mine = 1;
        for (a = 0; acts[a] && !strcmp(t.text[i], "i") && i + 1 < t.count; ++a)
            if (!strcmp(t.text[i + 1], acts[a])) c->mine = 1;
    }
    for (i = 0; i < t.count; ++i)
        if (c->kind == ROVER_KIND_ANY && (!strcmp(t.text[i], "file") || !strcmp(t.text[i], "files"))) c->kind = ROVER_KIND_FILES;
    for (i = 0; i < t.count; ++i)
        if (!t.used[i] && !is_stop(t.text[i]) && !month_of(t.text[i])) add_term(c, t.text[i]);
    c->terms_required = 1;
}

static int read_date(const char *s, unsigned long *out, long bias)
{
    xp25_u64 y, m, d;
    if (!s || strlen(s) != 10 || s[4] != '-' || s[7] != '-') return 0;
    if (!xp25_parse_u64(s, 4, &y) || !xp25_parse_u64(s + 5, 2, &m) || !xp25_parse_u64(s + 8, 2, &d)) return 0;
    if (y < 1980 || y > 2100 || m < 1 || m > 12 || d < 1 || d > 31) return 0;
    *out = utc_of_day(rover_days_from_civil((long)y, (unsigned)m, (unsigned)d), bias);
    return 1;
}

static int bad(char *error, size_t size, const char *text)
{
    if (error && size) { strncpy(error, text, size - 1); error[size - 1] = 0; }
    return 0;
}

int rover_criteria_from_json(const XP25_JNODE *o, unsigned long now, long bias, ROVER_CRITERIA *c,
                             char *error, size_t error_size)
{
    const XP25_JNODE *field, *v;
    (void)now;
    memset(c, 0, sizeof(*c));
    c->limit = 100;
    c->terms_required = 1;
    c->bias = bias;
    if (!o || o->type != XP25_JOBJ) return bad(error, error_size, "criteria must be a JSON object");
    for (field = o->child; field; field = field->next) {
        const char *k = field->key;
        xp25_i64 n;
        if (!strcmp(k, "terms") || !strcmp(k, "extensions")) {
            if (field->type != XP25_JARR || field->count > (size_t)(k[0] == 't' ? ROVER_MAX_TERMS : ROVER_MAX_EXTS))
                return bad(error, error_size, "terms/extensions must be short arrays");
            for (v = field->child; v; v = v->next) {
                size_t i;
                if (v->type != XP25_JSTR || !v->len || v->len >= (size_t)(k[0] == 't' ? 40 : 8))
                    return bad(error, error_size, "invalid term or extension");
                for (i = 0; i < v->len; ++i) {
                    unsigned char ch = (unsigned char)v->str[i];
                    if (k[0] == 'e' && i == 0 && ch == '.' && v->len > 1) continue;
                    if (!(xp25_is_alpha(ch) || xp25_is_digit(ch) || ch >= 0x80 || (k[0] == 't' && strchr(" -_'", ch))))
                        return bad(error, error_size, "invalid character in term or extension");
                }
                if (k[0] == 't') {
                    char term[40];
                    for (i = 0; i < v->len; ++i) term[i] = (char)xp25_lower((unsigned char)v->str[i]);
                    term[v->len] = 0;
                    add_term(c, term);
                } else add_ext(c, v->str[0] == '.' ? v->str + 1 : v->str, v->str[0] == '.' ? v->len - 1 : v->len);
            }
            if (k[0] == 'e' && c->ext_count) { c->kind = ROVER_KIND_FILES; ++c->recognized; }
        } else if (!strcmp(k, "kind")) {
            const char *s = field->type == XP25_JSTR ? field->str : "";
            if (!strcmp(s, "any")) c->kind = ROVER_KIND_ANY;
            else if (!strcmp(s, "files")) c->kind = ROVER_KIND_FILES;
            else if (!strcmp(s, "folders")) { c->kind = ROVER_KIND_FOLDERS; ++c->recognized; }
            else return bad(error, error_size, "kind must be any, files or folders");
        } else if (!strcmp(k, "modified_after") || !strcmp(k, "modified_before")) {
            unsigned long *slot = k[9] == 'a' ? &c->after : &c->before;
            if (field->type != XP25_JSTR || !read_date(field->str, slot, bias))
                return bad(error, error_size, "dates must be YYYY-MM-DD");
            ++c->recognized;
        } else if (!strcmp(k, "date_field")) {
            if (field->type != XP25_JSTR || (strcmp(field->str, "modified") && strcmp(field->str, "created")))
                return bad(error, error_size, "date_field must be modified or created");
            c->created = !strcmp(field->str, "created");
        } else if (!strcmp(k, "year")) {
            if (!xp25_json_node_i64(field, &n) || n < 1980 || n > 2100) return bad(error, error_size, "year out of range");
            c->year = (int)n;
            ++c->recognized;
        } else if (!strcmp(k, "min_size_bytes") || !strcmp(k, "max_size_bytes")) {
            if (!xp25_json_node_i64(field, &n) || n < 0) return bad(error, error_size, "sizes must be non-negative integers");
            if (k[1] == 'i') c->min_size = (xp25_u64)n; else c->max_size = (xp25_u64)n;
            ++c->recognized;
        } else if (!strcmp(k, "location")) {
            size_t i;
            if (field->type != XP25_JSTR || field->len >= sizeof(c->location)) return bad(error, error_size, "invalid location");
            for (i = 0; i < field->len; ++i) {
                if ((unsigned char)field->str[i] < 0x20 || strchr("*?\"<>|", field->str[i]))
                    return bad(error, error_size, "invalid location");
                c->location[i] = (char)xp25_lower((unsigned char)field->str[i]);
            }
            c->location[field->len] = 0;
            if (field->len) ++c->recognized;
        } else if (!strcmp(k, "sort")) {
            static const char *names[] = { "relevance", "date_desc", "date_asc", "size_desc", "size_asc", "name", NULL };
            int s;
            for (s = 0; names[s]; ++s) if (field->type == XP25_JSTR && !strcmp(field->str, names[s])) break;
            if (!names[s]) return bad(error, error_size, "unknown sort");
            c->sort = (ROVER_SORT)s;
            if (s) ++c->recognized;
        } else if (!strcmp(k, "limit")) {
            if (!xp25_json_node_i64(field, &n) || n < 1 || n > 500) return bad(error, error_size, "limit must be 1-500");
            c->limit = (int)n;
        } else return bad(error, error_size, "unknown criteria field");
    }
    if (c->before && c->after && c->before <= c->after) return bad(error, error_size, "empty date range");
    if (c->max_size && c->min_size > c->max_size) return bad(error, error_size, "empty size range");
    return 1;
}

static void day_text(unsigned long utc, long bias, char out[11])
{
    char full[20];
    rover_format_local(utc, bias, full);
    memcpy(out, full, 10);
    out[10] = 0;
}

void rover_criteria_json(const ROVER_CRITERIA *c, long bias, XP25_JW *w)
{
    static const char *sorts[] = { "relevance", "date_desc", "date_asc", "size_desc", "size_asc", "name" };
    char day[11];
    size_t i;
    xp25_jw_obj(w);
    xp25_jw_key(w, "terms"); xp25_jw_arr(w);
    for (i = 0; i < c->term_count; ++i) xp25_jw_str(w, c->terms[i]);
    xp25_jw_end(w);
    xp25_jw_key(w, "extensions"); xp25_jw_arr(w);
    for (i = 0; i < c->ext_count; ++i) xp25_jw_str(w, c->exts[i]);
    xp25_jw_end(w);
    xp25_jw_key(w, "kind"); xp25_jw_str(w, c->kind == ROVER_KIND_FOLDERS ? "folders" : c->kind == ROVER_KIND_FILES ? "files" : "any");
    if (c->after) { day_text(c->after, bias, day); xp25_jw_key(w, "modified_after"); xp25_jw_str(w, day); }
    if (c->before) { day_text(c->before, bias, day); xp25_jw_key(w, "modified_before"); xp25_jw_str(w, day); }
    if (c->after || c->before) { xp25_jw_key(w, "date_field"); xp25_jw_str(w, c->created ? "created" : "modified"); }
    if (c->year) { xp25_jw_key(w, "year"); xp25_jw_i64(w, c->year); }
    if (c->min_size) { xp25_jw_key(w, "min_size_bytes"); xp25_jw_u64(w, c->min_size); }
    if (c->max_size) { xp25_jw_key(w, "max_size_bytes"); xp25_jw_u64(w, c->max_size); }
    if (c->location[0]) { xp25_jw_key(w, "location"); xp25_jw_str(w, c->location); }
    xp25_jw_key(w, "sort"); xp25_jw_str(w, sorts[c->sort]);
    xp25_jw_key(w, "limit"); xp25_jw_i64(w, c->limit);
    xp25_jw_end(w);
}

void rover_criteria_describe(const ROVER_CRITERIA *c, long bias, XP25_BUF *out)
{
    char day[11];
    size_t i;
    xp25_buf_reset(out);
    if (c->type_label[0]) xp25_buf_puts(out, c->type_label);
    else if (c->ext_count) {
        for (i = 0; i < c->ext_count && i < 4; ++i) {
            if (i) xp25_buf_puts(out, ", ");
            xp25_buf_puts(out, c->exts[i]);
        }
        xp25_buf_puts(out, " files");
    } else xp25_buf_puts(out, c->kind == ROVER_KIND_FOLDERS ? "Folders" : "Files and folders");
    if (c->term_count) {
        xp25_buf_puts(out, " matching ");
        for (i = 0; i < c->term_count; ++i) {
            if (i) xp25_buf_puts(out, " + ");
            xp25_buf_putc(out, '\'');
            xp25_buf_puts(out, c->terms[i]);
            xp25_buf_putc(out, '\'');
        }
    }
    if (c->after || c->before) {
        xp25_buf_puts(out, c->created ? ", created" : ", modified");
        if (c->after) { day_text(c->after, bias, day); xp25_buf_puts(out, " from "); xp25_buf_puts(out, day); }
        if (c->before) {
            /* Show the inclusive last day. */
            day_text(c->before > 86400 ? c->before - 86400 : c->before, bias, day);
            xp25_buf_puts(out, " through ");
            xp25_buf_puts(out, day);
        }
    }
    if (c->year) { xp25_buf_puts(out, ", from "); xp25_buf_i64(out, c->year); }
    if (c->min_size) { xp25_buf_puts(out, ", at least "); xp25_buf_size(out, c->min_size); }
    if (c->max_size) { xp25_buf_puts(out, ", at most "); xp25_buf_size(out, c->max_size); }
    if (c->location[0]) { xp25_buf_puts(out, ", in '"); xp25_buf_puts(out, c->location); xp25_buf_putc(out, '\''); }
    if (c->sort == ROVER_SORT_SIZE_DESC) xp25_buf_puts(out, ", largest first");
    else if (c->sort == ROVER_SORT_SIZE_ASC) xp25_buf_puts(out, ", smallest first");
    else if (c->sort == ROVER_SORT_DATE_DESC) xp25_buf_puts(out, ", newest first");
    else if (c->sort == ROVER_SORT_DATE_ASC) xp25_buf_puts(out, ", oldest first");
}

const char *rover_type_name(const char *name, int directory)
{
    static const struct { const char *ext, *label; } types[] = {
        { "pdf", "PDF Document" }, { "doc", "Word Document" }, { "docx", "Word Document" },
        { "rtf", "Rich Text Document" }, { "txt", "Text Document" }, { "log", "Log File" },
        { "ini", "Configuration Settings" }, { "inf", "Setup Information" }, { "xml", "XML Document" },
        { "htm", "HTML Document" }, { "html", "HTML Document" }, { "jpg", "JPEG Image" },
        { "jpeg", "JPEG Image" }, { "png", "PNG Image" }, { "gif", "GIF Image" }, { "bmp", "Bitmap Image" },
        { "tif", "TIFF Image" }, { "avi", "Video Clip" }, { "mpg", "Movie Clip" }, { "mpeg", "Movie Clip" },
        { "wmv", "Windows Media Video" }, { "mp4", "MP4 Video" }, { "mov", "QuickTime Movie" },
        { "mp3", "MP3 Audio" }, { "wma", "Windows Media Audio" }, { "wav", "Wave Sound" },
        { "xls", "Excel Worksheet" }, { "xlsx", "Excel Worksheet" }, { "csv", "CSV File" },
        { "ppt", "PowerPoint Presentation" }, { "zip", "Compressed Folder" }, { "cab", "Cabinet File" },
        { "exe", "Application" }, { "msi", "Windows Installer Package" }, { "dll", "Application Extension" },
        { "lnk", "Shortcut" }, { "bat", "Batch File" }, { "cmd", "Command Script" }, { "c", "C Source" },
        { "h", "C Header" }, { "cpp", "C++ Source" }, { "py", "Python Script" }, { "js", "JScript File" },
        { "vbs", "VBScript File" }, { "reg", "Registration Entries" }, { NULL, NULL } };
    const char *dot;
    size_t i;
    if (directory) return "File Folder";
    dot = strrchr(name, '.');
    if (dot && !strchr(dot, '\\'))
        for (i = 0; types[i].ext; ++i)
            if (xp25_strieq(dot + 1, types[i].ext)) return types[i].label;
    return "File";
}

static int has_ext(const ROVER_CRITERIA *c, const char *name)
{
    static const char *config_files[] = { "hosts", "networks", "protocol", "services", "lmhosts", NULL };
    const char *dot = strrchr(name, '.');
    size_t i;
    if (!c->ext_count) return 1;
    if (!dot) {
        for (i = 0; c->config_names && config_files[i]; ++i) if (xp25_strieq(name, config_files[i])) return 1;
        return 0;
    }
    for (i = 0; i < c->ext_count; ++i) if (xp25_strieq(dot + 1, c->exts[i])) return 1;
    return 0;
}

/* Occurrence of word in text. The user's own words may match inside a name
   ("insurance" in "Insurance_Policy"); synonyms must start a token so that
   "proj" matches "Projects" but not "msproj95", and words of three letters
   or fewer must be a whole token ("ip" never matches "zip"). */
static const char *find_word(const char *text, const char *word, size_t n, const char *limit, int synonym)
{
    const char *hit = text;
    while ((hit = xp25_stristr(hit, word)) != NULL && (!limit || hit < limit)) {
        int before = hit == text || !(xp25_is_alpha((unsigned char)hit[-1]) || xp25_is_digit((unsigned char)hit[-1]));
        int after = !(xp25_is_alpha((unsigned char)hit[n]) || xp25_is_digit((unsigned char)hit[n]));
        if (n <= 3 ? before && after : (!synonym || before)) return hit;
        ++hit;
    }
    return NULL;
}

/* 3 = file name, 2 = folder path, 1 = content words, 0 = no match. */
static int term_match(const ROVER_ENTRY *e, const char *term)
{
    const char *alts = NULL;
    size_t i;
    int best = 0;
    for (i = 0; synonyms[i].term; ++i) if (!strcmp(synonyms[i].term, term)) { alts = synonyms[i].alts; break; }
    if (!alts) alts = term;
    while (*alts && best < 3) {
        const char *comma = strchr(alts, ',');
        char word[40];
        size_t n = comma ? (size_t)(comma - alts) : strlen(alts);
        if (n && n < sizeof(word)) {
            int synonym;
            memcpy(word, alts, n);
            word[n] = 0;
            synonym = strcmp(word, term) != 0;
            if (find_word(e->path + e->name, word, n, NULL, synonym)) best = 3;
            else if (best < 2 && find_word(e->path, word, n, e->path + e->name, synonym)) best = 2;
            else if (best < 1 && rover_entry_has_word(e, word)) best = 1;
        }
        alts += n + (comma ? 1 : 0);
    }
    return best;
}

static const ROVER_CRITERIA *sort_criteria;

static int XP25_CDECL hit_compare(const void *a, const void *b)
{
    const ROVER_HIT *x = (const ROVER_HIT *)a, *y = (const ROVER_HIT *)b;
    const ROVER_ENTRY *p = x->entry, *q = y->entry;
    switch (sort_criteria->sort) {
    case ROVER_SORT_DATE_DESC: if (p->mtime != q->mtime) return p->mtime < q->mtime ? 1 : -1; break;
    case ROVER_SORT_DATE_ASC: if (p->mtime != q->mtime) return p->mtime < q->mtime ? -1 : 1; break;
    case ROVER_SORT_SIZE_DESC: if (p->size != q->size) return p->size < q->size ? 1 : -1; break;
    case ROVER_SORT_SIZE_ASC: if (p->size != q->size) return p->size < q->size ? -1 : 1; break;
    case ROVER_SORT_NAME: break;
    default:
        if (x->score != y->score) return x->score < y->score ? 1 : -1;
        if (p->mtime != q->mtime) return p->mtime < q->mtime ? 1 : -1;
    }
    return rover_path_compare(p->path + p->name, q->path + q->name) ? rover_path_compare(p->path + p->name, q->path + q->name)
                                                                    : rover_path_compare(p->path, q->path);
}

static size_t run(const ROVER_INDEX *index, const ROVER_CRITERIA *c, const char *scope, int require_terms,
                  ROVER_HIT *hits, size_t max_hits, size_t *total)
{
    size_t i, k, n = 0, scope_len = scope ? strlen(scope) : 0;
    char year[8];
    year[0] = 0;
    if (c->year) {
        year[0] = (char)('0' + c->year / 1000); year[1] = (char)('0' + (c->year / 100) % 10);
        year[2] = (char)('0' + (c->year / 10) % 10); year[3] = (char)('0' + c->year % 10); year[4] = 0;
    }
    *total = 0;
    for (i = 0; i < index->count; ++i) {
        const ROVER_ENTRY *e = &index->entries[i];
        int directory = (e->attrs & ROVER_ATTR_DIRECTORY) != 0;
        unsigned long when = c->created ? e->ctime : e->mtime;
        long score = 0;
        int content = 0, missing = 0;
        if (e->attrs & (ROVER_ATTR_HIDDEN | ROVER_ATTR_SYSTEM | 0x80000000UL)) continue;
        if (scope_len && !(xp25_strnieq(e->path, scope, scope_len) &&
                           (e->path[scope_len] == '\\' || scope[scope_len - 1] == '\\'))) continue;
        if (c->kind == ROVER_KIND_FOLDERS && !directory) continue;
        if (c->kind == ROVER_KIND_FILES && directory) continue;
        if (c->ext_count && (directory || !has_ext(c, e->path + e->name))) continue;
        if (c->after && when < c->after) continue;
        if (c->before && when >= c->before) continue;
        if (c->min_size && (directory || e->size < c->min_size)) continue;
        if (c->max_size && (directory || e->size > c->max_size)) continue;
        if (c->location[0]) {
            const char *hit = c->location[1] == ':' ? (xp25_strnieq(e->path, c->location, strlen(c->location)) ? e->path : NULL)
                                                    : xp25_stristr(e->path, c->location);
            if (!hit || hit >= e->path + e->name) continue;
        }
        if (c->year) {
            long y;
            unsigned m, d;
            rover_civil_from_days(local_day(when, c->bias), &y, &m, &d);
            if (y == c->year) score += 20;
            else if (xp25_stristr(e->path, year)) score += 15;
            else continue;
        }
        for (k = 0; k < c->term_count; ++k) {
            int how = term_match(e, c->terms[k]);
            if (!how) { ++missing; continue; }
            score += how == 3 ? 40 : how == 2 ? 30 : 10;
            if (how == 1) content = 1;
        }
        if (missing && require_terms) continue;
        /* People mostly look for their own files: prefer the profile, more so for "my ...". */
        if (c->home[0] && xp25_starts_with_i(e->path, c->home)) score += c->mine ? 20 : 8;
        if (c->term_count && missing == (int)c->term_count && !require_terms) score -= 5;
        if (!directory) score += 1;
        ++*total;
        if (n < max_hits) {
            hits[n].entry = e;
            hits[n].score = score;
            hits[n].content_match = content;
            ++n;
        } else {
            /* Keep the best max_hits by replacing the current worst. */
            size_t worst = 0;
            ROVER_HIT candidate;
            candidate.entry = e;
            candidate.score = score;
            candidate.content_match = content;
            sort_criteria = c;
            for (k = 1; k < n; ++k) if (hit_compare(&hits[k], &hits[worst]) > 0) worst = k;
            if (hit_compare(&candidate, &hits[worst]) < 0) hits[worst] = candidate;
        }
    }
    sort_criteria = c;
    qsort(hits, n, sizeof(ROVER_HIT), hit_compare);
    return n;
}

size_t rover_search(const ROVER_INDEX *index, const ROVER_CRITERIA *c, const char *scope,
                    ROVER_HIT *hits, size_t max_hits, size_t *total, int *relaxed)
{
    size_t n, limit = c->limit > 0 && (size_t)c->limit < max_hits ? (size_t)c->limit : max_hits;
    if (relaxed) *relaxed = 0;
    n = run(index, c, scope, c->terms_required, hits, limit, total);
    if (!*total && c->term_count && c->recognized && c->terms_required) {
        /* No file mentions the words: fall back to the structured criteria alone. */
        ROVER_CRITERIA loose = *c;
        loose.terms_required = 0;
        n = run(index, &loose, scope, 0, hits, limit, total);
        if (relaxed) *relaxed = 1;
    }
    return n;
}
