/* XP25 AI runtime: file_search, RoverAI's grounded local search as a shared tool. */
#include <windows.h>
#include "win_tools.h"
#include "../../roverai/indexer/rover_win.h"

int tool_file_search(const XP25_TOOL *tool, const XP25_JNODE *args, XP25_BUF *out, XP25_EGRESS *egress)
{
    XP25W_TOOLS *ctx = TOOL_CONTEXT(tool);
    const char *query = tool_arg(args, "query", ""), *scope = tool_arg(args, "scope", NULL);
    long limit = tool_int(args, "limit", 20, 1, 200);
    ROVER_SETTINGS settings;
    ROVER_RESULTS results;
    int ok;
    (void)egress;
    if (!*query) { xp25_result_error(out, "bad_arguments", "Describe the files to find."); return 0; }
    if (!rover_settings_init(&settings, ctx->config, ctx->paths)) {
        xp25_result_error(out, "no_locations", "No indexed locations are configured.");
        return 0;
    }
    /* Only the query text may go to the configured provider, never file content. */
    ok = rover_query_run(query, scope, (int)limit, ctx->config->ai_query_interpretation ? ROVER_AI_AUTO : ROVER_AI_NEVER,
                         ctx->provider, &settings, &results);
    if (ok) rover_results_json(&results, query, out);
    else xp25_result_error(out, "search_failed", results.note[0] ? results.note : "The search could not run.");
    rover_results_free(&results);
    rover_settings_free(&settings);
    return ok;
}
