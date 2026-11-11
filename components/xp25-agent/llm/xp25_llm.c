/* XP25 AI runtime: Responses / Chat Completions codecs and gateway signing.
   Provider bodies are untrusted input; parsing is bounded and never executes
   anything. Tool calls are only returned to the agent loop, which applies
   the permission policy. Portable C89. */
#include <string.h>
#include "xp25_llm.h"
#include "xp25_sha256.h"

static void tools_json(XP25_JW *w, const XP25_REGISTRY *registry, XP25_API api)
{
    size_t i;
    xp25_jw_key(w, "tools");
    xp25_jw_arr(w);
    for (i = 0; i < registry->count; ++i) {
        const XP25_TOOL *tool = &registry->items[i];
        xp25_jw_obj(w);
        xp25_jw_key(w, "type"); xp25_jw_str(w, "function");
        if (api == XP25_API_CHAT) { xp25_jw_key(w, "function"); xp25_jw_obj(w); }
        xp25_jw_key(w, "name"); xp25_jw_str(w, tool->name);
        xp25_jw_key(w, "description"); xp25_jw_str(w, tool->description);
        xp25_jw_key(w, "parameters"); xp25_jw_raw(w, tool->parameters ? tool->parameters : "{\"type\":\"object\",\"properties\":{}}");
        if (api == XP25_API_CHAT) xp25_jw_end(w);
        xp25_jw_end(w);
    }
    xp25_jw_end(w);
}

static void responses_input(XP25_JW *w, const XP25_CONVERSATION *c, int remote)
{
    size_t i;
    xp25_jw_key(w, "input");
    xp25_jw_arr(w);
    for (i = 0; i < c->count; ++i) {
        const XP25_ITEM *item = &c->items[i];
        xp25_jw_obj(w);
        switch (item->kind) {
        case XP25_ITEM_USER:
        case XP25_ITEM_ASSISTANT:
            xp25_jw_key(w, "role"); xp25_jw_str(w, item->kind == XP25_ITEM_USER ? "user" : "assistant");
            xp25_jw_key(w, "content"); xp25_jw_str(w, item->text);
            break;
        case XP25_ITEM_CALL:
            xp25_jw_key(w, "type"); xp25_jw_str(w, "function_call");
            xp25_jw_key(w, "call_id"); xp25_jw_str(w, item->call_id);
            xp25_jw_key(w, "name"); xp25_jw_str(w, item->name);
            xp25_jw_key(w, "arguments"); xp25_jw_str(w, item->arguments ? item->arguments : "{}");
            break;
        case XP25_ITEM_RESULT:
            xp25_jw_key(w, "type"); xp25_jw_str(w, "function_call_output");
            xp25_jw_key(w, "call_id"); xp25_jw_str(w, item->call_id);
            xp25_jw_key(w, "output"); xp25_jw_str(w, xp25_item_output_for(item, remote));
            break;
        }
        xp25_jw_end(w);
    }
    xp25_jw_end(w);
}

static void chat_messages(XP25_JW *w, const XP25_CONVERSATION *c, const char *instructions, int remote)
{
    size_t i = 0;
    xp25_jw_key(w, "messages");
    xp25_jw_arr(w);
    if (instructions) {
        xp25_jw_obj(w);
        xp25_jw_key(w, "role"); xp25_jw_str(w, "system");
        xp25_jw_key(w, "content"); xp25_jw_str(w, instructions);
        xp25_jw_end(w);
    }
    while (i < c->count) {
        const XP25_ITEM *item = &c->items[i];
        if (item->kind == XP25_ITEM_USER) {
            xp25_jw_obj(w);
            xp25_jw_key(w, "role"); xp25_jw_str(w, "user");
            xp25_jw_key(w, "content"); xp25_jw_str(w, item->text);
            xp25_jw_end(w);
            ++i;
        } else if (item->kind == XP25_ITEM_RESULT) {
            xp25_jw_obj(w);
            xp25_jw_key(w, "role"); xp25_jw_str(w, "tool");
            xp25_jw_key(w, "tool_call_id"); xp25_jw_str(w, item->call_id);
            xp25_jw_key(w, "content"); xp25_jw_str(w, xp25_item_output_for(item, remote));
            xp25_jw_end(w);
            ++i;
        } else {
            /* One assistant message carries optional text plus consecutive calls. */
            xp25_jw_obj(w);
            xp25_jw_key(w, "role"); xp25_jw_str(w, "assistant");
            xp25_jw_key(w, "content");
            if (item->kind == XP25_ITEM_ASSISTANT) { xp25_jw_str(w, item->text); ++i; }
            else xp25_jw_null(w);
            if (i < c->count && c->items[i].kind == XP25_ITEM_CALL) {
                xp25_jw_key(w, "tool_calls");
                xp25_jw_arr(w);
                while (i < c->count && c->items[i].kind == XP25_ITEM_CALL) {
                    xp25_jw_obj(w);
                    xp25_jw_key(w, "id"); xp25_jw_str(w, c->items[i].call_id);
                    xp25_jw_key(w, "type"); xp25_jw_str(w, "function");
                    xp25_jw_key(w, "function");
                    xp25_jw_obj(w);
                    xp25_jw_key(w, "name"); xp25_jw_str(w, c->items[i].name);
                    xp25_jw_key(w, "arguments"); xp25_jw_str(w, c->items[i].arguments ? c->items[i].arguments : "{}");
                    xp25_jw_end(w);
                    xp25_jw_end(w);
                    ++i;
                }
                xp25_jw_end(w);
            }
            xp25_jw_end(w);
        }
    }
    xp25_jw_end(w);
}

int xp25_llm_build_request(XP25_API api, const char *model, const XP25_CONVERSATION *conversation,
                           const XP25_REGISTRY *registry, const char *instructions, int remote,
                           long max_output_tokens, XP25_BUF *out)
{
    XP25_JW w;
    xp25_buf_reset(out);
    xp25_jw_init(&w, out);
    xp25_jw_obj(&w);
    xp25_jw_key(&w, "model"); xp25_jw_str(&w, model && *model ? model : "gpt-4.1-mini");
    if (api == XP25_API_RESPONSES) {
        if (instructions) { xp25_jw_key(&w, "instructions"); xp25_jw_str(&w, instructions); }
        xp25_jw_key(&w, "store"); xp25_jw_bool(&w, 0);
        responses_input(&w, conversation, remote);
        if (max_output_tokens > 0) { xp25_jw_key(&w, "max_output_tokens"); xp25_jw_i64(&w, max_output_tokens); }
    } else {
        chat_messages(&w, conversation, instructions, remote);
        if (max_output_tokens > 0) { xp25_jw_key(&w, "max_tokens"); xp25_jw_i64(&w, max_output_tokens); }
    }
    if (registry && registry->count) {
        tools_json(&w, registry, api);
        xp25_jw_key(&w, "tool_choice"); xp25_jw_str(&w, "auto");
        xp25_jw_key(&w, "parallel_tool_calls"); xp25_jw_bool(&w, 0);
    }
    xp25_jw_end(&w);
    return xp25_jw_ok(&w);
}

int xp25_llm_build_simple(XP25_API api, const char *model, const char *instructions,
                          const char *user_text, XP25_BUF *out)
{
    XP25_CONVERSATION c;
    int ok;
    xp25_conversation_init(&c);
    ok = xp25_conversation_add(&c, XP25_ITEM_USER, user_text) != NULL &&
         xp25_llm_build_request(api, model, &c, NULL, instructions, 1, 600, out);
    xp25_conversation_free(&c);
    return ok;
}

static void add_text(XP25_BUF *text, const char *s, size_t n)
{
    if (text->len) xp25_buf_puts(text, "\n");
    xp25_buf_append(text, s, n);
}

static int add_call(XP25_REPLY *reply, const char *id, const char *name, const XP25_JNODE *arguments)
{
    XP25_CALL *call;
    if (!name || !*name) return 0;
    if (reply->call_count >= XP25_MAX_CALLS) return 1;   /* extra calls are ignored, not executed */
    call = &reply->calls[reply->call_count++];
    call->call_id = xp25_strdup(id ? id : "");
    call->name = xp25_strdup(name);
    if (arguments && arguments->type == XP25_JSTR) call->arguments = xp25_strdup(arguments->str);
    else if (arguments && arguments->type == XP25_JOBJ) {
        XP25_BUF b;
        xp25_buf_init(&b);
        xp25_json_write(&b, arguments);
        call->arguments = xp25_buf_detach(&b);
    } else call->arguments = xp25_strdup("{}");
    return call->call_id && call->name && call->arguments;
}

static int provider_error(const XP25_JNODE *root, int http_status, XP25_REPLY *reply)
{
    const XP25_JNODE *error = xp25_json_get(root, "error");
    const char *message, *code, *type;
    int retryable = http_status == 429 || http_status >= 500;
    if (!error || error->type == XP25_JNULL) {
        if (http_status >= 200 && http_status < 300) return 0;
        xp25_reply_error(reply, http_status == 401 || http_status == 403 ? "provider_unauthorized" : "provider_http_error",
                         "The AI provider returned an unexpected HTTP status.", retryable);
        reply->http_status = http_status;
        return 1;
    }
    message = error->type == XP25_JSTR ? error->str : xp25_json_string(error, "message");
    code = xp25_json_string(error, "code");
    type = xp25_json_string(error, "type");
    xp25_reply_error(reply, code ? code : (type ? type : "provider_error"),
                     message ? message : "The AI provider reported an error.", retryable);
    reply->http_status = http_status;
    return 1;
}

static int parse_responses(const XP25_JNODE *root, XP25_REPLY *reply)
{
    const XP25_JNODE *output = xp25_json_get(root, "output"), *item;
    const char *status = xp25_json_string(root, "status");
    XP25_BUF text;
    if (!output || output->type != XP25_JARR) {
        xp25_reply_error(reply, "malformed_response", "The response has no output array.", 0);
        return 0;
    }
    xp25_buf_init(&text);
    for (item = output->child; item; item = item->next) {
        const char *type = xp25_json_string(item, "type");
        if (!type) continue;
        if (!strcmp(type, "message")) {
            const XP25_JNODE *content = xp25_json_get(item, "content"), *part;
            if (content && content->type == XP25_JSTR) add_text(&text, content->str, content->len);
            else if (content && content->type == XP25_JARR)
                for (part = content->child; part; part = part->next) {
                    const char *ptype = xp25_json_string(part, "type");
                    const XP25_JNODE *value = xp25_json_get(part, ptype && !strcmp(ptype, "refusal") ? "refusal" : "text");
                    if (ptype && (!strcmp(ptype, "output_text") || !strcmp(ptype, "refusal")) &&
                        value && value->type == XP25_JSTR)
                        add_text(&text, value->str, value->len);
                }
        } else if (!strcmp(type, "function_call")) {
            if (!add_call(reply, xp25_json_string(item, "call_id"), xp25_json_string(item, "name"),
                          xp25_json_get(item, "arguments"))) {
                xp25_buf_free(&text);
                xp25_reply_error(reply, "malformed_tool_call", "A tool call in the response is malformed.", 0);
                return 0;
            }
        }
    }
    if (!reply->call_count && !text.len && status && !strcmp(status, "incomplete")) {
        xp25_buf_free(&text);
        xp25_reply_error(reply, "response_incomplete", "The model stopped before producing an answer.", 1);
        return 0;
    }
    if (text.len) reply->text = xp25_buf_detach(&text);
    else xp25_buf_free(&text);
    return 1;
}

static int parse_chat(const XP25_JNODE *root, XP25_REPLY *reply)
{
    const XP25_JNODE *message = xp25_json_get(xp25_json_at(xp25_json_get(root, "choices"), 0), "message");
    const XP25_JNODE *content, *calls, *call;
    if (!message || message->type != XP25_JOBJ) {
        xp25_reply_error(reply, "malformed_response", "The response has no message.", 0);
        return 0;
    }
    content = xp25_json_get(message, "content");
    if (content && content->type == XP25_JSTR && content->len) reply->text = xp25_strdup(content->str);
    calls = xp25_json_get(message, "tool_calls");
    if (calls && calls->type == XP25_JARR)
        for (call = calls->child; call; call = call->next) {
            const XP25_JNODE *function = xp25_json_get(call, "function");
            if (!add_call(reply, xp25_json_string(call, "id"), xp25_json_string(function, "name"),
                          xp25_json_get(function, "arguments"))) {
                xp25_reply_error(reply, "malformed_tool_call", "A tool call in the response is malformed.", 0);
                return 0;
            }
        }
    return 1;
}

int xp25_llm_parse_response(XP25_API api, const char *body, size_t len, int http_status, XP25_REPLY *reply)
{
    XP25_JDOC doc;
    int ok;
    if (!body || !len) {
        xp25_reply_error(reply, http_status ? "provider_http_error" : "empty_response",
                         "The AI provider returned no body.", http_status == 429 || http_status >= 500);
        reply->http_status = http_status;
        return 0;
    }
    if (!xp25_json_parse(&doc, body, len) || doc.root->type != XP25_JOBJ) {
        xp25_reply_error(reply, "malformed_response", "The AI provider returned invalid JSON.", http_status >= 500);
        reply->http_status = http_status;
        xp25_json_free(&doc);
        return 0;
    }
    if (provider_error(doc.root, http_status, reply)) { xp25_json_free(&doc); return 0; }
    ok = api == XP25_API_RESPONSES ? parse_responses(doc.root, reply) : parse_chat(doc.root, reply);
    reply->http_status = http_status;
    xp25_json_free(&doc);
    return ok;
}

void xp25_gateway_sign(const unsigned char *secret, size_t secret_len, const char *method,
                       const char *path, const char *challenge, const char *nonce,
                       const char *body, size_t body_len, char signature[65], char body_sha256[65])
{
    unsigned char digest[32], mac[32];
    XP25_BUF message, hex;
    xp25_sha256(body ? body : "", body_len, digest);
    xp25_buf_init(&hex);
    xp25_buf_hex(&hex, digest, 32);
    memcpy(body_sha256, xp25_buf_cstr(&hex), 64);
    body_sha256[64] = 0;
    xp25_buf_init(&message);
    xp25_buf_puts(&message, XP25_GATEWAY_REQUEST_LABEL "\n");
    xp25_buf_puts(&message, method); xp25_buf_putc(&message, '\n');
    xp25_buf_puts(&message, path); xp25_buf_putc(&message, '\n');
    xp25_buf_puts(&message, challenge); xp25_buf_putc(&message, '\n');
    xp25_buf_puts(&message, nonce); xp25_buf_putc(&message, '\n');
    xp25_buf_puts(&message, body_sha256);
    xp25_hmac_sha256(secret, secret_len, xp25_buf_cstr(&message), message.len, mac);
    xp25_buf_reset(&hex);
    xp25_buf_hex(&hex, mac, 32);
    memcpy(signature, xp25_buf_cstr(&hex), 64);
    signature[64] = 0;
    xp25_buf_free(&message);
    xp25_buf_free(&hex);
}

int xp25_gateway_verify(const unsigned char *secret, size_t secret_len, const char *nonce, int status,
                        const char *body, size_t body_len, const char *signature)
{
    unsigned char digest[32], mac[32], given[32];
    XP25_BUF message;
    int ok;
    if (!signature || strlen(signature) != 64 || xp25_hex_decode(signature, given, 32) != 32) return 0;
    xp25_sha256(body ? body : "", body_len, digest);
    xp25_buf_init(&message);
    xp25_buf_puts(&message, XP25_GATEWAY_RESPONSE_LABEL "\n");
    xp25_buf_puts(&message, nonce); xp25_buf_putc(&message, '\n');
    xp25_buf_i64(&message, status); xp25_buf_putc(&message, '\n');
    xp25_buf_hex(&message, digest, 32);
    xp25_hmac_sha256(secret, secret_len, xp25_buf_cstr(&message), message.len, mac);
    ok = xp25_buf_ok(&message) && xp25_mem_equal_ct(mac, given, 32);
    xp25_buf_free(&message);
    return ok;
}
