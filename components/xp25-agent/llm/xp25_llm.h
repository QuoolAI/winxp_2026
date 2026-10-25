/* XP25 AI runtime: provider wire formats and gateway authentication. Portable C89. */
#ifndef XP25_LLM_H
#define XP25_LLM_H
#include "../runtime/xp25_agent.h"

typedef enum {
    XP25_API_RESPONSES,   /* OpenAI Responses API: POST /v1/responses */
    XP25_API_CHAT         /* OpenAI-compatible Chat Completions (local servers) */
} XP25_API;

/* Build a stateless request (store=false): the whole conversation is sent.
   With remote set, withheld results are replaced by placeholders. */
int xp25_llm_build_request(XP25_API api, const char *model, const XP25_CONVERSATION *conversation,
                           const XP25_REGISTRY *registry, const char *instructions, int remote,
                           long max_output_tokens, XP25_BUF *out);
/* Single question, no tools: used for RoverAI structured query interpretation. */
int xp25_llm_build_simple(XP25_API api, const char *model, const char *instructions,
                          const char *user_text, XP25_BUF *out);
/* Parse a provider response into text and tool calls, or a structured error. */
int xp25_llm_parse_response(XP25_API api, const char *body, size_t len, int http_status, XP25_REPLY *reply);

/* Companion gateway: HMAC-SHA256 over a server challenge, a client nonce and
   the body digest. The gateway signs its response with the same secret. */
#define XP25_GATEWAY_REQUEST_LABEL "XP25-GW1"
#define XP25_GATEWAY_RESPONSE_LABEL "XP25-GW1-RESPONSE"
void xp25_gateway_sign(const unsigned char *secret, size_t secret_len, const char *method,
                       const char *path, const char *challenge, const char *nonce,
                       const char *body, size_t body_len, char signature[65], char body_sha256[65]);
int xp25_gateway_verify(const unsigned char *secret, size_t secret_len, const char *nonce, int status,
                        const char *body, size_t body_len, const char *signature);
#endif
