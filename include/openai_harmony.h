#ifndef OPENAI_HARMONY_H
#define OPENAI_HARMONY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Opaque handle owning a Rust HarmonyEncoding instance. */
typedef struct HarmonyEncodingHandle HarmonyEncodingHandle;

/** Opaque handle owning a Rust StreamableParser instance. */
typedef struct HarmonyStreamableParserHandle HarmonyStreamableParserHandle;

/** Error/return codes used by the Harmony C bindings. */
typedef enum HarmonyStatus {
    HARMONY_STATUS_OK = 0,
    HARMONY_STATUS_NULL_POINTER = 1,
    HARMONY_STATUS_INVALID_UTF8 = 2,
    HARMONY_STATUS_INVALID_ARGUMENT = 3,
    HARMONY_STATUS_JSON_ERROR = 4,
    HARMONY_STATUS_PANIC = 5,
    HARMONY_STATUS_INTERNAL_ERROR = 6,
} HarmonyStatus;

/** Optional configuration for rendering entire conversations. */
typedef struct HarmonyRenderConversationConfig {
    bool auto_drop_analysis;
} HarmonyRenderConversationConfig;

/** Optional configuration for rendering individual messages. */
typedef struct HarmonyRenderOptions {
    bool conversation_has_function_tools;
} HarmonyRenderOptions;

/** Heap-allocated array of 32-bit tokens owned by Rust. */
typedef struct HarmonyOwnedU32Array {
    uint32_t *data;
    size_t len;
} HarmonyOwnedU32Array;

/** Heap-allocated array of bytes owned by Rust. */
typedef struct HarmonyOwnedU8Array {
    uint8_t *data;
    size_t len;
} HarmonyOwnedU8Array;

/** Heap-allocated array of C strings owned by Rust. */
typedef struct HarmonyStringArray {
    char **data;
    size_t len;
} HarmonyStringArray;

/** C representation of a message with textual contents only. */
typedef struct HarmonyMessage {
    const char *role;          /** required: "system", "developer", "user", "assistant", or tool role */
    const char *name;          /** optional: tool name when role==tool */
    const char *recipient;     /** optional: e.g., "assistant" or "functions.get_weather" */
    const char *channel;       /** optional: "analysis", "commentary", "final" */
    const char *content_type;  /** optional */
    HarmonyStringArray contents; /** array of UTF-8 strings; each becomes a text content block */
} HarmonyMessage;

typedef struct HarmonyMessageArray {
    HarmonyMessage *data;
    size_t len;
} HarmonyMessageArray;

HarmonyStatus harmony_encoding_new(const char *name, HarmonyEncodingHandle **out_encoding, char **out_error);
void harmony_encoding_free(HarmonyEncodingHandle *handle);
HarmonyStatus harmony_encoding_name(const HarmonyEncodingHandle *encoding, char **out_name, char **out_error);
HarmonyStatus harmony_encoding_render_conversation_for_completion(
    const HarmonyEncodingHandle *encoding,
    const char *conversation_json,
    const char *next_turn_role,
    const HarmonyRenderConversationConfig *config,
    HarmonyOwnedU32Array *out_tokens,
    char **out_error);

/** Optional completion options for extended rendering. */
typedef struct HarmonyCompletionOptions {
    /** When true, the parser should prefer emitting only 'final' channel deltas. */
    bool final_only_deltas;
    /** When true, the parser should ignore premature stops until a final/tool event occurred. */
    bool guarded_stop;
    /** When true, pre-fill the next assistant header with channel=final before sampling. */
    bool force_next_channel_final;
    /** Optional JSON-encoded tool registry (names + JSON schema). */
    const char *tools_json;
} HarmonyCompletionOptions;

/** Extended variant that accepts additional completion options. */
HarmonyStatus harmony_encoding_render_conversation_for_completion_ex(
    const HarmonyEncodingHandle *encoding,
    const char *conversation_json,
    const char *next_turn_role,
    const HarmonyRenderConversationConfig *config,
    const HarmonyCompletionOptions *options,
    HarmonyOwnedU32Array *out_tokens,
    char **out_error);
HarmonyStatus harmony_encoding_render_conversation(
    const HarmonyEncodingHandle *encoding,
    const char *conversation_json,
    const HarmonyRenderConversationConfig *config,
    HarmonyOwnedU32Array *out_tokens,
    char **out_error);
HarmonyStatus harmony_encoding_render_conversation_for_training(
    const HarmonyEncodingHandle *encoding,
    const char *conversation_json,
    const HarmonyRenderConversationConfig *config,
    HarmonyOwnedU32Array *out_tokens,
    char **out_error);
HarmonyStatus harmony_encoding_render(
    const HarmonyEncodingHandle *encoding,
    const char *message_json,
    const HarmonyRenderOptions *options,
    HarmonyOwnedU32Array *out_tokens,
    char **out_error);

/** Convenience: render a system + user conversation without JSON. */
HarmonyStatus harmony_encoding_render_system_and_user_for_completion_ex(
    const HarmonyEncodingHandle *encoding,
    const char *system_text,                 /** optional, may be NULL */
    const HarmonyStringArray *user_parts,    /** array of UTF-8 strings */
    const char *next_turn_role,              /** e.g., "assistant" */
    const HarmonyRenderConversationConfig *config,
    const HarmonyCompletionOptions *options,
    HarmonyOwnedU32Array *out_tokens,
    char **out_error);

/** Convenience: render a single tool message (role=tool, to=assistant, channel=commentary). */
HarmonyStatus harmony_encoding_render_tool_message(
    const HarmonyEncodingHandle *encoding,
    const char *tool_name,
    const char *output_text,
    HarmonyOwnedU32Array *out_tokens,
    char **out_error);

/** Render a conversation from an array of messages (text-only contents) and append next turn role. */
HarmonyStatus harmony_encoding_render_conversation_from_messages_ex(
    const HarmonyEncodingHandle *encoding,
    const HarmonyMessageArray *messages,
    const char *next_turn_role,
    const HarmonyRenderConversationConfig *config,
    const HarmonyCompletionOptions *options,
    HarmonyOwnedU32Array *out_tokens,
    char **out_error);
HarmonyStatus harmony_encoding_parse_messages_from_completion_tokens(
    const HarmonyEncodingHandle *encoding,
    const uint32_t *tokens,
    size_t tokens_len,
    const char *role,
    char **out_json,
    char **out_error);
HarmonyStatus harmony_encoding_decode_utf8(
    const HarmonyEncodingHandle *encoding,
    const uint32_t *tokens,
    size_t tokens_len,
    char **out_string,
    char **out_error);
HarmonyStatus harmony_encoding_decode_bytes(
    const HarmonyEncodingHandle *encoding,
    const uint32_t *tokens,
    size_t tokens_len,
    HarmonyOwnedU8Array *out_bytes,
    char **out_error);
HarmonyStatus harmony_encoding_encode(
    const HarmonyEncodingHandle *encoding,
    const char *text,
    const char *const *allowed_special,
    size_t allowed_special_len,
    HarmonyOwnedU32Array *out_tokens,
    char **out_error);
HarmonyStatus harmony_encoding_special_tokens(
    const HarmonyEncodingHandle *encoding,
    HarmonyStringArray *out_tokens,
    char **out_error);
HarmonyStatus harmony_encoding_is_special_token(
    const HarmonyEncodingHandle *encoding,
    uint32_t token,
    bool *out_is_special,
    char **out_error);
HarmonyStatus harmony_encoding_stop_tokens(
    const HarmonyEncodingHandle *encoding,
    HarmonyOwnedU32Array *out_tokens,
    char **out_error);
HarmonyStatus harmony_encoding_stop_tokens_for_assistant_actions(
    const HarmonyEncodingHandle *encoding,
    HarmonyOwnedU32Array *out_tokens,
    char **out_error);
HarmonyStatus harmony_get_tool_namespace_config(const char *tool, char **out_json, char **out_error);

HarmonyStatus harmony_streamable_parser_new(
    const HarmonyEncodingHandle *encoding,
    const char *role,
    HarmonyStreamableParserHandle **out_parser,
    char **out_error);
void harmony_streamable_parser_free(HarmonyStreamableParserHandle *parser);
HarmonyStatus harmony_streamable_parser_process(HarmonyStreamableParserHandle *parser, uint32_t token, char **out_error);
HarmonyStatus harmony_streamable_parser_process_eos(HarmonyStreamableParserHandle *parser, char **out_error);
HarmonyStatus harmony_streamable_parser_current_content(
    const HarmonyStreamableParserHandle *parser,
    char **out_string,
    char **out_error);
HarmonyStatus harmony_streamable_parser_current_role(
    const HarmonyStreamableParserHandle *parser,
    char **out_role,
    char **out_error);
HarmonyStatus harmony_streamable_parser_current_content_type(
    const HarmonyStreamableParserHandle *parser,
    char **out_content_type,
    char **out_error);
HarmonyStatus harmony_streamable_parser_last_content_delta(
    const HarmonyStreamableParserHandle *parser,
    char **out_delta,
    char **out_error);
HarmonyStatus harmony_streamable_parser_messages(
    const HarmonyStreamableParserHandle *parser,
    char **out_json,
    char **out_error);
HarmonyStatus harmony_streamable_parser_tokens(
    const HarmonyStreamableParserHandle *parser,
    HarmonyOwnedU32Array *out_tokens,
    char **out_error);
HarmonyStatus harmony_streamable_parser_state(
    const HarmonyStreamableParserHandle *parser,
    char **out_state,
    char **out_error);
HarmonyStatus harmony_streamable_parser_current_recipient(
    const HarmonyStreamableParserHandle *parser,
    char **out_recipient,
    char **out_error);
HarmonyStatus harmony_streamable_parser_current_channel(
    const HarmonyStreamableParserHandle *parser,
    char **out_channel,
    char **out_error);

/**
 * Stream event kinds emitted by the parser.
 *
 * NONE indicates no event is currently available.
 */
typedef enum HarmonyStreamEventKind {
    HARMONY_STREAM_EVENT_NONE = 0,
    HARMONY_STREAM_EVENT_CONTENT_DELTA = 1,
    HARMONY_STREAM_EVENT_TOOL_CALL_BEGIN = 2,
    HARMONY_STREAM_EVENT_TOOL_ARGS_DELTA = 3,
    HARMONY_STREAM_EVENT_TOOL_ARGS_DONE = 4,
    HARMONY_STREAM_EVENT_STOP = 5,
} HarmonyStreamEventKind;

/** Owned stream event with heap-allocated strings to be freed by harmony_stream_event_free. */
typedef struct HarmonyStreamEvent {
    int kind;          /** HarmonyStreamEventKind */
    char *channel;     /** optional */
    char *recipient;   /** optional */
    char *name;        /** optional tool name */
    char *call_id;     /** optional tool call id */
    char *text;        /** content delta text (for CONTENT_DELTA) */
    char *json;        /** JSON delta (for TOOL_ARGS_DELTA) */
} HarmonyStreamEvent;

/** Pull the next available event from the parser (or NONE if none available). */
HarmonyStatus harmony_streamable_parser_next_event(
    HarmonyStreamableParserHandle *parser,
    HarmonyStreamEvent *out_event,
    char **out_error);

/** Prime the parser for the next assistant turn with channel=final so that
 *  subsequent tokens are parsed as final content. */
HarmonyStatus harmony_streamable_parser_prime_assistant_final(
    HarmonyStreamableParserHandle *parser,
    char **out_error);

/** Free any heap-allocated fields inside the event structure. */
void harmony_stream_event_free(HarmonyStreamEvent *ev);

void harmony_string_free(char *ptr);
void harmony_owned_u32_array_free(HarmonyOwnedU32Array array);
void harmony_owned_u8_array_free(HarmonyOwnedU8Array array);
void harmony_string_array_free(HarmonyStringArray array);

#ifdef __cplusplus
}
#endif

#endif /* OPENAI_HARMONY_H */
