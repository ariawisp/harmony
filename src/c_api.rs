//! C-compatible bindings for the harmony crate.
//!
//! The C API intentionally mirrors the low-level surface exposed via the
//! Python bindings.  Complex data-structures are exchanged as JSON strings in
//! order to keep the ABI small and stable.  Callers are responsible for
//! releasing all heap-allocated values returned from the API via the respective
//! `harmony_*_free` helpers provided in this module.

use crate::{
    chat::{Conversation, DeveloperContent, Message, Role, SystemContent, ToolDescription, ToolNamespaceConfig},
    encoding::{HarmonyEncoding, RenderConversationConfig, RenderOptions, StreamableParser, FormattingToken},
    load_harmony_encoding, HarmonyEncodingName,
};

use std::{
    collections::HashSet,
    ffi::{CStr, CString},
    os::raw::c_char,
    panic::AssertUnwindSafe,
    ptr,
};

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HarmonyStatus {
    Ok = 0,
    NullPointer = 1,
    InvalidUtf8 = 2,
    InvalidArgument = 3,
    JsonError = 4,
    Panic = 5,
    InternalError = 6,
}

struct FfiError {
    status: HarmonyStatus,
    message: String,
}

type FfiResult<T> = Result<T, FfiError>;

impl FfiError {
    fn new(status: HarmonyStatus, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

impl From<anyhow::Error> for FfiError {
    fn from(err: anyhow::Error) -> Self {
        if err.downcast_ref::<serde_json::Error>().is_some() {
            FfiError::new(HarmonyStatus::JsonError, err.to_string())
        } else {
            FfiError::new(HarmonyStatus::InternalError, err.to_string())
        }
    }
}

impl From<serde_json::Error> for FfiError {
    fn from(err: serde_json::Error) -> Self {
        FfiError::new(HarmonyStatus::JsonError, err.to_string())
    }
}

fn sanitize_cstring(message: String) -> CString {
    let sanitized = message.replace('\0', "\\0");
    CString::new(sanitized)
        .unwrap_or_else(|_| CString::new("(error message contains NUL)").unwrap())
}

fn store_error(out_error: *mut *mut c_char, message: Option<String>) {
    if out_error.is_null() {
        return;
    }
    unsafe {
        *out_error = match message {
            Some(msg) => sanitize_cstring(msg).into_raw(),
            None => ptr::null_mut(),
        };
    }
}

fn catch_unwind_result<F>(out_error: *mut *mut c_char, f: F) -> HarmonyStatus
where
    F: FnOnce() -> FfiResult<()>,
{
    match std::panic::catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => {
            store_error(out_error, None);
            HarmonyStatus::Ok
        }
        Ok(Err(err)) => {
            store_error(out_error, Some(err.message));
            err.status
        }
        Err(_) => {
            store_error(out_error, Some("Rust panic".to_string()));
            HarmonyStatus::Panic
        }
    }
}

fn ensure_out_ptr<T>(ptr: *mut T, name: &str) -> FfiResult<()> {
    if ptr.is_null() {
        Err(FfiError::new(
            HarmonyStatus::NullPointer,
            format!("output pointer `{name}` was NULL"),
        ))
    } else {
        Ok(())
    }
}

fn string_argument(ptr: *const c_char, name: &str) -> FfiResult<String> {
    if ptr.is_null() {
        return Err(FfiError::new(
            HarmonyStatus::NullPointer,
            format!("argument `{name}` was NULL"),
        ));
    }
    let c_str = unsafe { CStr::from_ptr(ptr) };
    let s = c_str.to_str().map_err(|e| {
        FfiError::new(
            HarmonyStatus::InvalidUtf8,
            format!("argument `{name}` was not valid UTF-8: {e}"),
        )
    })?;
    Ok(s.to_string())
}

fn optional_string_argument(ptr: *const c_char, name: &str) -> FfiResult<Option<String>> {
    if ptr.is_null() {
        Ok(None)
    } else {
        string_argument(ptr, name).map(Some)
    }
}

fn tokens_from_raw(ptr: *const u32, len: usize, name: &str) -> FfiResult<Vec<u32>> {
    if len == 0 {
        return Ok(Vec::new());
    }
    if ptr.is_null() {
        return Err(FfiError::new(
            HarmonyStatus::NullPointer,
            format!("argument `{name}` was NULL"),
        ));
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    Ok(slice.to_vec())
}

fn to_owned_c_string(value: impl Into<String>) -> *mut c_char {
    sanitize_cstring(value.into()).into_raw()
}

fn vec_to_u32_array(data: Vec<u32>) -> HarmonyOwnedU32Array {
    let len = data.len();
    let ptr = if len == 0 {
        ptr::null_mut()
    } else {
        Box::into_raw(data.into_boxed_slice()) as *mut u32
    };
    HarmonyOwnedU32Array { data: ptr, len }
}

fn vec_to_u8_array(data: Vec<u8>) -> HarmonyOwnedU8Array {
    let len = data.len();
    let ptr = if len == 0 {
        ptr::null_mut()
    } else {
        Box::into_raw(data.into_boxed_slice()) as *mut u8
    };
    HarmonyOwnedU8Array { data: ptr, len }
}

fn vec_to_string_array(values: Vec<String>) -> HarmonyStringArray {
    let len = values.len();
    if len == 0 {
        return HarmonyStringArray {
            data: ptr::null_mut(),
            len: 0,
        };
    }
    let mut raw_values: Vec<*mut c_char> = Vec::with_capacity(len);
    for value in values {
        raw_values.push(to_owned_c_string(value));
    }
    let ptr = Box::into_raw(raw_values.into_boxed_slice()) as *mut *mut c_char;
    HarmonyStringArray { data: ptr, len }
}

fn encoding_from_ptr<'a>(
    ptr: *const HarmonyEncodingHandle,
) -> FfiResult<&'a HarmonyEncodingHandle> {
    unsafe {
        ptr.as_ref().ok_or_else(|| {
            FfiError::new(
                HarmonyStatus::NullPointer,
                "encoding handle was NULL".to_string(),
            )
        })
    }
}

fn parser_from_ptr<'a>(
    ptr: *const HarmonyStreamableParserHandle,
) -> FfiResult<&'a HarmonyStreamableParserHandle> {
    unsafe {
        ptr.as_ref().ok_or_else(|| {
            FfiError::new(
                HarmonyStatus::NullPointer,
                "parser handle was NULL".to_string(),
            )
        })
    }
}

fn parser_from_ptr_mut<'a>(
    ptr: *mut HarmonyStreamableParserHandle,
) -> FfiResult<&'a mut HarmonyStreamableParserHandle> {
    unsafe {
        ptr.as_mut().ok_or_else(|| {
            FfiError::new(
                HarmonyStatus::NullPointer,
                "parser handle was NULL".to_string(),
            )
        })
    }
}

#[repr(C)]
pub struct HarmonyEncodingHandle {
    inner: HarmonyEncoding,
}

#[repr(C)]
pub struct HarmonyStreamableParserHandle {
    inner: StreamableParser,
    // State for event generation
    last_recipient: Option<String>,
    last_messages_len: usize,
    pending_tool_args_done: Option<String>,
    pending_stop: bool,
    // Tool call tracking
    call_seq: u64,
    current_call_id: Option<String>,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct HarmonyRenderConversationConfig {
    pub auto_drop_analysis: bool,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct HarmonyRenderOptions {
    pub conversation_has_function_tools: bool,
}

#[repr(C)]
pub struct HarmonyOwnedU32Array {
    pub data: *mut u32,
    pub len: usize,
}

#[repr(C)]
pub struct HarmonyMessageC {
    pub role: *const c_char,
    pub name: *const c_char,
    pub recipient: *const c_char,
    pub channel: *const c_char,
    pub content_type: *const c_char,
    pub contents: HarmonyStringArray,
}

#[repr(C)]
pub struct HarmonyMessageArrayC {
    pub data: *mut HarmonyMessageC,
    pub len: usize,
}

#[repr(C)]
pub struct HarmonyOwnedU8Array {
    pub data: *mut u8,
    pub len: usize,
}

#[repr(C)]
pub struct HarmonyStringArray {
    pub data: *mut *mut c_char,
    pub len: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub enum HarmonyStreamEventKind {
    None = 0,
    ContentDelta = 1,
    ToolCallBegin = 2,
    ToolArgsDelta = 3,
    ToolArgsDone = 4,
    Stop = 5,
}

#[repr(C)]
pub struct HarmonyStreamEvent {
    pub kind: i32,
    pub channel: *mut c_char,
    pub recipient: *mut c_char,
    pub name: *mut c_char,
    pub call_id: *mut c_char,
    pub text: *mut c_char,
    pub json: *mut c_char,
}

#[no_mangle]
pub extern "C" fn harmony_encoding_new(
    name: *const c_char,
    out_encoding: *mut *mut HarmonyEncodingHandle,
    out_error: *mut *mut c_char,
) -> HarmonyStatus {
    if let Err(err) = ensure_out_ptr(out_encoding, "out_encoding") {
        store_error(out_error, Some(err.message));
        return err.status;
    }
    unsafe {
        *out_encoding = ptr::null_mut();
    }

    catch_unwind_result(out_error, || {
        let name_str = string_argument(name, "name")?;
        let parsed_name = name_str
            .parse::<HarmonyEncodingName>()
            .map_err(|e| FfiError::new(HarmonyStatus::InvalidArgument, e.to_string()))?;
        let encoding = load_harmony_encoding(parsed_name)?;
        let handle = HarmonyEncodingHandle { inner: encoding };
        unsafe {
            *out_encoding = Box::into_raw(Box::new(handle));
        }
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn harmony_encoding_free(ptr: *mut HarmonyEncodingHandle) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(ptr));
    }
}

#[no_mangle]
pub extern "C" fn harmony_encoding_name(
    encoding: *const HarmonyEncodingHandle,
    out_name: *mut *mut c_char,
    out_error: *mut *mut c_char,
) -> HarmonyStatus {
    if let Err(err) = ensure_out_ptr(out_name, "out_name") {
        store_error(out_error, Some(err.message));
        return err.status;
    }
    unsafe {
        *out_name = ptr::null_mut();
    }

    catch_unwind_result(out_error, || {
        let handle = encoding_from_ptr(encoding)?;
        let name = handle.inner.name();
        unsafe {
            *out_name = to_owned_c_string(name);
        }
        Ok(())
    })
}

fn map_conversation_config(
    config: *const HarmonyRenderConversationConfig,
) -> Option<RenderConversationConfig> {
    unsafe {
        config.as_ref().map(|cfg| RenderConversationConfig {
            auto_drop_analysis: cfg.auto_drop_analysis,
        })
    }
}

fn map_render_options(options: *const HarmonyRenderOptions) -> Option<RenderOptions> {
    unsafe {
        options.as_ref().map(|opts| RenderOptions {
            conversation_has_function_tools: opts.conversation_has_function_tools,
        })
    }
}

#[no_mangle]
pub extern "C" fn harmony_encoding_render_conversation_for_completion(
    encoding: *const HarmonyEncodingHandle,
    conversation_json: *const c_char,
    next_turn_role: *const c_char,
    config: *const HarmonyRenderConversationConfig,
    out_tokens: *mut HarmonyOwnedU32Array,
    out_error: *mut *mut c_char,
) -> HarmonyStatus {
    if let Err(err) = ensure_out_ptr(out_tokens, "out_tokens") {
        store_error(out_error, Some(err.message));
        return err.status;
    }
    unsafe {
        (*out_tokens).data = ptr::null_mut();
        (*out_tokens).len = 0;
    }

    catch_unwind_result(out_error, || {
        let handle = encoding_from_ptr(encoding)?;
        let conversation_str = string_argument(conversation_json, "conversation_json")?;
        let role_str = string_argument(next_turn_role, "next_turn_role")?;
        let conversation: Conversation = serde_json::from_str(&conversation_str)?;
        let role = Role::try_from(role_str.as_str()).map_err(|_| {
            FfiError::new(
                HarmonyStatus::InvalidArgument,
                format!("unknown role: {role_str}"),
            )
        })?;
        let config_owned = map_conversation_config(config);
        let tokens = handle
            .inner
            .render_conversation_for_completion(&conversation, role, config_owned.as_ref())?
            .into_iter()
            .map(|t| t as u32)
            .collect();
        unsafe {
            *out_tokens = vec_to_u32_array(tokens);
        }
        Ok(())
    })
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct HarmonyCompletionOptions {
    pub final_only_deltas: bool,
    pub guarded_stop: bool,
    pub force_next_channel_final: bool,
    pub tools_json: *const c_char,
}

#[no_mangle]
pub extern "C" fn harmony_encoding_render_conversation_for_completion_ex(
    encoding: *const HarmonyEncodingHandle,
    conversation_json: *const c_char,
    next_turn_role: *const c_char,
    config: *const HarmonyRenderConversationConfig,
    _options: *const HarmonyCompletionOptions,
    out_tokens: *mut HarmonyOwnedU32Array,
    out_error: *mut *mut c_char,
) -> HarmonyStatus {
    if let Err(err) = ensure_out_ptr(out_tokens, "out_tokens") {
        store_error(out_error, Some(err.message));
        return err.status;
    }
    unsafe {
        (*out_tokens).data = ptr::null_mut();
        (*out_tokens).len = 0;
    }

    catch_unwind_result(out_error, || {
        let handle = encoding_from_ptr(encoding)?;
        let conversation_str = string_argument(conversation_json, "conversation_json")?;
        let role_str = string_argument(next_turn_role, "next_turn_role")?;
        // Try strict parse first; if it fails, attempt a lenient fixup for missing content.type
        let mut conversation: Conversation = serde_json::from_str(&conversation_str)?;
        let role = Role::try_from(role_str.as_str()).map_err(|_| {
            FfiError::new(
                HarmonyStatus::InvalidArgument,
                format!("unknown role: {role_str}"),
            )
        })?;

        let mut config_owned = map_conversation_config(config);

        // Ensure channel configuration is present by injecting a default SystemContent
        // message at the start. This sets required channels (analysis, commentary, final).
        conversation
            .messages
            .insert(0, Message::from_role_and_content(Role::System, SystemContent::new()));
        let opts = unsafe { _options.as_ref().copied() };

        if let Some(o) = opts {
            // Inject instruction for final-only deltas
            if o.final_only_deltas {
                let dev_msg = Message::from_role_and_content(
                    Role::Developer,
                    DeveloperContent::new().with_instructions(
                        "You are a helpful assistant. Produce exactly one assistant message in the final channel for the user. Do not reveal analysis or commentary to the user. If the user simply greets (e.g., 'hello'), reply briefly with a greeting like 'Hello!' in the final channel.",
                    ),
                );
                // Insert after any system messages
                let mut new_msgs = Vec::<Message>::new();
                let mut inserted = false;
                for m in conversation.messages.iter() {
                    if !inserted && m.author.role != Role::System {
                        new_msgs.push(dev_msg.clone());
                        inserted = true;
                    }
                    new_msgs.push(m.clone());
                }
                if !inserted { new_msgs.push(dev_msg); }
                conversation.messages = new_msgs;
            }
            // Inject tools namespace if provided
            if !o.tools_json.is_null() {
                if let Ok(tools_str) = string_argument(o.tools_json, "tools_json") {
                    if let Ok(root) = serde_json::from_str::<serde_json::Value>(&tools_str) {
                        let ns = root
                            .get("namespace")
                            .and_then(|v| v.as_str())
                            .unwrap_or("functions")
                            .to_string();
                        let mut tool_descs: Vec<ToolDescription> = Vec::new();
                        if let Some(arr) = root.get("tools").and_then(|v| v.as_array()) {
                            for t in arr {
                                let name = t.get("name").and_then(|v| v.as_str()).unwrap_or("");
                                if name.is_empty() { continue; }
                                let params = t.get("json_schema").cloned();
                                let desc = t
                                    .get("description")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                tool_descs.push(ToolDescription::new(name, desc, params));
                            }
                        }
                        if !tool_descs.is_empty() {
                            let dev = DeveloperContent::new()
                                .with_tools(ToolNamespaceConfig::new(ns, None, tool_descs));
                            let dev_msg = Message::from_role_and_content(Role::Developer, dev);
                            // Insert after system and any prior developer instruction
                            let mut new_msgs = Vec::<Message>::new();
                            let mut inserted = false;
                            for m in conversation.messages.iter() {
                                if !inserted && m.author.role != Role::System && m.author.role != Role::Developer {
                                    new_msgs.push(dev_msg.clone());
                                    inserted = true;
                                }
                                new_msgs.push(m.clone());
                            }
                            if !inserted { new_msgs.push(dev_msg); }
                            conversation.messages = new_msgs;
                        }
                    }
                }
            }
        }

        if config_owned.is_none() {
            config_owned = Some(RenderConversationConfig { auto_drop_analysis: true });
        }

        // Render conversation and next-turn role header (<|start|>assistant)
        let mut tokens: Vec<u32> = handle
            .inner
            .render_conversation_for_completion(&conversation, role, config_owned.as_ref())?
            .into_iter()
            .map(|t| t as u32)
            .collect();
        if let Some(o) = opts {
            if o.force_next_channel_final {
                // Append only the remaining header atoms: <|channel|>final<|message|>
                handle
                    .inner
                    .render_formatting_token_into(FormattingToken::Channel, &mut tokens)
                    .map_err(|e| FfiError::new(HarmonyStatus::InternalError, e.to_string()))?;
                handle
                    .inner
                    .render_text_into("final", &mut tokens)
                    .map_err(|e| FfiError::new(HarmonyStatus::InternalError, e.to_string()))?;
                handle
                    .inner
                    .render_formatting_token_into(FormattingToken::Message, &mut tokens)
                    .map_err(|e| FfiError::new(HarmonyStatus::InternalError, e.to_string()))?;
            }
        }
        unsafe { *out_tokens = vec_to_u32_array(tokens) };
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn harmony_encoding_render_conversation_for_completion_and_prime_ex(
    encoding: *const HarmonyEncodingHandle,
    conversation_json: *const c_char,
    next_turn_role: *const c_char,
    config: *const HarmonyRenderConversationConfig,
    options: *const HarmonyCompletionOptions,
    parser: *mut HarmonyStreamableParserHandle,
    out_tokens: *mut HarmonyOwnedU32Array,
    out_error: *mut *mut c_char,
) -> HarmonyStatus {
    if let Err(err) = ensure_out_ptr(out_tokens, "out_tokens") {
        store_error(out_error, Some(err.message));
        return err.status;
    }
    unsafe { (*out_tokens).data = ptr::null_mut(); (*out_tokens).len = 0; }

    catch_unwind_result(out_error, || {
        let handle = encoding_from_ptr(encoding)?;
        let conversation_str = string_argument(conversation_json, "conversation_json")?;
        let role_str = string_argument(next_turn_role, "next_turn_role")?;
        let mut conversation: Conversation = serde_json::from_str(&conversation_str)?;
        let role = Role::try_from(role_str.as_str()).map_err(|_| {
            FfiError::new(HarmonyStatus::InvalidArgument, format!("unknown role: {role_str}"))
        })?;

        let mut config_owned = map_conversation_config(config);
        // Ensure default system message to activate channel config
        conversation
            .messages
            .insert(0, Message::from_role_and_content(Role::System, SystemContent::new()));

        let opts = unsafe { options.as_ref().copied() };
        if let Some(o) = opts {
            if o.final_only_deltas {
                let dev_msg = Message::from_role_and_content(
                    Role::Developer,
                    DeveloperContent::new().with_instructions(
                        "You are a helpful assistant. Produce exactly one assistant message in the final channel for the user. Do not reveal analysis or commentary to the user.",
                    ),
                );
                let mut new_msgs = Vec::<Message>::new();
                let mut inserted = false;
                for m in conversation.messages.iter() {
                    if !inserted && m.author.role != Role::System {
                        new_msgs.push(dev_msg.clone());
                        inserted = true;
                    }
                    new_msgs.push(m.clone());
                }
                if !inserted { new_msgs.push(dev_msg); }
                conversation.messages = new_msgs;
            }
            if !o.tools_json.is_null() {
                if let Ok(tools_str) = string_argument(o.tools_json, "tools_json") {
                    if let Ok(root) = serde_json::from_str::<serde_json::Value>(&tools_str) {
                        let ns = root.get("namespace").and_then(|v| v.as_str()).unwrap_or("functions").to_string();
                        let mut tool_descs: Vec<ToolDescription> = Vec::new();
                        if let Some(arr) = root.get("tools").and_then(|v| v.as_array()) {
                            for t in arr {
                                let name = t.get("name").and_then(|v| v.as_str()).unwrap_or("");
                                if name.is_empty() { continue; }
                                let params = t.get("json_schema").cloned();
                                let desc = t.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                tool_descs.push(ToolDescription::new(name, desc, params));
                            }
                        }
                        if !tool_descs.is_empty() {
                            let dev = DeveloperContent::new().with_tools(ToolNamespaceConfig::new(ns, None, tool_descs));
                            let dev_msg = Message::from_role_and_content(Role::Developer, dev);
                            let mut new_msgs = Vec::<Message>::new();
                            let mut inserted = false;
                            for m in conversation.messages.iter() {
                                if !inserted && m.author.role != Role::System && m.author.role != Role::Developer {
                                    new_msgs.push(dev_msg.clone()); inserted = true;
                                }
                                new_msgs.push(m.clone());
                            }
                            if !inserted { new_msgs.push(dev_msg); }
                            conversation.messages = new_msgs;
                        }
                    }
                }
            }
        }

        if config_owned.is_none() { config_owned = Some(RenderConversationConfig { auto_drop_analysis: true }); }

        // Render next turn header and content prefix
        let mut tokens: Vec<u32> = handle
            .inner
            .render_conversation_for_completion(&conversation, role, config_owned.as_ref())?
            .into_iter()
            .map(|t| t as u32)
            .collect();
        if let Some(o) = opts {
            if o.force_next_channel_final {
                handle.inner.render_formatting_token_into(FormattingToken::Channel, &mut tokens)
                    .map_err(|e| FfiError::new(HarmonyStatus::InternalError, e.to_string()))?;
                handle.inner.render_text_into("final", &mut tokens)
                    .map_err(|e| FfiError::new(HarmonyStatus::InternalError, e.to_string()))?;
                handle.inner.render_formatting_token_into(FormattingToken::Message, &mut tokens)
                    .map_err(|e| FfiError::new(HarmonyStatus::InternalError, e.to_string()))?;
            }
        }

        // Prime parser if provided
        if !parser.is_null() {
            let parser_handle = parser_from_ptr_mut(parser)?;
            if let Some(o) = opts {
                if o.force_next_channel_final {
                    parser_handle.inner.prime_assistant_final()
                        .map_err(|e| FfiError::new(HarmonyStatus::InternalError, e.to_string()))?;
                }
            }
        }

        unsafe { *out_tokens = vec_to_u32_array(tokens) };
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn harmony_encoding_render_conversation(
    encoding: *const HarmonyEncodingHandle,
    conversation_json: *const c_char,
    config: *const HarmonyRenderConversationConfig,
    out_tokens: *mut HarmonyOwnedU32Array,
    out_error: *mut *mut c_char,
) -> HarmonyStatus {
    if let Err(err) = ensure_out_ptr(out_tokens, "out_tokens") {
        store_error(out_error, Some(err.message));
        return err.status;
    }
    unsafe {
        (*out_tokens).data = ptr::null_mut();
        (*out_tokens).len = 0;
    }

    catch_unwind_result(out_error, || {
        let handle = encoding_from_ptr(encoding)?;
        let conversation_str = string_argument(conversation_json, "conversation_json")?;
        let conversation: Conversation = serde_json::from_str(&conversation_str)?;
        let config_owned = map_conversation_config(config);
        let tokens = handle
            .inner
            .render_conversation(&conversation, config_owned.as_ref())?
            .into_iter()
            .map(|t| t as u32)
            .collect();
        unsafe {
            *out_tokens = vec_to_u32_array(tokens);
        }
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn harmony_encoding_render_conversation_for_training(
    encoding: *const HarmonyEncodingHandle,
    conversation_json: *const c_char,
    config: *const HarmonyRenderConversationConfig,
    out_tokens: *mut HarmonyOwnedU32Array,
    out_error: *mut *mut c_char,
) -> HarmonyStatus {
    if let Err(err) = ensure_out_ptr(out_tokens, "out_tokens") {
        store_error(out_error, Some(err.message));
        return err.status;
    }
    unsafe {
        (*out_tokens).data = ptr::null_mut();
        (*out_tokens).len = 0;
    }

    catch_unwind_result(out_error, || {
        let handle = encoding_from_ptr(encoding)?;
        let conversation_str = string_argument(conversation_json, "conversation_json")?;
        let conversation: Conversation = serde_json::from_str(&conversation_str)?;
        let config_owned = map_conversation_config(config);
        let tokens = handle
            .inner
            .render_conversation_for_training(&conversation, config_owned.as_ref())?
            .into_iter()
            .map(|t| t as u32)
            .collect();
        unsafe {
            *out_tokens = vec_to_u32_array(tokens);
        }
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn harmony_encoding_render(
    encoding: *const HarmonyEncodingHandle,
    message_json: *const c_char,
    render_options: *const HarmonyRenderOptions,
    out_tokens: *mut HarmonyOwnedU32Array,
    out_error: *mut *mut c_char,
) -> HarmonyStatus {
    if let Err(err) = ensure_out_ptr(out_tokens, "out_tokens") {
        store_error(out_error, Some(err.message));
        return err.status;
    }
    unsafe {
        (*out_tokens).data = ptr::null_mut();
        (*out_tokens).len = 0;
    }

    catch_unwind_result(out_error, || {
        let handle = encoding_from_ptr(encoding)?;
        let message_str = string_argument(message_json, "message_json")?;
        let message: Message = serde_json::from_str(&message_str)?;
        let options_owned = map_render_options(render_options);
        let tokens = handle
            .inner
            .render(&message, options_owned.as_ref())?
            .into_iter()
            .map(|t| t as u32)
            .collect();
        unsafe {
            *out_tokens = vec_to_u32_array(tokens);
        }
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn harmony_encoding_render_system_and_user_for_completion_ex(
    encoding: *const HarmonyEncodingHandle,
    system_text: *const c_char,
    user_parts: *const HarmonyStringArray,
    next_turn_role: *const c_char,
    config: *const HarmonyRenderConversationConfig,
    options: *const HarmonyCompletionOptions,
    out_tokens: *mut HarmonyOwnedU32Array,
    out_error: *mut *mut c_char,
) -> HarmonyStatus {
    if let Err(err) = ensure_out_ptr(out_tokens, "out_tokens") {
        store_error(out_error, Some(err.message));
        return err.status;
    }
    unsafe {
        (*out_tokens).data = ptr::null_mut();
        (*out_tokens).len = 0;
    }

    catch_unwind_result(out_error, || {
        let handle = encoding_from_ptr(encoding)?;
        let role_str = string_argument(next_turn_role, "next_turn_role")?;
        let role = Role::try_from(role_str.as_str()).map_err(|_| {
            FfiError::new(
                HarmonyStatus::InvalidArgument,
                format!("unknown role: {role_str}"),
            )
        })?;

        // Build conversation in Rust without JSON
        let mut messages: Vec<Message> = Vec::new();
        if !system_text.is_null() {
            let sys_txt = string_argument(system_text, "system_text")?;
            let sys = SystemContent::new().with_model_identity("You are ChatGPT, a large language model trained by OpenAI.");
            let mut msg = Message::from_role_and_content(Role::System, sys);
            // Prepend plain text system text as an additional content block
            msg = msg.adding_content(sys_txt);
            messages.push(msg);
        }
        if !user_parts.is_null() {
            let arr = unsafe { &*user_parts };
            if !arr.data.is_null() {
                let items = unsafe { std::slice::from_raw_parts(arr.data, arr.len) };
                for &p in items {
                    if p.is_null() { continue; }
                    let s = unsafe { CStr::from_ptr(p) }.to_string_lossy().to_string();
                    if !s.is_empty() {
                        messages.push(Message::from_role_and_content(Role::User, s));
                    }
                }
            }
        }

        let mut conversation = Conversation::from_messages(messages);

        // Map config and options (reusing render_ex behavior)
        let mut config_owned = map_conversation_config(config);
        let opts = unsafe { options.as_ref().copied() };
        if let Some(o) = opts {
            if o.final_only_deltas {
                let dev_msg = Message::from_role_and_content(
                    Role::Developer,
                    DeveloperContent::new().with_instructions(
                        "You are a helpful assistant. Produce exactly one assistant message in the final channel for the user. Do not reveal analysis or commentary to the user.",
                    ),
                );
                // Insert after system messages
                let mut new_msgs: Vec<Message> = Vec::new();
                let mut inserted = false;
                for m in conversation.messages.iter() {
                    if !inserted && m.author.role != Role::System {
                        new_msgs.push(dev_msg.clone());
                        inserted = true;
                    }
                    new_msgs.push(m.clone());
                }
                if !inserted { new_msgs.push(dev_msg); }
                conversation.messages = new_msgs;
            }
            if !o.tools_json.is_null() {
                if let Ok(tools_str) = string_argument(o.tools_json, "tools_json") {
                    if let Ok(root) = serde_json::from_str::<serde_json::Value>(&tools_str) {
                        let ns = root
                            .get("namespace")
                            .and_then(|v| v.as_str())
                            .unwrap_or("functions")
                            .to_string();
                        let mut tool_descs: Vec<ToolDescription> = Vec::new();
                        if let Some(arr) = root.get("tools").and_then(|v| v.as_array()) {
                            for t in arr {
                                let name = t.get("name").and_then(|v| v.as_str()).unwrap_or("");
                                if name.is_empty() { continue; }
                                let params = t.get("json_schema").cloned();
                                let desc = t.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                tool_descs.push(ToolDescription::new(name, desc, params));
                            }
                        }
                        if !tool_descs.is_empty() {
                            let dev = DeveloperContent::new().with_tools(ToolNamespaceConfig::new(ns, None, tool_descs));
                            let dev_msg = Message::from_role_and_content(Role::Developer, dev);
                            let mut new_msgs = Vec::<Message>::new();
                            let mut inserted = false;
                            for m in conversation.messages.iter() {
                                if !inserted && m.author.role != Role::System && m.author.role != Role::Developer {
                                    new_msgs.push(dev_msg.clone());
                                    inserted = true;
                                }
                                new_msgs.push(m.clone());
                            }
                            if !inserted { new_msgs.push(dev_msg); }
                            conversation.messages = new_msgs;
                        }
                    }
                }
            }
        }

        if config_owned.is_none() {
            config_owned = Some(RenderConversationConfig { auto_drop_analysis: true });
        }

        let mut tokens = handle
            .inner
            .render_conversation_for_completion(&conversation, role, config_owned.as_ref())?
            .into_iter()
            .map(|t| t as u32)
            .collect();
        if let Some(o) = opts {
            if o.force_next_channel_final {
                // Append only the remaining header atoms: <|channel|>final<|message|>
                handle
                    .inner
                    .render_formatting_token_into(FormattingToken::Channel, &mut tokens)
                    .map_err(|e| FfiError::new(HarmonyStatus::InternalError, e.to_string()))?;
                handle
                    .inner
                    .render_text_into("final", &mut tokens)
                    .map_err(|e| FfiError::new(HarmonyStatus::InternalError, e.to_string()))?;
                handle
                    .inner
                    .render_formatting_token_into(FormattingToken::Message, &mut tokens)
                    .map_err(|e| FfiError::new(HarmonyStatus::InternalError, e.to_string()))?;
            }
        }
        unsafe { *out_tokens = vec_to_u32_array(tokens) };
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn harmony_encoding_render_system_and_user_for_completion_and_prime_ex(
    encoding: *const HarmonyEncodingHandle,
    system_text: *const c_char,
    user_parts: *const HarmonyStringArray,
    next_turn_role: *const c_char,
    config: *const HarmonyRenderConversationConfig,
    options: *const HarmonyCompletionOptions,
    parser: *mut HarmonyStreamableParserHandle,
    out_tokens: *mut HarmonyOwnedU32Array,
    out_error: *mut *mut c_char,
) -> HarmonyStatus {
    if let Err(err) = ensure_out_ptr(out_tokens, "out_tokens") {
        store_error(out_error, Some(err.message));
        return err.status;
    }
    unsafe { (*out_tokens).data = ptr::null_mut(); (*out_tokens).len = 0; }

    catch_unwind_result(out_error, || {
        let handle = encoding_from_ptr(encoding)?;
        let role_str = string_argument(next_turn_role, "next_turn_role")?;
        let role = Role::try_from(role_str.as_str()).map_err(|_| {
            FfiError::new(HarmonyStatus::InvalidArgument, format!("unknown role: {role_str}"))
        })?;

        // Build messages from inputs
        let mut messages: Vec<Message> = Vec::new();
        if !system_text.is_null() {
            let sys_str = string_argument(system_text, "system_text")?;
            messages.push(Message::from_role_and_content(Role::System, SystemContent::new()));
            if !sys_str.is_empty() {
                // Append instructions as developer content to avoid duplicating system semantics
                let dev = DeveloperContent::new().with_instructions(sys_str);
                messages.push(Message::from_role_and_content(Role::Developer, dev));
            }
        } else {
            messages.push(Message::from_role_and_content(Role::System, SystemContent::new()));
        }
        if !user_parts.is_null() {
            let arr = unsafe { &*user_parts };
            if !arr.data.is_null() {
                let slice = unsafe { std::slice::from_raw_parts(arr.data, arr.len) };
                for p in slice {
                    if !p.is_null() {
                        let s = unsafe { CStr::from_ptr(*p) }.to_string_lossy().to_string();
                        if !s.is_empty() {
                            messages.push(Message::from_role_and_content(Role::User, s));
                        }
                    }
                }
            }
        }

        let mut conversation = Conversation::from_messages(messages);
        let mut config_owned = map_conversation_config(config);
        let opts = unsafe { options.as_ref().copied() };
        if let Some(o) = opts {
            if o.final_only_deltas {
                let dev_msg = Message::from_role_and_content(
                    Role::Developer,
                    DeveloperContent::new().with_instructions(
                        "You are a helpful assistant. Produce exactly one assistant message in the final channel for the user. Do not reveal analysis or commentary to the user.",
                    ),
                );
                let mut new_msgs = Vec::<Message>::new();
                let mut inserted = false;
                for m in conversation.messages.iter() {
                    if !inserted && m.author.role != Role::System {
                        new_msgs.push(dev_msg.clone());
                        inserted = true;
                    }
                    new_msgs.push(m.clone());
                }
                if !inserted { new_msgs.push(dev_msg); }
                conversation.messages = new_msgs;
            }
            if !o.tools_json.is_null() {
                if let Ok(tools_str) = string_argument(o.tools_json, "tools_json") {
                    if let Ok(root) = serde_json::from_str::<serde_json::Value>(&tools_str) {
                        let ns = root.get("namespace").and_then(|v| v.as_str()).unwrap_or("functions").to_string();
                        let mut tool_descs: Vec<ToolDescription> = Vec::new();
                        if let Some(arr) = root.get("tools").and_then(|v| v.as_array()) {
                            for t in arr {
                                let name = t.get("name").and_then(|v| v.as_str()).unwrap_or("");
                                if name.is_empty() { continue; }
                                let params = t.get("json_schema").cloned();
                                let desc = t.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                tool_descs.push(ToolDescription::new(name, desc, params));
                            }
                        }
                        if !tool_descs.is_empty() {
                            let dev = DeveloperContent::new().with_tools(ToolNamespaceConfig::new(ns, None, tool_descs));
                            let dev_msg = Message::from_role_and_content(Role::Developer, dev);
                            let mut new_msgs = Vec::<Message>::new();
                            let mut inserted = false;
                            for m in conversation.messages.iter() {
                                if !inserted && m.author.role != Role::System && m.author.role != Role::Developer {
                                    new_msgs.push(dev_msg.clone()); inserted = true;
                                }
                                new_msgs.push(m.clone());
                            }
                            if !inserted { new_msgs.push(dev_msg); }
                            conversation.messages = new_msgs;
                        }
                    }
                }
            }
        }

        if config_owned.is_none() { config_owned = Some(RenderConversationConfig { auto_drop_analysis: true }); }

        let mut tokens: Vec<u32> = handle
            .inner
            .render_conversation_for_completion(&conversation, role, config_owned.as_ref())?
            .into_iter()
            .map(|t| t as u32)
            .collect();
        if let Some(o) = opts {
            if o.force_next_channel_final {
                handle.inner.render_formatting_token_into(FormattingToken::Channel, &mut tokens)
                    .map_err(|e| FfiError::new(HarmonyStatus::InternalError, e.to_string()))?;
                handle.inner.render_text_into("final", &mut tokens)
                    .map_err(|e| FfiError::new(HarmonyStatus::InternalError, e.to_string()))?;
                handle.inner.render_formatting_token_into(FormattingToken::Message, &mut tokens)
                    .map_err(|e| FfiError::new(HarmonyStatus::InternalError, e.to_string()))?;
            }
        }

        if !parser.is_null() {
            let parser_handle = parser_from_ptr_mut(parser)?;
            if let Some(o) = opts {
                if o.force_next_channel_final {
                    parser_handle.inner.prime_assistant_final()
                        .map_err(|e| FfiError::new(HarmonyStatus::InternalError, e.to_string()))?;
                }
            }
        }

        unsafe { *out_tokens = vec_to_u32_array(tokens) };
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn harmony_encoding_render_tool_message(
    encoding: *const HarmonyEncodingHandle,
    tool_name: *const c_char,
    output_text: *const c_char,
    out_tokens: *mut HarmonyOwnedU32Array,
    out_error: *mut *mut c_char,
) -> HarmonyStatus {
    if let Err(err) = ensure_out_ptr(out_tokens, "out_tokens") {
        store_error(out_error, Some(err.message));
        return err.status;
    }
    unsafe {
        (*out_tokens).data = ptr::null_mut();
        (*out_tokens).len = 0;
    }
    catch_unwind_result(out_error, || {
        let handle = encoding_from_ptr(encoding)?;
        let name = string_argument(tool_name, "tool_name")?;
        let out = string_argument(output_text, "output_text")?;
        let mut msg = Message::from_author_and_content(
            crate::chat::Author::new(Role::Tool, &name),
            out,
        );
        msg = msg.with_channel("commentary").with_recipient("assistant");
        let tokens = handle
            .inner
            .render(&msg, None)?
            .into_iter()
            .map(|t| t as u32)
            .collect();
        unsafe { *out_tokens = vec_to_u32_array(tokens) };
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn harmony_encoding_render_conversation_from_messages_ex(
    encoding: *const HarmonyEncodingHandle,
    messages_c: *const HarmonyMessageArrayC,
    next_turn_role: *const c_char,
    config: *const HarmonyRenderConversationConfig,
    options: *const HarmonyCompletionOptions,
    out_tokens: *mut HarmonyOwnedU32Array,
    out_error: *mut *mut c_char,
) -> HarmonyStatus {
    if let Err(err) = ensure_out_ptr(out_tokens, "out_tokens") {
        store_error(out_error, Some(err.message));
        return err.status;
    }
    unsafe { (*out_tokens).data = ptr::null_mut(); (*out_tokens).len = 0; }

    catch_unwind_result(out_error, || {
        let handle = encoding_from_ptr(encoding)?;
        let role_str = string_argument(next_turn_role, "next_turn_role")?;
        let role = Role::try_from(role_str.as_str()).map_err(|_| {
            FfiError::new(HarmonyStatus::InvalidArgument, format!("unknown role: {role_str}"))
        })?;

        let mut messages: Vec<Message> = Vec::new();
        if !messages_c.is_null() {
            let arr = unsafe { &*messages_c };
            if !arr.data.is_null() {
                let slice = unsafe { std::slice::from_raw_parts(arr.data, arr.len) };
                for m in slice {
                    let role_s = optional_string_argument(m.role, "role")?.ok_or_else(|| FfiError::new(HarmonyStatus::InvalidArgument, "message.role is required"))?;
                    let role_enum = Role::try_from(role_s.as_str()).map_err(|_| FfiError::new(HarmonyStatus::InvalidArgument, format!("unknown role: {role_s}")))?;
                    let mut msg = if role_enum == Role::System {
                        // Build SystemContent and then append text contents
                        let sys = SystemContent::new();
                        Message::from_role_and_content(Role::System, sys)
                    } else if role_enum == Role::Tool {
                        let name = optional_string_argument(m.name, "name")?.unwrap_or_default();
                        Message::from_author_and_content(crate::chat::Author::new(Role::Tool, name), "")
                    } else {
                        Message::from_role_and_content(role_enum.clone(), "")
                    };
                    if let Some(rec) = optional_string_argument(m.recipient, "recipient")? { msg = msg.with_recipient(rec); }
                    if let Some(ch) = optional_string_argument(m.channel, "channel")? { msg = msg.with_channel(ch); }
                    if let Some(ct) = optional_string_argument(m.content_type, "content_type")? { msg = msg.with_content_type(ct); }
                    // Append text content blocks
                    if !m.contents.data.is_null() {
                        let c_slice = unsafe { std::slice::from_raw_parts(m.contents.data, m.contents.len) };
                        for &p in c_slice {
                            if p.is_null() { continue; }
                            let s = unsafe { CStr::from_ptr(p) }.to_string_lossy().to_string();
                            if !s.is_empty() {
                                msg = msg.adding_content(s);
                            }
                        }
                    }
                    messages.push(msg);
                }
            }
        }

        let mut conversation = Conversation::from_messages(messages);
        let mut config_owned = map_conversation_config(config);
        let opts = unsafe { options.as_ref().copied() };
        if let Some(o) = opts {
            if o.final_only_deltas {
                let dev_msg = Message::from_role_and_content(
                    Role::Developer,
                    DeveloperContent::new().with_instructions(
                        "You are a helpful assistant. Produce exactly one assistant message in the final channel for the user. Do not reveal analysis or commentary to the user.",
                    ),
                );
                let mut new_msgs = Vec::<Message>::new();
                let mut inserted = false;
                for m in conversation.messages.iter() {
                    if !inserted && m.author.role != Role::System {
                        new_msgs.push(dev_msg.clone());
                        inserted = true;
                    }
                    new_msgs.push(m.clone());
                }
                if !inserted { new_msgs.push(dev_msg); }
                conversation.messages = new_msgs;
            }
            if !o.tools_json.is_null() {
                if let Ok(tools_str) = string_argument(o.tools_json, "tools_json") {
                    if let Ok(root) = serde_json::from_str::<serde_json::Value>(&tools_str) {
                        let ns = root.get("namespace").and_then(|v| v.as_str()).unwrap_or("functions").to_string();
                        let mut tool_descs: Vec<ToolDescription> = Vec::new();
                        if let Some(arr) = root.get("tools").and_then(|v| v.as_array()) {
                            for t in arr {
                                let name = t.get("name").and_then(|v| v.as_str()).unwrap_or("");
                                if name.is_empty() { continue; }
                                let params = t.get("json_schema").cloned();
                                let desc = t.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                tool_descs.push(ToolDescription::new(name, desc, params));
                            }
                        }
                        if !tool_descs.is_empty() {
                            let dev = DeveloperContent::new().with_tools(ToolNamespaceConfig::new(ns, None, tool_descs));
                            let dev_msg = Message::from_role_and_content(Role::Developer, dev);
                            let mut new_msgs = Vec::<Message>::new();
                            let mut inserted = false;
                            for m in conversation.messages.iter() {
                                if !inserted && m.author.role != Role::System && m.author.role != Role::Developer {
                                    new_msgs.push(dev_msg.clone()); inserted = true;
                                }
                                new_msgs.push(m.clone());
                            }
                            if !inserted { new_msgs.push(dev_msg); }
                            conversation.messages = new_msgs;
                        }
                    }
                }
            }
        }

        if config_owned.is_none() { config_owned = Some(RenderConversationConfig { auto_drop_analysis: true }); }

        let tokens = handle
            .inner
            .render_conversation_for_completion(&conversation, role, config_owned.as_ref())?
            .into_iter()
            .map(|t| t as u32)
            .collect();
        unsafe { *out_tokens = vec_to_u32_array(tokens) };
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn harmony_encoding_parse_messages_from_completion_tokens(
    encoding: *const HarmonyEncodingHandle,
    tokens: *const u32,
    tokens_len: usize,
    role: *const c_char,
    out_json: *mut *mut c_char,
    out_error: *mut *mut c_char,
) -> HarmonyStatus {
    if let Err(err) = ensure_out_ptr(out_json, "out_json") {
        store_error(out_error, Some(err.message));
        return err.status;
    }
    unsafe {
        *out_json = ptr::null_mut();
    }

    catch_unwind_result(out_error, || {
        let handle = encoding_from_ptr(encoding)?;
        let tokens_vec = tokens_from_raw(tokens, tokens_len, "tokens")?;
        let role_opt = optional_string_argument(role, "role")?;
        let role_parsed = if let Some(role_str) = role_opt {
            Some(Role::try_from(role_str.as_str()).map_err(|_| {
                FfiError::new(
                    HarmonyStatus::InvalidArgument,
                    format!("unknown role: {role_str}"),
                )
            })?)
        } else {
            None
        };
        let messages: Vec<Message> = handle
            .inner
            .parse_messages_from_completion_tokens(tokens_vec, role_parsed)?;
        let json = serde_json::to_string(&messages)
            .map_err(|e| FfiError::new(HarmonyStatus::InternalError, e.to_string()))?;
        unsafe {
            *out_json = to_owned_c_string(json);
        }
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn harmony_encoding_decode_utf8(
    encoding: *const HarmonyEncodingHandle,
    tokens: *const u32,
    tokens_len: usize,
    out_string: *mut *mut c_char,
    out_error: *mut *mut c_char,
) -> HarmonyStatus {
    if let Err(err) = ensure_out_ptr(out_string, "out_string") {
        store_error(out_error, Some(err.message));
        return err.status;
    }
    unsafe {
        *out_string = ptr::null_mut();
    }

    catch_unwind_result(out_error, || {
        let handle = encoding_from_ptr(encoding)?;
        let tokens_vec = tokens_from_raw(tokens, tokens_len, "tokens")?;
        let text = handle
            .inner
            .tokenizer()
            .decode_utf8(tokens_vec)
            .map_err(|e| FfiError::new(HarmonyStatus::InternalError, e.to_string()))?;
        unsafe {
            *out_string = to_owned_c_string(text);
        }
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn harmony_encoding_decode_bytes(
    encoding: *const HarmonyEncodingHandle,
    tokens: *const u32,
    tokens_len: usize,
    out_bytes: *mut HarmonyOwnedU8Array,
    out_error: *mut *mut c_char,
) -> HarmonyStatus {
    if let Err(err) = ensure_out_ptr(out_bytes, "out_bytes") {
        store_error(out_error, Some(err.message));
        return err.status;
    }
    unsafe {
        (*out_bytes).data = ptr::null_mut();
        (*out_bytes).len = 0;
    }

    catch_unwind_result(out_error, || {
        let handle = encoding_from_ptr(encoding)?;
        let tokens_vec = tokens_from_raw(tokens, tokens_len, "tokens")?;
        let bytes = handle
            .inner
            .tokenizer()
            .decode_bytes(tokens_vec)
            .map_err(|e| FfiError::new(HarmonyStatus::InternalError, e.to_string()))?;
        unsafe {
            *out_bytes = vec_to_u8_array(bytes);
        }
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn harmony_encoding_encode(
    encoding: *const HarmonyEncodingHandle,
    text: *const c_char,
    allowed_special: *const *const c_char,
    allowed_special_len: usize,
    out_tokens: *mut HarmonyOwnedU32Array,
    out_error: *mut *mut c_char,
) -> HarmonyStatus {
    if let Err(err) = ensure_out_ptr(out_tokens, "out_tokens") {
        store_error(out_error, Some(err.message));
        return err.status;
    }
    unsafe {
        (*out_tokens).data = ptr::null_mut();
        (*out_tokens).len = 0;
    }

    catch_unwind_result(out_error, || {
        let handle = encoding_from_ptr(encoding)?;
        let text_str = string_argument(text, "text")?;
        let mut allowed_vec = Vec::with_capacity(allowed_special_len);
        if allowed_special_len > 0 {
            if allowed_special.is_null() {
                return Err(FfiError::new(
                    HarmonyStatus::NullPointer,
                    "argument `allowed_special` was NULL".to_string(),
                ));
            }
            let slice = unsafe { std::slice::from_raw_parts(allowed_special, allowed_special_len) };
            for (idx, entry) in slice.iter().enumerate() {
                let name = format!("allowed_special[{idx}]");
                let value = string_argument(*entry, &name)?;
                allowed_vec.push(value);
            }
        }
        let allowed_set: HashSet<&str> = allowed_vec.iter().map(|s| s.as_str()).collect();
        let tokens = handle
            .inner
            .tokenizer()
            .encode(&text_str, &allowed_set)
            .0
            .into_iter()
            .map(|t| t as u32)
            .collect();
        unsafe {
            *out_tokens = vec_to_u32_array(tokens);
        }
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn harmony_encoding_special_tokens(
    encoding: *const HarmonyEncodingHandle,
    out_tokens: *mut HarmonyStringArray,
    out_error: *mut *mut c_char,
) -> HarmonyStatus {
    if let Err(err) = ensure_out_ptr(out_tokens, "out_tokens") {
        store_error(out_error, Some(err.message));
        return err.status;
    }
    unsafe {
        (*out_tokens).data = ptr::null_mut();
        (*out_tokens).len = 0;
    }

    catch_unwind_result(out_error, || {
        let handle = encoding_from_ptr(encoding)?;
        let values: Vec<String> = handle
            .inner
            .tokenizer()
            .special_tokens()
            .into_iter()
            .map(str::to_string)
            .collect();
        unsafe {
            *out_tokens = vec_to_string_array(values);
        }
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn harmony_encoding_is_special_token(
    encoding: *const HarmonyEncodingHandle,
    token: u32,
    out_is_special: *mut bool,
    out_error: *mut *mut c_char,
) -> HarmonyStatus {
    if let Err(err) = ensure_out_ptr(out_is_special, "out_is_special") {
        store_error(out_error, Some(err.message));
        return err.status;
    }

    catch_unwind_result(out_error, || {
        let handle = encoding_from_ptr(encoding)?;
        unsafe {
            *out_is_special = handle.inner.tokenizer().is_special_token(token);
        }
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn harmony_encoding_stop_tokens(
    encoding: *const HarmonyEncodingHandle,
    out_tokens: *mut HarmonyOwnedU32Array,
    out_error: *mut *mut c_char,
) -> HarmonyStatus {
    if let Err(err) = ensure_out_ptr(out_tokens, "out_tokens") {
        store_error(out_error, Some(err.message));
        return err.status;
    }
    unsafe {
        (*out_tokens).data = ptr::null_mut();
        (*out_tokens).len = 0;
    }

    catch_unwind_result(out_error, || {
        let handle = encoding_from_ptr(encoding)?;
        let tokens: Vec<u32> = handle
            .inner
            .stop_tokens()?
            .into_iter()
            .map(|t| t as u32)
            .collect();
        unsafe {
            *out_tokens = vec_to_u32_array(tokens);
        }
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn harmony_encoding_stop_tokens_for_assistant_actions(
    encoding: *const HarmonyEncodingHandle,
    out_tokens: *mut HarmonyOwnedU32Array,
    out_error: *mut *mut c_char,
) -> HarmonyStatus {
    if let Err(err) = ensure_out_ptr(out_tokens, "out_tokens") {
        store_error(out_error, Some(err.message));
        return err.status;
    }
    unsafe {
        (*out_tokens).data = ptr::null_mut();
        (*out_tokens).len = 0;
    }

    catch_unwind_result(out_error, || {
        let handle = encoding_from_ptr(encoding)?;
        let tokens: Vec<u32> = handle
            .inner
            .stop_tokens_for_assistant_actions()?
            .into_iter()
            .map(|t| t as u32)
            .collect();
        unsafe {
            *out_tokens = vec_to_u32_array(tokens);
        }
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn harmony_get_tool_namespace_config(
    tool: *const c_char,
    out_json: *mut *mut c_char,
    out_error: *mut *mut c_char,
) -> HarmonyStatus {
    if let Err(err) = ensure_out_ptr(out_json, "out_json") {
        store_error(out_error, Some(err.message));
        return err.status;
    }
    unsafe {
        *out_json = ptr::null_mut();
    }

    catch_unwind_result(out_error, || {
        let tool_str = string_argument(tool, "tool")?;
        let cfg = match tool_str.as_str() {
            "browser" => ToolNamespaceConfig::browser(),
            "python" => ToolNamespaceConfig::python(),
            _ => {
                return Err(FfiError::new(
                    HarmonyStatus::InvalidArgument,
                    format!("unknown tool namespace: {tool_str}"),
                ));
            }
        };
        let json = serde_json::to_string(&cfg)
            .map_err(|e| FfiError::new(HarmonyStatus::InternalError, e.to_string()))?;
        unsafe {
            *out_json = to_owned_c_string(json);
        }
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn harmony_streamable_parser_new(
    encoding: *const HarmonyEncodingHandle,
    role: *const c_char,
    out_parser: *mut *mut HarmonyStreamableParserHandle,
    out_error: *mut *mut c_char,
) -> HarmonyStatus {
    if let Err(err) = ensure_out_ptr(out_parser, "out_parser") {
        store_error(out_error, Some(err.message));
        return err.status;
    }
    unsafe {
        *out_parser = ptr::null_mut();
    }

    catch_unwind_result(out_error, || {
        let encoding_handle = encoding_from_ptr(encoding)?;
        let role_opt = optional_string_argument(role, "role")?;
        let parsed_role = if let Some(role_str) = role_opt {
            Some(Role::try_from(role_str.as_str()).map_err(|_| {
                FfiError::new(
                    HarmonyStatus::InvalidArgument,
                    format!("unknown role: {role_str}"),
                )
            })?)
        } else {
            None
        };
        let parser = StreamableParser::new(encoding_handle.inner.clone(), parsed_role)?;
        unsafe {
            *out_parser = Box::into_raw(Box::new(HarmonyStreamableParserHandle {
                inner: parser,
                last_recipient: None,
                last_messages_len: 0,
                pending_tool_args_done: None,
                pending_stop: false,
                call_seq: 0,
                current_call_id: None,
            }));
        }
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn harmony_streamable_parser_free(ptr: *mut HarmonyStreamableParserHandle) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(ptr));
    }
}

#[no_mangle]
pub extern "C" fn harmony_streamable_parser_process(
    parser: *mut HarmonyStreamableParserHandle,
    token: u32,
    out_error: *mut *mut c_char,
) -> HarmonyStatus {
    catch_unwind_result(out_error, || {
        let parser_handle = parser_from_ptr_mut(parser)?;
        parser_handle.inner.process(token)?;
        // Detect message close to emit pending events
        let msgs = parser_handle.inner.messages().to_vec();
        if msgs.len() > parser_handle.last_messages_len {
            if let Some(last) = msgs.last() {
                if last.author.role == Role::Assistant {
                    if last.recipient.is_some() {
                        // Tool call arguments finished
                        parser_handle.pending_tool_args_done = last.recipient.clone();
                    } else if last.channel.as_deref() == Some("final") {
                        // Completed final message
                        parser_handle.pending_stop = true;
                    }
                }
            }
            parser_handle.last_messages_len = msgs.len();
        }
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn harmony_streamable_parser_process_eos(
    parser: *mut HarmonyStreamableParserHandle,
    out_error: *mut *mut c_char,
) -> HarmonyStatus {
    catch_unwind_result(out_error, || {
        let parser_handle = parser_from_ptr_mut(parser)?;
        parser_handle.inner.process_eos()?;
        let msgs = parser_handle.inner.messages().to_vec();
        if msgs.len() > parser_handle.last_messages_len {
            if let Some(last) = msgs.last() {
                if last.author.role == Role::Assistant {
                    if last.recipient.is_some() {
                        parser_handle.pending_tool_args_done = last.recipient.clone();
                    } else if last.channel.as_deref() == Some("final") {
                        parser_handle.pending_stop = true;
                    }
                }
            }
            parser_handle.last_messages_len = msgs.len();
        }
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn harmony_streamable_parser_current_content(
    parser: *const HarmonyStreamableParserHandle,
    out_string: *mut *mut c_char,
    out_error: *mut *mut c_char,
) -> HarmonyStatus {
    if let Err(err) = ensure_out_ptr(out_string, "out_string") {
        store_error(out_error, Some(err.message));
        return err.status;
    }
    unsafe {
        *out_string = ptr::null_mut();
    }

    catch_unwind_result(out_error, || {
        let parser_handle = parser_from_ptr(parser)?;
        let content = parser_handle.inner.current_content()?;
        unsafe {
            *out_string = to_owned_c_string(content);
        }
        Ok(())
    })
}

fn set_optional_string(out: *mut *mut c_char, name: &str, value: Option<String>) -> FfiResult<()> {
    ensure_out_ptr(out, name)?;
    unsafe {
        *out = match value {
            Some(v) => to_owned_c_string(v),
            None => ptr::null_mut(),
        };
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn harmony_streamable_parser_current_role(
    parser: *const HarmonyStreamableParserHandle,
    out_role: *mut *mut c_char,
    out_error: *mut *mut c_char,
) -> HarmonyStatus {
    if let Err(err) = ensure_out_ptr(out_role, "out_role") {
        store_error(out_error, Some(err.message));
        return err.status;
    }
    unsafe {
        *out_role = ptr::null_mut();
    }

    catch_unwind_result(out_error, || {
        let parser_handle = parser_from_ptr(parser)?;
        let value = parser_handle
            .inner
            .current_role()
            .map(|role| role.as_str().to_string());
        set_optional_string(out_role, "out_role", value)?;
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn harmony_streamable_parser_current_content_type(
    parser: *const HarmonyStreamableParserHandle,
    out_content_type: *mut *mut c_char,
    out_error: *mut *mut c_char,
) -> HarmonyStatus {
    if let Err(err) = ensure_out_ptr(out_content_type, "out_content_type") {
        store_error(out_error, Some(err.message));
        return err.status;
    }
    unsafe {
        *out_content_type = ptr::null_mut();
    }

    catch_unwind_result(out_error, || {
        let parser_handle = parser_from_ptr(parser)?;
        let value = parser_handle.inner.current_content_type();
        set_optional_string(out_content_type, "out_content_type", value)?;
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn harmony_streamable_parser_last_content_delta(
    parser: *const HarmonyStreamableParserHandle,
    out_delta: *mut *mut c_char,
    out_error: *mut *mut c_char,
) -> HarmonyStatus {
    if let Err(err) = ensure_out_ptr(out_delta, "out_delta") {
        store_error(out_error, Some(err.message));
        return err.status;
    }
    unsafe {
        *out_delta = ptr::null_mut();
    }

    catch_unwind_result(out_error, || {
        let parser_handle = parser_from_ptr(parser)?;
        let value = parser_handle.inner.last_content_delta()?;
        set_optional_string(out_delta, "out_delta", value)?;
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn harmony_streamable_parser_messages(
    parser: *const HarmonyStreamableParserHandle,
    out_json: *mut *mut c_char,
    out_error: *mut *mut c_char,
) -> HarmonyStatus {
    if let Err(err) = ensure_out_ptr(out_json, "out_json") {
        store_error(out_error, Some(err.message));
        return err.status;
    }
    unsafe {
        *out_json = ptr::null_mut();
    }

    catch_unwind_result(out_error, || {
        let parser_handle = parser_from_ptr(parser)?;
        let json = serde_json::to_string(parser_handle.inner.messages())
            .map_err(|e| FfiError::new(HarmonyStatus::InternalError, e.to_string()))?;
        unsafe {
            *out_json = to_owned_c_string(json);
        }
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn harmony_streamable_parser_tokens(
    parser: *const HarmonyStreamableParserHandle,
    out_tokens: *mut HarmonyOwnedU32Array,
    out_error: *mut *mut c_char,
) -> HarmonyStatus {
    if let Err(err) = ensure_out_ptr(out_tokens, "out_tokens") {
        store_error(out_error, Some(err.message));
        return err.status;
    }
    unsafe {
        (*out_tokens).data = ptr::null_mut();
        (*out_tokens).len = 0;
    }

    catch_unwind_result(out_error, || {
        let parser_handle = parser_from_ptr(parser)?;
        let tokens: Vec<u32> = parser_handle
            .inner
            .tokens()
            .iter()
            .copied()
            .map(|t| t as u32)
            .collect();
        unsafe {
            *out_tokens = vec_to_u32_array(tokens);
        }
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn harmony_streamable_parser_state(
    parser: *const HarmonyStreamableParserHandle,
    out_state: *mut *mut c_char,
    out_error: *mut *mut c_char,
) -> HarmonyStatus {
    if let Err(err) = ensure_out_ptr(out_state, "out_state") {
        store_error(out_error, Some(err.message));
        return err.status;
    }
    unsafe {
        *out_state = ptr::null_mut();
    }

    catch_unwind_result(out_error, || {
        let parser_handle = parser_from_ptr(parser)?;
        let state = parser_handle.inner.state_json()?;
        unsafe {
            *out_state = to_owned_c_string(state);
        }
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn harmony_streamable_parser_current_recipient(
    parser: *const HarmonyStreamableParserHandle,
    out_recipient: *mut *mut c_char,
    out_error: *mut *mut c_char,
) -> HarmonyStatus {
    if let Err(err) = ensure_out_ptr(out_recipient, "out_recipient") {
        store_error(out_error, Some(err.message));
        return err.status;
    }
    unsafe {
        *out_recipient = ptr::null_mut();
    }

    catch_unwind_result(out_error, || {
        let parser_handle = parser_from_ptr(parser)?;
        let value = parser_handle.inner.current_recipient();
        set_optional_string(out_recipient, "out_recipient", value)?;
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn harmony_streamable_parser_current_channel(
    parser: *const HarmonyStreamableParserHandle,
    out_channel: *mut *mut c_char,
    out_error: *mut *mut c_char,
) -> HarmonyStatus {
    if let Err(err) = ensure_out_ptr(out_channel, "out_channel") {
        store_error(out_error, Some(err.message));
        return err.status;
    }
    unsafe {
        *out_channel = ptr::null_mut();
    }

    catch_unwind_result(out_error, || {
        let parser_handle = parser_from_ptr(parser)?;
        let value = parser_handle.inner.current_channel();
        set_optional_string(out_channel, "out_channel", value)?;
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn harmony_streamable_parser_next_event(
    parser: *mut HarmonyStreamableParserHandle,
    out_event: *mut HarmonyStreamEvent,
    out_error: *mut *mut c_char,
) -> HarmonyStatus {
    if let Err(err) = ensure_out_ptr(out_event, "out_event") {
        store_error(out_error, Some(err.message));
        return err.status;
    }
    // Initialize to NONE with null pointers
    unsafe {
        (*out_event).kind = HarmonyStreamEventKind::None as i32;
        (*out_event).channel = ptr::null_mut();
        (*out_event).recipient = ptr::null_mut();
        (*out_event).name = ptr::null_mut();
        (*out_event).call_id = ptr::null_mut();
        (*out_event).text = ptr::null_mut();
        (*out_event).json = ptr::null_mut();
    }

    catch_unwind_result(out_error, || {
        let parser_handle = parser_from_ptr_mut(parser)?;
        let channel = parser_handle.inner.current_channel();
        let recipient = parser_handle.inner.current_recipient();
        // Take and clear the last content delta so each delta is emitted once
        let delta = parser_handle.inner.take_last_content_delta()?;

        // Tool begin: recipient changed from None/other -> Some
        if recipient.is_some() && recipient != parser_handle.last_recipient {
            parser_handle.last_recipient = recipient.clone();
            // Allocate a new call_id for this tool call
            parser_handle.call_seq = parser_handle.call_seq.wrapping_add(1);
            let call_id = format!("call-{}", parser_handle.call_seq);
            parser_handle.current_call_id = Some(call_id.clone());
            unsafe {
                (*out_event).kind = HarmonyStreamEventKind::ToolCallBegin as i32;
                if let Some(ch) = channel { (*out_event).channel = to_owned_c_string(ch); }
                if let Some(rc) = recipient { (*out_event).recipient = to_owned_c_string(rc); }
                (*out_event).call_id = to_owned_c_string(call_id);
                // For convenience, mirror recipient into name when available
                if let Some(rc) = parser_handle.last_recipient.clone() {
                    (*out_event).name = to_owned_c_string(rc);
                }
            }
            return Ok(());
        }
        // Tool args delta: commentary + recipient + delta
        if let (Some(ch), Some(_rc), Some(d)) = (channel.as_deref(), recipient.as_ref(), delta.as_ref()) {
            if ch == "commentary" && !d.is_empty() {
                unsafe {
                    (*out_event).kind = HarmonyStreamEventKind::ToolArgsDelta as i32;
                    (*out_event).channel = to_owned_c_string(ch);
                    if let Some(rc) = recipient { (*out_event).recipient = to_owned_c_string(rc); }
                    (*out_event).json = to_owned_c_string(d);
                    if let Some(id) = parser_handle.current_call_id.clone() {
                        (*out_event).call_id = to_owned_c_string(id);
                    }
                }
                return Ok(());
            }
        }
        // Final content delta
        if let (Some(ch), Some(d)) = (channel.as_deref(), delta.as_ref()) {
            if ch == "final" && !d.is_empty() {
                unsafe {
                    (*out_event).kind = HarmonyStreamEventKind::ContentDelta as i32;
                    (*out_event).channel = to_owned_c_string(ch);
                    (*out_event).text = to_owned_c_string(d);
                }
                return Ok(());
            }
        }
        // Emit pending TOOL_ARGS_DONE if any
        if let Some(rc) = parser_handle.pending_tool_args_done.take() {
            unsafe {
                (*out_event).kind = HarmonyStreamEventKind::ToolArgsDone as i32;
                if let Some(ch) = channel.clone() { (*out_event).channel = to_owned_c_string(ch); }
                (*out_event).recipient = to_owned_c_string(rc);
                if let Some(id) = parser_handle.current_call_id.clone() {
                    (*out_event).call_id = to_owned_c_string(id);
                }
            }
            // Clear current_call_id after DONE
            parser_handle.current_call_id = None;
            return Ok(());
        }
        // Emit pending STOP if any
        if parser_handle.pending_stop {
            parser_handle.pending_stop = false;
            unsafe {
                (*out_event).kind = HarmonyStreamEventKind::Stop as i32;
                if let Some(ch) = channel { (*out_event).channel = to_owned_c_string(ch); }
            }
            return Ok(());
        }
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn harmony_streamable_parser_prime_assistant_final(
    parser: *mut HarmonyStreamableParserHandle,
    out_error: *mut *mut c_char,
) -> HarmonyStatus {
    catch_unwind_result(out_error, || {
        let parser_handle = parser_from_ptr_mut(parser)?;
        parser_handle
            .inner
            .prime_assistant_final()
            .map_err(|e| FfiError::new(HarmonyStatus::InternalError, e.to_string()))?;
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn harmony_stream_event_free(ev: *mut HarmonyStreamEvent) {
    if ev.is_null() {
        return;
    }
    unsafe {
        let e = &mut *ev;
        if !e.channel.is_null() { drop(CString::from_raw(e.channel)); e.channel = ptr::null_mut(); }
        if !e.recipient.is_null() { drop(CString::from_raw(e.recipient)); e.recipient = ptr::null_mut(); }
        if !e.name.is_null() { drop(CString::from_raw(e.name)); e.name = ptr::null_mut(); }
        if !e.call_id.is_null() { drop(CString::from_raw(e.call_id)); e.call_id = ptr::null_mut(); }
        if !e.text.is_null() { drop(CString::from_raw(e.text)); e.text = ptr::null_mut(); }
        if !e.json.is_null() { drop(CString::from_raw(e.json)); e.json = ptr::null_mut(); }
    }
}

#[no_mangle]
pub extern "C" fn harmony_string_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        drop(CString::from_raw(ptr));
    }
}

#[no_mangle]
pub extern "C" fn harmony_owned_u32_array_free(array: HarmonyOwnedU32Array) {
    if array.data.is_null() {
        return;
    }
    unsafe {
        let slice = std::ptr::slice_from_raw_parts_mut(array.data, array.len);
        drop(Box::from_raw(slice));
    }
}

#[no_mangle]
pub extern "C" fn harmony_owned_u8_array_free(array: HarmonyOwnedU8Array) {
    if array.data.is_null() {
        return;
    }
    unsafe {
        let slice = std::ptr::slice_from_raw_parts_mut(array.data, array.len);
        drop(Box::from_raw(slice));
    }
}

#[no_mangle]
pub extern "C" fn harmony_string_array_free(array: HarmonyStringArray) {
    if array.data.is_null() {
        return;
    }
    unsafe {
        let boxed = Box::from_raw(std::ptr::slice_from_raw_parts_mut(array.data, array.len));
        for ptr in boxed.iter() {
            if !ptr.is_null() {
                drop(CString::from_raw(*ptr));
            }
        }
    }
}
