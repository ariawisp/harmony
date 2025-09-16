//! C-compatible bindings for the harmony crate.
//!
//! The C API intentionally mirrors the low-level surface exposed via the
//! Python bindings.  Complex data-structures are exchanged as JSON strings in
//! order to keep the ABI small and stable.  Callers are responsible for
//! releasing all heap-allocated values returned from the API via the respective
//! `harmony_*_free` helpers provided in this module.

use crate::{
    chat::{Conversation, Message, Role, ToolNamespaceConfig},
    encoding::{HarmonyEncoding, RenderConversationConfig, RenderOptions, StreamableParser},
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
pub struct HarmonyOwnedU8Array {
    pub data: *mut u8,
    pub len: usize,
}

#[repr(C)]
pub struct HarmonyStringArray {
    pub data: *mut *mut c_char,
    pub len: usize,
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
            *out_parser = Box::into_raw(Box::new(HarmonyStreamableParserHandle { inner: parser }));
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
