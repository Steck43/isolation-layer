//! Host-side vestibule: treat every guest byte as hostile until it fits schema.
//!
//! B3 deliverable slice 1: length-prefixed frame codec + result schema + BS-04
//! reject suite (including negative control with validation disabled).

mod frame;
mod schema;

pub use frame::{decode_frame, encode_frame, FrameError, MAX_FRAME_BYTES};
pub use schema::{
    parse_result_message, parse_result_message_raw, ParseMode, ResultMessage, SchemaError,
    MAX_BODY_BYTES, MAX_FILENAME_LEN, MAX_TASK_ID_LEN, SCHEMA_VERSION,
};
