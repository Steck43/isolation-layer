//! Host-side vestibule: treat every guest byte as hostile until it fits schema.

mod frame;
mod listen;
mod schema;

pub use frame::{decode_frame, encode_frame, FrameError, MAX_FRAME_BYTES};
pub use listen::{accept_one_result, bind_uds, read_one_frame, serve_one, serve_vsock_one, ListenError};
pub use schema::{
    parse_result_message, parse_result_message_raw, ParseMode, ResultMessage, SchemaError,
    MAX_BODY_BYTES, MAX_FILENAME_LEN, MAX_TASK_ID_LEN, SCHEMA_VERSION,
};
