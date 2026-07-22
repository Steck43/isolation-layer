//! Host-side vestibule: schema-bounded Firecracker vsock / UDS listener (B3 / BS-04).

pub mod frame;
pub mod harden;
pub mod listen;
pub mod reject;
pub mod schema;

pub use frame::{decode_frame, encode_frame, FrameError, MAX_FRAME_BYTES};
pub use harden::{apply_listener_hardening, apply_listener_hardening_with_fs_roots, landlock_roots_for_listen_path, HardenReport};
pub use listen::{
    accept_one_result, bind_uds, read_one_frame, serve_one, serve_one_with_opts, serve_vsock_one,
    serve_vsock_one_with_opts, ListenError, ServeOpts,
};
pub use reject::RejectLog;
pub use schema::{
    parse_result_message, parse_result_message_raw, ParseMode, ResultMessage, SchemaError,
    SCHEMA_VERSION,
};
