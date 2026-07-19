#![allow(clippy::doc_lazy_continuation)]
#![doc = include_str!("../README.md")]

mod chained;
mod error;
mod multicast;
mod sock;

pub use chained::NetlinkReplyChained;
pub use error::ReplyError;
pub use multicast::{MulticastRecv, MulticastSocketRaw};
pub use sock::{NetlinkReply, NetlinkSocket};
