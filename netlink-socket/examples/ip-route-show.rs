//! This example dumps routing entries from the main table similar to `ip route show`.
//!
//! Run with: `cargo run --example ip-route-show --features=rt-route`

use std::{ffi::CStr, net::Ipv4Addr};

use netlink_bindings::rt_route;
use netlink_socket2::NetlinkSocket;

#[cfg_attr(not(feature = "async"), maybe_async::must_be_sync)]
#[cfg_attr(feature = "tokio", tokio::main(flavor = "current_thread"))]
#[cfg_attr(feature = "smol", macro_rules_attribute::apply(smol_macros::main))]
async fn main() {
    let mut sock = NetlinkSocket::new();

    let header = rt_route::Rtmsg {
        rtm_family: libc::AF_INET as u8,
        rtm_table: libc::RT_TABLE_MAIN as u8,
        ..Default::default()
    };

    let req = rt_route::Request::new().op_getroute_dump(&header);

    let mut res = sock.request(&req).await.unwrap();
    while let Some((header, attrs)) = res.recv().await.transpose().unwrap() {
        let dst = attrs.get_dst().unwrap_or(Ipv4Addr::UNSPECIFIED.into());
        let ifindex = attrs.get_oif().unwrap();
        let ifname = get_ifname(ifindex);

        println!();
        print!("{dst}/{}", header.rtm_dst_len);
        if let Some(gateway) = attrs.get_gateway().ok() {
            print!(" via {gateway}");
        }
        print!(" dev {ifname}");
        if let Some(src) = attrs.get_prefsrc().ok() {
            print!(" src {src}");
        }
        println!();

        println!("{header:?}");
        println!("{attrs:?}");
    }
}

fn get_ifname(ifindex: u32) -> String {
    unsafe {
        let mut buf = [0i8; libc::IFNAMSIZ];
        let ifname = libc::if_indextoname(ifindex, buf.as_mut_ptr());
        assert!(!ifname.is_null());
        CStr::from_ptr(ifname).to_string_lossy().to_string()
    }
}
