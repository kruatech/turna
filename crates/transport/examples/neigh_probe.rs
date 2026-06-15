//! Lab probe for netlink neighbor resolution (AF_XDP Phase 2, step 1).
//!
//! Resolves the next-hop MAC for a target IP using the kernel routing +
//! neighbour tables, exactly as the AF_XDP datapath will. Run it on the lab
//! before wiring the resolver into the datapath:
//!
//!   cargo run -p turna-transport --features af-xdp --example neigh_probe -- 10.0.0.2
//!
//! If it prints "(no neighbor entry)", populate the kernel table first
//! (`ping -c1 10.0.0.2`) and re-run — the resolver reads the table, it does not
//! yet send its own ARP/NDP probe (that is a later refinement).
#[cfg(all(target_os = "linux", feature = "af-xdp"))]
fn main() {
    let arg = std::env::args().nth(1).expect("usage: neigh_probe <ip>");
    let target: std::net::IpAddr = arg.parse().expect("invalid IP address");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    match rt.block_on(turna_transport::neighbor::resolve_mac(target)) {
        Ok(Some(m)) => println!(
            "{target} -> {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            m[0], m[1], m[2], m[3], m[4], m[5]
        ),
        Ok(None) => {
            println!("{target} -> (no neighbor entry; try `ping -c1 {target}` then re-run)")
        }
        Err(e) => {
            eprintln!("netlink error: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(all(target_os = "linux", feature = "af-xdp")))]
fn main() {
    eprintln!("neigh_probe requires a Linux build with --features af-xdp");
    std::process::exit(1);
}
