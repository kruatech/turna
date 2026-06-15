//! Build script for `turna-transport`.
//!
//! Under the `af-xdp` feature it compiles the in-tree XDP filter program
//! (`src/bpf/xdp_turn.c`, task 1.1) to a BPF object that `af_xdp.rs` embeds via
//! `include_bytes!`. For all other builds it is a no-op, so non-`af-xdp` targets
//! (incl. macOS / Windows) do not require clang.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // The XDP object is only needed when the af-xdp datapath is built.
    if env::var_os("CARGO_FEATURE_AF_XDP").is_none() {
        return;
    }

    let src = PathBuf::from("src/bpf/xdp_turn.c");
    println!("cargo:rerun-if-changed={}", src.display());

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let obj = out_dir.join("xdp_turn.o");

    let clang = env::var("CLANG").unwrap_or_else(|_| "clang".to_string());
    // libbpf headers (`bpf/bpf_helpers.h`) are exported by libbpf-sys via the
    // DEP_BPF_INCLUDE env var (it has `links = "bpf"`); we depend on it directly
    // under the af-xdp feature precisely so this is visible here.
    let bpf_inc = env::var("DEP_BPF_INCLUDE").unwrap_or_default();
    if bpf_inc.is_empty() {
        println!(
            "cargo:warning=DEP_BPF_INCLUDE not set; relying on system bpf headers. \
             Ensure libbpf-sys is a dependency under the af-xdp feature."
        );
    }

    let mut cmd = Command::new(&clang);
    cmd.args(["-O2", "-g", "-Wall", "-Werror", "-target", "bpf", "-c"]);
    if !bpf_inc.is_empty() {
        cmd.arg(format!("-I{bpf_inc}"));
    }
    // `-target bpf` does not pull the host's arch-specific uapi headers, so
    // `<asm/types.h>` (reached via <linux/bpf.h>) is not found. Add the
    // multiarch include dir (e.g. /usr/include/x86_64-linux-gnu) so it resolves.
    match arch_include() {
        Some(arch_inc) => {
            cmd.arg(format!("-I{arch_inc}"));
        }
        None => println!(
            "cargo:warning=could not locate the arch uapi include dir (asm/types.h); \
             if clang reports it missing, install linux-libc-dev for your arch."
        ),
    }
    cmd.arg(&src).arg("-o").arg(&obj);

    let status = cmd.status().unwrap_or_else(|e| {
        panic!(
            "failed to invoke `{clang}` to build {} ({e}).\n\
             The `af-xdp` feature requires clang/llvm and the Linux uapi headers.\n\
             Install them (e.g. `apt-get install clang llvm linux-libc-dev`) or set \
             CLANG to the compiler path.",
            src.display()
        )
    });
    if !status.success() {
        panic!(
            "clang failed to compile {} (exit {status}). See output above.",
            src.display()
        );
    }

    println!("cargo:rerun-if-env-changed=CLANG");
    println!("cargo:rerun-if-env-changed=DEP_BPF_INCLUDE");
}

/// Locate the architecture-specific uapi include dir (where `asm/types.h`
/// lives). Prefers the C compiler's multiarch answer; falls back to the
/// cargo TARGET arch, then the non-multiarch location. Only returns a path
/// that actually contains `asm/types.h`.
fn arch_include() -> Option<String> {
    use std::path::Path;
    let has = |p: &str| Path::new(&format!("{p}/asm/types.h")).exists();
    // Debian/Ubuntu multiarch: `cc -print-multiarch` -> e.g. "x86_64-linux-gnu".
    let cc = env::var("CC").unwrap_or_else(|_| "cc".to_string());
    if let Ok(out) = Command::new(&cc).arg("-print-multiarch").output() {
        if out.status.success() {
            let triple = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !triple.is_empty() {
                let p = format!("/usr/include/{triple}");
                if has(&p) {
                    return Some(p);
                }
            }
        }
    }
    // Fallback: arch from TARGET ("x86_64-unknown-linux-gnu" -> "x86_64").
    if let Ok(target) = env::var("TARGET") {
        if let Some(arch) = target.split('-').next() {
            let p = format!("/usr/include/{arch}-linux-gnu");
            if has(&p) {
                return Some(p);
            }
        }
    }
    // Last resort: the non-multiarch location.
    if has("/usr/include") {
        return Some("/usr/include".to_string());
    }
    None
}
