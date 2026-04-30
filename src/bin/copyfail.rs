#![no_std]
#![no_main]

use copyfail_rs::{check_kernel, Error};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe {
        libc::syscall(libc::SYS_exit_group, 134);
    }
    loop {}
}

const USAGE: &[u8] = b"copyfail-rs (CVE-2026-31431)\n\
Usage:\n  copyfail --check\n  copyfail --mode exploit --vector <su|passwd|pam|auto>\n  copyfail --mode detect  --scan|--check|--watch|--hunt\n  copyfail --help\n";

#[no_mangle]
pub extern "C" fn main(argc: i32, argv: *const *const u8) -> i32 {
    let args = unsafe { Args::parse(argc, argv) };
    match args.cmd {
        Cmd::Check => run_check(),
        Cmd::Exploit => run_exploit_stub(),
        Cmd::Detect => run_detect_stub(),
        Cmd::Help => { write_stderr(USAGE); 0 }
        Cmd::Bad => { write_stderr(USAGE); 2 }
    }
}

enum Cmd { Check, Exploit, Detect, Help, Bad }

struct Args { cmd: Cmd }

impl Args {
    unsafe fn parse(argc: i32, argv: *const *const u8) -> Args {
        if argc < 2 {
            return Args { cmd: Cmd::Help };
        }
        let mut cmd = Cmd::Bad;
        let mut i: isize = 1;
        while (i as i32) < argc {
            let a = *argv.offset(i);
            if cstr_eq(a, b"--check\0") {
                cmd = Cmd::Check;
            } else if cstr_eq(a, b"--help\0") || cstr_eq(a, b"-h\0") {
                cmd = Cmd::Help;
            } else if cstr_eq(a, b"--mode\0") {
                i += 1;
                if (i as i32) >= argc { return Args { cmd: Cmd::Bad }; }
                let m = *argv.offset(i);
                if cstr_eq(m, b"exploit\0") {
                    cmd = Cmd::Exploit;
                } else if cstr_eq(m, b"detect\0") {
                    cmd = Cmd::Detect;
                } else {
                    return Args { cmd: Cmd::Bad };
                }
            }
            i += 1;
        }
        Args { cmd }
    }
}

unsafe fn cstr_eq(p: *const u8, b: &[u8]) -> bool {
    let mut i = 0;
    loop {
        let c = *p.add(i);
        if i >= b.len() { return c == 0 && b.last() == Some(&0); }
        if c != b[i] { return false; }
        if c == 0 && b[i] == 0 { return true; }
        i += 1;
    }
}

fn run_check() -> i32 {
    match check_kernel() {
        Ok(s) => {
            write_stderr(b"copyfail-rs --check\n");
            write_stderr(b"  kernel: ");
            write_stderr(&s.osrelease[..s.osrelease_len]);
            write_stderr(b"\n  algif_aead module:        ");
            write_stderr(if s.algif_aead_module { b"present" } else { b"not in /proc/modules (may be builtin)" });
            write_stderr(b"\n  authencesn template:      ");
            write_stderr(if s.authencesn_template { b"present in /proc/crypto" } else { b"NOT present in /proc/crypto" });
            write_stderr(b"\n  verdict:                  deferred to S6 (detection rules)\n");
            0
        }
        Err(_) => {
            write_stderr(b"--check: failed to read /proc files\n");
            1
        }
    }
}

fn run_exploit_stub() -> i32 {
    write_stderr(b"--mode exploit: not implemented in S1 (foundation only)\n");
    err_code(Error::NotImplemented)
}

fn run_detect_stub() -> i32 {
    write_stderr(b"--mode detect: not implemented in S1 (foundation only)\n");
    err_code(Error::NotImplemented)
}

fn err_code(_e: Error) -> i32 { 3 }

fn write_stderr(b: &[u8]) {
    unsafe { libc::write(2, b.as_ptr() as *const _, b.len()); }
}
