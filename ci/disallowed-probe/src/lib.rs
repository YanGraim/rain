//! One call per `disallowed-methods` entry. Never executed, only linted.
//! Each line must produce exactly one `disallowed method` error.

use std::fs::{self, DirBuilder, File, FileTimes, OpenOptions, Permissions};
use std::io;
use std::path::Path;
use std::time::SystemTime;

pub fn portable(p: &Path, perm: Permissions, f: &File) -> io::Result<()> {
    fs::write(p, b"")?;
    fs::remove_file(p)?;
    fs::remove_dir(p)?;
    fs::remove_dir_all(p)?;
    fs::rename(p, p)?;
    fs::create_dir(p)?;
    fs::create_dir_all(p)?;
    fs::copy(p, p)?;
    fs::hard_link(p, p)?;
    #[allow(deprecated)]
    fs::soft_link(p, p)?;
    fs::set_permissions(p, perm.clone())?;
    fs::set_times(p, FileTimes::new())?;
    File::create(p)?;
    File::create_new(p)?;
    let _ = File::options();
    f.set_len(0)?;
    f.set_permissions(perm)?;
    f.set_times(FileTimes::new())?;
    f.set_modified(SystemTime::now())?;
    let _ = OpenOptions::new();
    DirBuilder::new().create(p)?;
    let _ = std::process::Command::new("true");
    Ok(())
}

#[cfg(unix)]
pub fn unix(p: &Path, f: &File) -> io::Result<()> {
    std::os::unix::fs::symlink(p, p)?;
    std::os::unix::fs::chown(p, None, None)?;
    std::os::unix::fs::lchown(p, None, None)?;
    std::os::unix::fs::fchown(f, None, None)?;
    std::os::unix::fs::chroot(p)?;
    Ok(())
}

pub fn net() -> io::Result<()> {
    let _ = std::net::TcpStream::connect("127.0.0.1:1")?;
    let _ = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let _ = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(())
}
