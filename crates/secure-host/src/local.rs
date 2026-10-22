//! What on this host a user can connect to: the listening Unix sockets
//! and local TCP ports. The uid boundary covers files and processes; a
//! daemon that listens where any user may connect is on the other side
//! of it all the same.
//!
//! `sandbox check` runs this as the sandbox user (`sandbox probe-local`,
//! from the copy of this program that setup installed) and compares what
//! comes back with what the host is expected to offer.

use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::time::Duration;

use anyhow::{Context, Result};
use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};

const PROC_UNIX: &str = "/proc/net/unix";

const PROC_TCP: &[&str] = &["/proc/net/tcp", "/proc/net/tcp6"];

/// `__SO_ACCEPTCON`: the socket is listening.
const FLAG_LISTENING: u32 = 0x1_0000;

/// The `St` column of a listening TCP socket.
const TCP_LISTEN: &str = "0A";

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// How the prober prints an abstract socket's name, as `/proc` does.
pub const ABSTRACT_PREFIX: char = '@';

/// Something a user connected to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Reached {
    /// A listening socket: a path, or [`ABSTRACT_PREFIX`] and an
    /// abstract name.
    Unix(String),
    /// A datagram socket, named the same way: it can be sent to.
    UnixDatagram(String),
    Tcp(SocketAddr),
}

impl Reached {
    /// One line of the prober's output.
    pub fn parse(line: &str) -> Option<Self> {
        match line.split_once(' ')? {
            ("unix", name) => Some(Self::Unix(name.to_owned())),
            ("unix-dgram", name) => Some(Self::UnixDatagram(name.to_owned())),
            ("tcp", addr) => addr.parse().ok().map(Self::Tcp),
            _ => None,
        }
    }
}

impl std::fmt::Display for Reached {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unix(name) => write!(f, "unix {name}"),
            Self::UnixDatagram(name) => write!(f, "unix-dgram {name}"),
            Self::Tcp(addr) => write!(f, "tcp {addr}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum UnixKind {
    Stream,
    Datagram,
    SeqPacket,
}

impl UnixKind {
    fn socket_type(self) -> SocketType {
        match self {
            Self::Stream => SocketType::STREAM,
            Self::Datagram => SocketType::DGRAM,
            Self::SeqPacket => SocketType::SEQPACKET,
        }
    }
}

/// The named sockets of `/proc/net/unix` that take connections: listening
/// stream and sequenced-packet sockets, and every bound datagram socket.
fn unix_listeners(proc_unix: &str) -> Vec<(UnixKind, String)> {
    let mut found: Vec<(UnixKind, String)> = proc_unix
        .lines()
        .filter_map(|line| {
            // Num RefCount Protocol Flags Type St Inode Path; the path is
            // the rest of the line, and may hold spaces.
            let mut rest = line;
            let mut columns = [""; 7];
            for column in &mut columns {
                rest = rest.trim_start_matches(' ');
                let end = rest.find(' ')?;
                (*column, rest) = rest.split_at(end);
            }
            let name = rest.strip_prefix(' ').filter(|name| !name.is_empty())?;
            let flags = u32::from_str_radix(columns[3], 16).ok()?;
            let listening = flags & FLAG_LISTENING != 0;
            let kind = match (u32::from_str_radix(columns[4], 16).ok()?, listening) {
                (1, true) => UnixKind::Stream,
                (5, true) => UnixKind::SeqPacket,
                (2, _) => UnixKind::Datagram,
                _ => return None,
            };
            Some((kind, name.to_owned()))
        })
        .collect();
    found.sort();
    found.dedup();
    found
}

/// Where to dial each listening TCP socket of a `/proc/net/tcp` or
/// `tcp6` table: its own address, or loopback when it listens on all.
fn tcp_listeners(proc_tcp: &str) -> Vec<SocketAddr> {
    let mut found: Vec<SocketAddr> = proc_tcp
        .lines()
        .filter_map(|line| {
            let mut columns = line.split_whitespace();
            let (local, state) = (columns.nth(1)?, columns.nth(1)?);
            if state != TCP_LISTEN {
                return None;
            }
            let (addr, port) = local.rsplit_once(':')?;
            let port = u16::from_str_radix(port, 16).ok()?;
            // The kernel prints each 32-bit word of the address as the
            // number it is in memory, so its bytes come back the same way.
            let words: Vec<[u8; 4]> = addr
                .as_bytes()
                .chunks(8)
                .map(|word| {
                    let word = std::str::from_utf8(word).ok()?;
                    u32::from_str_radix(word, 16).ok().map(u32::to_ne_bytes)
                })
                .collect::<Option<_>>()?;
            let ip = match words[..] {
                [v4] => IpAddr::V4(Ipv4Addr::from(v4)),
                [a, b, c, d] => {
                    let bytes: [u8; 16] = [a, b, c, d].concat().try_into().ok()?;
                    IpAddr::V6(Ipv6Addr::from(bytes))
                }
                _ => return None,
            };
            Some((ip, port))
        })
        .flat_map(|(ip, port)| {
            let targets = match ip {
                IpAddr::V4(v4) if v4.is_unspecified() => vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
                // A socket on every IPv6 address usually takes IPv4 too.
                IpAddr::V6(v6) if v6.is_unspecified() => vec![
                    IpAddr::V6(Ipv6Addr::LOCALHOST),
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                ],
                ip => vec![ip],
            };
            targets.into_iter().map(move |ip| SocketAddr::new(ip, port))
        })
        .collect();
    found.sort();
    found.dedup();
    found
}

/// Whether this process may connect to the Unix socket `name`.
///
/// An abstract socket has no permissions, so it counts without a try;
/// and a try would miss some, since `/proc` prints the NUL bytes of a
/// padded name as `@` and the name cannot be had back from that. For a
/// path, the socket does not block: a listener with a full queue has
/// still let us in as far as permissions go.
fn connects_unix(kind: UnixKind, name: &str) -> bool {
    if name.starts_with(ABSTRACT_PREFIX) {
        return true;
    }
    let Ok(addr) = SocketAddrUnix::new(name) else {
        return false;
    };
    let flags = SocketFlags::NONBLOCK | SocketFlags::CLOEXEC;
    rustix::net::socket_with(AddressFamily::UNIX, kind.socket_type(), flags, None)
        .and_then(|socket| rustix::net::connect(&socket, &addr))
        .map_or_else(|err| err.kind() == ErrorKind::WouldBlock, |()| true)
}

/// Everything local this process could connect to, in a stable order.
pub fn reachable() -> Result<Vec<Reached>> {
    let proc_unix =
        std::fs::read_to_string(PROC_UNIX).with_context(|| format!("reading {PROC_UNIX}"))?;
    let unix = unix_listeners(&proc_unix)
        .into_iter()
        .filter(|(kind, name)| connects_unix(*kind, name))
        .map(|(kind, name)| match kind {
            UnixKind::Datagram => Reached::UnixDatagram(name),
            UnixKind::Stream | UnixKind::SeqPacket => Reached::Unix(name),
        });
    // A host without IPv6 has no tcp6 table.
    let tcp = PROC_TCP
        .iter()
        .filter_map(|path| std::fs::read_to_string(path).ok())
        .flat_map(|table| tcp_listeners(&table))
        .filter(|addr| TcpStream::connect_timeout(addr, CONNECT_TIMEOUT).is_ok())
        .map(Reached::Tcp);
    let mut found: Vec<Reached> = unix.chain(tcp).collect();
    found.sort();
    found.dedup();
    Ok(found)
}

/// `sandbox probe-local`: one line for each thing reached.
pub fn run() -> Result<()> {
    for reached in reachable()? {
        println!("{reached}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROC_UNIX_SAMPLE: &str = "\
Num       RefCount Protocol Flags    Type St Inode Path
0000000000000000: 00000002 00000000 00010000 0001 01 22740 /run/dbus/system_bus_socket
0000000000000000: 00000003 00000000 00000000 0001 03 31337 /run/dbus/system_bus_socket
0000000000000000: 00000002 00000000 00010000 0001 01  2012 @/tmp/.X11-unix/X0
0000000000000000: 00000002 00000000 00010000 0001 01  2013 @padded@@@@
0000000000000000: 00000002 00000000 00000000 0002 01   915 /run/systemd/journal/dev-log
0000000000000000: 00000002 00000000 00010000 0005 01 18222 /run/udev/control
0000000000000000: 00000002 00000000 00010000 0001 01 40001 /run/a dir/with spaces.sock
0000000000000000: 00000003 00000000 00000000 0001 03 31338
0000000000000000: 00000002 00000000 00000000 0005 01 18223 /run/not-listening
";

    #[test]
    fn unix_sockets_that_take_connections() {
        let found = unix_listeners(PROC_UNIX_SAMPLE);
        let want = [
            (UnixKind::Stream, "/run/a dir/with spaces.sock"),
            (UnixKind::Stream, "/run/dbus/system_bus_socket"),
            (UnixKind::Stream, "@/tmp/.X11-unix/X0"),
            (UnixKind::Stream, "@padded@@@@"),
            (UnixKind::Datagram, "/run/systemd/journal/dev-log"),
            (UnixKind::SeqPacket, "/run/udev/control"),
        ];
        let found: Vec<(UnixKind, &str)> = found
            .iter()
            .map(|(kind, name)| (*kind, name.as_str()))
            .collect();
        assert_eq!(found, want);
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn tcp_listeners_and_where_to_dial_them() {
        let v4 = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0C38 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 1 1 0000000000000000 100 0 0 10 0
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2 1 0000000000000000 100 0 0 10 0
   2: 0400000A:01BB 0100000A:C350 01 00000000:00000000 00:00000000 00000000     0        0 3 1 0000000000000000 100 0 0 10 0
   3: 3500007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 4 1 0000000000000000 100 0 0 10 0
";
        let found: Vec<String> = tcp_listeners(v4).iter().map(ToString::to_string).collect();
        assert_eq!(found, ["127.0.0.1:22", "127.0.0.1:3128", "127.0.0.53:53"]);

        let v6 = "\
  sl  local_address                         remote_address                        st
   0: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 0A
   1: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A
";
        let found: Vec<String> = tcp_listeners(v6).iter().map(ToString::to_string).collect();
        assert_eq!(found, ["127.0.0.1:8080", "[::1]:631", "[::1]:8080"]);
    }

    #[test]
    fn output_lines_round_trip() {
        let cases = [
            Reached::Unix("/run/a dir/x.sock".into()),
            Reached::Unix("@abstract".into()),
            Reached::UnixDatagram("@14028884306257329759".into()),
            Reached::Tcp("127.0.0.1:3128".parse().unwrap()),
            Reached::Tcp("[::1]:631".parse().unwrap()),
        ];
        for reached in cases {
            assert_eq!(Reached::parse(&reached.to_string()), Some(reached.clone()));
        }
        for bad in ["", "unix", "udp 127.0.0.1:53", "tcp nowhere"] {
            assert_eq!(Reached::parse(bad), None, "{bad:?}");
        }
    }

    /// The prober finds and connects to what this test itself listens on.
    #[test]
    fn reaches_our_own_listeners() {
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::net::{SocketAddr as UnixAddr, UnixListener};

        let name = format!("agentic-job-test-{}", std::process::id());
        let addr = UnixAddr::from_abstract_name(&name).unwrap();
        let _unix = UnixListener::bind_addr(&addr).unwrap();
        let tcp = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        // A name padded with NULs cannot be dialed from what /proc
        // prints, and is reported all the same.
        assert!(connects_unix(UnixKind::Stream, "@padded@@@@"));
        assert!(!connects_unix(UnixKind::Stream, "/nonexistent/socket"));
        let found = reachable().unwrap();
        assert!(
            found.contains(&Reached::Unix(format!("@{name}"))),
            "{found:?}"
        );
        assert!(
            found.contains(&Reached::Tcp(tcp.local_addr().unwrap())),
            "{found:?}"
        );
    }
}
