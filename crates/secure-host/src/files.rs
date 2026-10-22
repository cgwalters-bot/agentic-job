//! Reading files that someone else wrote: the hand-back of an agent, an
//! artifact another job uploaded. A name there may be a link to a file
//! the reader should not see, or a pipe that never ends, so nothing is
//! followed and everything is capped.

use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use rustix::fs::{Mode, OFlags};

/// Why a file was not read.
#[derive(Debug)]
pub enum ReadError {
    /// A link, a directory, a pipe or a device.
    NotRegular,
    /// Its size in bytes, which is over the cap.
    TooBig {
        size: u64,
        max: u64,
    },
    Io(io::Error),
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRegular => write!(f, "is not a regular file"),
            Self::TooBig { size, max } => write!(f, "is {size} bytes, over {max}"),
            Self::Io(err) => write!(f, "cannot be read: {err}"),
        }
    }
}

impl std::error::Error for ReadError {}

/// Opens `path` without following a link in its last component and
/// without waiting on a pipe. Links in the directories above it are
/// followed: the caller owns those.
fn open(path: &Path, access: OFlags) -> io::Result<File> {
    let flags = access | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
    Ok(rustix::fs::open(path, flags, Mode::empty())?.into())
}

/// The regular file at `path`, opened to be read in pieces: reading more
/// than `max` bytes from it, which a file still growing can give, fails
/// with [`io::ErrorKind::FileTooLarge`].
#[derive(Debug)]
pub struct Regular {
    file: File,
    size: u64,
    left: u64,
}

impl Regular {
    /// Its size when it was opened.
    pub fn size(&self) -> u64 {
        self.size
    }
}

impl Read for Regular {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // One byte past the cap tells a file that grew from one that ends.
        let room = usize::try_from(self.left.saturating_add(1)).unwrap_or(usize::MAX);
        let room = buf.len().min(room);
        let read = self.file.read(&mut buf[..room])?;
        let read_u64 = u64::try_from(read).unwrap_or(u64::MAX);
        if read_u64 > self.left {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "grew past its cap while it was read",
            ));
        }
        self.left -= read_u64;
        Ok(read)
    }
}

/// Opens the regular file at `path`, if it is at most `max` bytes.
pub fn open_regular(path: &Path, max: u64) -> Result<Regular, ReadError> {
    let file = open(path, OFlags::RDONLY).map_err(|err| {
        // What O_NOFOLLOW gives for a link.
        if err.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) {
            ReadError::NotRegular
        } else {
            ReadError::Io(err)
        }
    })?;
    let meta = file.metadata().map_err(ReadError::Io)?;
    if !meta.is_file() {
        return Err(ReadError::NotRegular);
    }
    if meta.len() > max {
        return Err(ReadError::TooBig {
            size: meta.len(),
            max,
        });
    }
    Ok(Regular {
        file,
        size: meta.len(),
        left: max,
    })
}

/// The content of the regular file at `path`, if it is at most `max` bytes.
pub fn read_regular(path: &Path, max: u64) -> Result<Vec<u8>, ReadError> {
    let mut file = open_regular(path, max)?;
    // The size was read a moment ago and the file may still be growing.
    let mut content = Vec::new();
    match file.read_to_end(&mut content) {
        Ok(_) => Ok(content),
        Err(err) if err.kind() == io::ErrorKind::FileTooLarge => Err(ReadError::TooBig {
            size: max.saturating_add(1),
            max,
        }),
        Err(err) => Err(ReadError::Io(err)),
    }
}

/// Replaces the content of the existing regular file at `path`.
pub fn overwrite_regular(path: &Path, mut content: impl Read) -> io::Result<()> {
    let mut file = open(path, OFlags::WRONLY)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    // Truncated only once it is known to be a regular file.
    file.set_len(0)?;
    io::copy(&mut content, &mut file).map(drop)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    #[test]
    fn reads_only_regular_files_within_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = |name: &str| dir.path().join(name);
        std::fs::write(path("file"), b"12345").unwrap();
        std::fs::create_dir(path("dir")).unwrap();
        symlink(path("file"), path("link")).unwrap();
        symlink("/nonexistent", path("dangling")).unwrap();

        assert_eq!(read_regular(&path("file"), 5).unwrap(), b"12345");
        assert!(matches!(
            read_regular(&path("file"), 4),
            Err(ReadError::TooBig { size: 5, max: 4 })
        ));
        for name in ["dir", "link", "dangling"] {
            assert!(
                matches!(read_regular(&path(name), 99), Err(ReadError::NotRegular)),
                "{name}"
            );
        }
        assert!(matches!(
            read_regular(&path("missing"), 99),
            Err(ReadError::Io(_))
        ));
    }

    #[test]
    fn overwrites_a_file_and_not_what_a_link_names() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        let link = dir.path().join("link");
        std::fs::write(&file, b"a long first content").unwrap();
        symlink(&file, &link).unwrap();

        assert!(overwrite_regular(&link, &b"x"[..]).is_err());
        assert_eq!(std::fs::read(&file).unwrap(), b"a long first content");
        overwrite_regular(&file, &b"short"[..]).unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), b"short");
    }
}
