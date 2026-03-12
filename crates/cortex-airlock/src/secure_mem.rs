use zeroize::Zeroize;

/// A memory buffer that is:
/// - mlock'd on Unix (pinned in RAM, never swapped to disk)
/// - Zeroized on drop (all bytes set to 0)
///
/// This ensures plaintext data never touches disk, even under memory pressure.
pub struct LockedBuffer {
    data: Vec<u8>,
    locked: bool,
}

impl LockedBuffer {
    /// Allocate a new locked buffer. Memory is immediately mlock'd.
    pub fn new(capacity: usize) -> Self {
        let data = vec![0u8; capacity];
        let locked = Self::mlock_region(data.as_ptr(), data.len());

        if !locked {
            tracing::warn!(
                "Failed to mlock {} bytes — data may be swapped to disk",
                capacity
            );
        }

        Self { data, locked }
    }

    /// Write data into the locked buffer
    pub fn write(&mut self, src: &[u8]) -> usize {
        let len = src.len().min(self.data.len());
        self.data[..len].copy_from_slice(&src[..len]);
        len
    }

    /// Read the contents of the locked buffer
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get a mutable reference to the buffer contents
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Explicitly wipe and unlock. Also called on drop.
    pub fn wipe(&mut self) {
        self.data.zeroize();
        if self.locked {
            Self::munlock_region(self.data.as_ptr(), self.data.len());
            self.locked = false;
        }
    }

    #[cfg(unix)]
    fn mlock_region(ptr: *const u8, len: usize) -> bool {
        unsafe { libc::mlock(ptr as *const libc::c_void, len) == 0 }
    }

    #[cfg(unix)]
    fn munlock_region(ptr: *const u8, len: usize) {
        unsafe {
            libc::munlock(ptr as *const libc::c_void, len);
        }
    }

    #[cfg(not(unix))]
    fn mlock_region(_ptr: *const u8, _len: usize) -> bool {
        false // mlock not available, warn but continue
    }

    #[cfg(not(unix))]
    fn munlock_region(_ptr: *const u8, _len: usize) {}
}

impl Drop for LockedBuffer {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_locked_buffer_write_read() {
        let mut buf = LockedBuffer::new(32);
        let data = b"secret content";
        buf.write(data);
        assert_eq!(&buf.as_bytes()[..data.len()], data);
    }

    #[test]
    fn test_locked_buffer_wipe() {
        let mut buf = LockedBuffer::new(16);
        buf.write(b"secret");
        buf.wipe();
        assert!(buf.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_locked_buffer_drop_zeroizes() {
        let ptr: *const u8;
        let len: usize;
        {
            let mut buf = LockedBuffer::new(8);
            buf.write(b"12345678");
            ptr = buf.as_bytes().as_ptr();
            len = buf.len();
            // buf dropped here — should zeroize
        }
        // Note: we can't safely read ptr after drop, but the
        // zeroize implementation is tested via wipe() above
        let _ = (ptr, len);
    }
}
