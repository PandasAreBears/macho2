use std::io::{self, Read, Seek, SeekFrom};

/// Represents a subset/slice of a readable and seekable source, allowing Read and Seek operations
/// within the boundaries of the defined subset.
pub struct FileSubset<'a, T: Read + Seek> {
    /// The underlying readable and seekable source
    file: &'a mut T,
    /// Start offset of the subset in the source
    start_offset: u64,
    /// Size of the subset in bytes
    size: u64,
    /// Current position within the subset (0 is the start of the subset)
    position: u64,
}

impl<'a, T: Read + Seek> FileSubset<'a, T> {
    /// Create a new FileSubset from any type that implements Read + Seek with the specified range
    pub fn new(file: &'a mut T, start_offset: u64, size: u64) -> io::Result<Self> {
        // Verify the range is valid by checking the source size
        let source_size = file.seek(SeekFrom::End(0))?;
        if start_offset + size > source_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Invalid subset range: offset {} + size {} exceeds source size {}",
                    start_offset, size, source_size
                ),
            ));
        }

        // Position the source at our starting offset
        file.seek(SeekFrom::Start(start_offset))?;

        Ok(Self {
            file,
            start_offset,
            size,
            position: 0,
        })
    }

    /// Get the size of the subset in bytes
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Get the starting offset of the subset in the file
    pub fn start_offset(&self) -> u64 {
        self.start_offset
    }

    /// Get the current position within the subset
    pub fn position(&self) -> u64 {
        self.position
    }

    /// Get the absolute position in the file
    pub fn absolute_position(&self) -> u64 {
        self.start_offset + self.position
    }

    /// Get the underlying source
    pub fn get_source(&mut self) -> &mut T {
        self.file
    }
}

impl<'a, T: Read + Seek> Read for FileSubset<'a, T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Calculate how many bytes we can read
        let remaining = self.size.saturating_sub(self.position);
        if remaining == 0 {
            return Ok(0); // EOF
        }

        // Limit the read to the subset boundary
        let to_read = std::cmp::min(buf.len() as u64, remaining) as usize;
        if to_read == 0 {
            return Ok(0);
        }

        // Read from the source and update our position
        let bytes_read = self.file.read(&mut buf[..to_read])?;
        self.position += bytes_read as u64;
        Ok(bytes_read)
    }
}

impl<'a, T: Read + Seek> Seek for FileSubset<'a, T> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            // From start of the subset
            SeekFrom::Start(offset) => offset,

            // From current position in the subset
            SeekFrom::Current(delta) => {
                let new_pos = self.position as i64 + delta;
                if new_pos < 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Attempted to seek before the start of the subset",
                    ));
                }
                new_pos as u64
            }

            // From end of the subset
            SeekFrom::End(delta) => {
                let new_pos = self.size as i64 + delta;
                if new_pos < 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Attempted to seek before the start of the subset",
                    ));
                }
                new_pos as u64
            }
        };

        // Don't allow seeking past the end of the subset
        if new_pos > self.size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Attempted to seek past the end of the subset (size: {})",
                    self.size
                ),
            ));
        }

        // Calculate the absolute position in the source
        let abs_pos = self.start_offset + new_pos;
        self.file.seek(SeekFrom::Start(abs_pos))?;
        self.position = new_pos;

        Ok(self.position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::io::{Cursor, Write};
    use tempfile::tempdir;

    #[test]
    fn test_file_subset_read() -> io::Result<()> {
        // Create a temp file with some content
        let dir = tempdir()?;
        let file_path = dir.path().join("test_file.txt");
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .open(&file_path)?;

        file.write_all(b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")?;
        file.flush()?;

        // Create a subset from offset 10, size 10
        let mut file = OpenOptions::new().read(true).open(&file_path)?;
        let mut subset = FileSubset::new(&mut file, 10, 10)?;

        // Read the entire subset
        let mut buffer = [0u8; 20];
        let bytes_read = subset.read(&mut buffer)?;

        assert_eq!(bytes_read, 10);
        assert_eq!(&buffer[..bytes_read], b"ABCDEFGHIJ");

        Ok(())
    }

    #[test]
    fn test_file_subset_seek() -> io::Result<()> {
        // Create a temp file with some content
        let dir = tempdir()?;
        let file_path = dir.path().join("test_file.txt");
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .open(&file_path)?;

        file.write_all(b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")?;
        file.flush()?;

        // Create a subset from offset 10, size 10
        let mut file = OpenOptions::new().read(true).open(&file_path)?;
        let mut subset = FileSubset::new(&mut file, 10, 10)?;

        // Test SeekFrom::Start
        subset.seek(SeekFrom::Start(5))?;
        let mut buffer = [0u8; 5];
        subset.read_exact(&mut buffer)?;
        assert_eq!(&buffer, b"FGHIJ");

        // Test SeekFrom::Current
        subset.seek(SeekFrom::Start(0))?;
        subset.seek(SeekFrom::Current(3))?;
        subset.read_exact(&mut buffer[..2])?;
        assert_eq!(&buffer[..2], b"DE");

        // Test SeekFrom::End
        subset.seek(SeekFrom::End(-3))?;
        subset.read_exact(&mut buffer[..3])?;
        assert_eq!(&buffer[..3], b"HIJ");

        Ok(())
    }

    #[test]
    fn test_cursor_subset() -> io::Result<()> {
        // Create an in-memory buffer
        let data = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_vec();
        let mut cursor = Cursor::new(data);

        // Create a subset from offset 10, size 15
        let mut subset = FileSubset::new(&mut cursor, 10, 15)?;

        // Read and verify
        let mut buffer = [0u8; 5];
        subset.read_exact(&mut buffer)?;
        assert_eq!(&buffer, b"ABCDE");

        // Seek and read more
        subset.seek(SeekFrom::Current(5))?;
        subset.read_exact(&mut buffer)?;
        assert_eq!(&buffer, b"KLMNO");

        Ok(())
    }
}
