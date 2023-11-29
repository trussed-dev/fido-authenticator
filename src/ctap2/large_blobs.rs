use ctap_types::{sizes::LARGE_BLOB_MAX_FRAGMENT_LENGTH, Error};
use trussed::{
    client::Client,
    config::MAX_MESSAGE_LENGTH,
    syscall, try_syscall,
    types::{Bytes, Location, Mechanism, Message, PathBuf},
};

use crate::{Result, TrussedRequirements};

const HASH_SIZE: usize = 16;
pub const MIN_SIZE: usize = HASH_SIZE + 1;
// empty CBOR array (0x80) + hash
const EMPTY_ARRAY: &[u8; MIN_SIZE] = &[
    0x80, 0x76, 0xbe, 0x8b, 0x52, 0x8d, 0x00, 0x75, 0xf7, 0xaa, 0xe9, 0x8d, 0x6f, 0xa5, 0x7a, 0x6d,
    0x3c,
];
const FILENAME: &[u8] = b"large-blob-array";
const FILENAME_TMP: &[u8] = b".large-blob-array";

pub type Chunk = Bytes<LARGE_BLOB_MAX_FRAGMENT_LENGTH>;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Config {
    /// The location for storing the large-blob array.
    pub location: Location,
    /// The maximum size for the large-blob array including metadata.
    ///
    /// This value must be at least 1024 according to the CTAP2.1 spec.  Without the chunking
    /// extension, it cannot be larger than 1024 because the large-blob array must fit into a
    /// Trussed message.  Therefore, this setting is only available if the chunked feature is
    /// enabled.
    #[cfg(feature = "chunked")]
    pub max_size: usize,
}

impl Config {
    pub fn max_size(&self) -> usize {
        #[cfg(feature = "chunked")]
        {
            self.max_size
        }

        #[cfg(not(feature = "chunked"))]
        {
            MAX_MESSAGE_LENGTH
        }
    }
}

pub fn size<C: TrussedRequirements>(client: &mut C, location: Location) -> Result<usize> {
    Ok(
        try_syscall!(client.entry_metadata(location, PathBuf::from(FILENAME)))
            .map_err(|_| Error::Other)?
            .metadata
            .map(|metadata| metadata.len())
            .unwrap_or_default()
            // If the data is shorter than MIN_SIZE, it is missing or corrupted and we fall back to
            // an empty array which has exactly MIN_SIZE
            .max(MIN_SIZE),
    )
}

pub fn read_chunk<C: TrussedRequirements>(
    client: &mut C,
    location: Location,
    offset: usize,
    length: usize,
) -> Result<Chunk> {
    SelectedStorage::read(client, location, offset, length)
}

pub fn write_chunk<C: TrussedRequirements>(
    client: &mut C,
    state: &mut State,
    location: Location,
    data: &[u8],
) -> Result<()> {
    write_impl::<_, SelectedStorage>(client, state, location, data)
}

pub fn reset<C: TrussedRequirements>(client: &mut C) {
    for location in [Location::Internal, Location::External, Location::Volatile] {
        try_syscall!(client.remove_file(location, PathBuf::from(FILENAME))).ok();
    }
    try_syscall!(client.remove_file(Location::Volatile, PathBuf::from(FILENAME_TMP))).ok();
}

fn write_impl<C, S: Storage<C>>(
    client: &mut C,
    state: &mut State,
    location: Location,
    data: &[u8],
) -> Result<()> {
    // sanity checks
    if state.expected_next_offset + data.len() > state.expected_length {
        return Err(Error::InvalidParameter);
    }

    let mut writer = S::start_write(
        client,
        location,
        state.expected_next_offset,
        state.expected_length,
    )?;
    state.expected_next_offset = writer.extend_buffer(client, data)?;
    if state.expected_next_offset == state.expected_length {
        if writer.validate_checksum(client)? {
            writer.commit(client)
        } else {
            writer.abort(client)?;
            Err(Error::IntegrityFailure)
        }
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct State {
    pub expected_length: usize,
    pub expected_next_offset: usize,
}

trait Storage<C>: Sized {
    fn read(client: &mut C, location: Location, offset: usize, length: usize) -> Result<Chunk>;

    fn start_write(
        client: &mut C,
        location: Location,
        offset: usize,
        expected_length: usize,
    ) -> Result<Self>;

    fn extend_buffer(&mut self, client: &mut C, data: &[u8]) -> Result<usize>;

    fn validate_checksum(&mut self, client: &mut C) -> Result<bool>;

    fn commit(&mut self, client: &mut C) -> Result<()>;

    fn abort(&mut self, client: &mut C) -> Result<()> {
        let _ = client;
        Ok(())
    }
}

#[cfg(not(feature = "chunked"))]
type SelectedStorage = SimpleStorage;
#[cfg(feature = "chunked")]
type SelectedStorage = ChunkedStorage;

// Basic implementation using a file in the volatile storage as a buffer based on the core Trussed
// API.  Maximum size for the entire large blob array: 1024 bytes.
struct SimpleStorage {
    location: Location,
    buffer: Message,
}

impl<C: Client> Storage<C> for SimpleStorage {
    fn read(client: &mut C, location: Location, offset: usize, length: usize) -> Result<Chunk> {
        let result = try_syscall!(client.read_file(location, PathBuf::from(FILENAME)));
        let data = if let Ok(reply) = &result {
            reply.data.as_slice()
        } else {
            EMPTY_ARRAY.as_slice()
        };
        let Some(max_length) = data.len().checked_sub(offset) else {
            return Err(Error::InvalidParameter);
        };
        let length = length.min(max_length);
        let mut buffer = Chunk::new();
        buffer.extend_from_slice(&data[offset..][..length]).unwrap();
        Ok(buffer)
    }

    fn start_write(
        client: &mut C,
        location: Location,
        offset: usize,
        expected_length: usize,
    ) -> Result<Self> {
        let buffer = if offset == 0 {
            Message::new()
        } else {
            try_syscall!(client.read_file(Location::Volatile, PathBuf::from(FILENAME_TMP)))
                .map_err(|_| Error::Other)?
                .data
        };

        // sanity checks
        if expected_length > buffer.capacity() {
            return Err(Error::InvalidLength);
        }
        if buffer.len() != offset {
            return Err(Error::Other);
        }

        Ok(Self { buffer, location })
    }

    fn extend_buffer(&mut self, client: &mut C, data: &[u8]) -> Result<usize> {
        self.buffer
            .extend_from_slice(data)
            .map_err(|_| Error::InvalidParameter)?;
        try_syscall!(client.write_file(
            Location::Volatile,
            PathBuf::from(FILENAME_TMP),
            self.buffer.clone(),
            None
        ))
        .map_err(|_| Error::Other)?;
        Ok(self.buffer.len())
    }

    fn validate_checksum(&mut self, client: &mut C) -> Result<bool> {
        let Some(n) = self.buffer.len().checked_sub(HASH_SIZE) else {
            return Ok(false);
        };
        let mut message = Message::new();
        message.extend_from_slice(&self.buffer[..n]).unwrap();
        let checksum = syscall!(client.hash(Mechanism::Sha256, message)).hash;
        Ok(checksum[..HASH_SIZE] == self.buffer[n..])
    }

    fn commit(&mut self, client: &mut C) -> Result<()> {
        try_syscall!(client.write_file(
            self.location,
            PathBuf::from(FILENAME),
            self.buffer.clone(),
            None
        ))
        .map_err(|_| Error::Other)?;
        try_syscall!(client.remove_file(Location::Volatile, PathBuf::from(FILENAME_TMP))).ok();
        Ok(())
    }
}

#[cfg(feature = "chunked")]
struct ChunkedStorage {
    location: Location,
    expected_length: usize,
    create_file: bool,
}

#[cfg(feature = "chunked")]
impl<C: TrussedRequirements> Storage<C> for ChunkedStorage {
    fn read(client: &mut C, location: Location, offset: usize, length: usize) -> Result<Chunk> {
        debug!("ChunkedStorage::read: offset = {offset}, length = {length}");
        let mut chunk = Chunk::new();
        let file_size = try_syscall!(client.entry_metadata(location, PathBuf::from(FILENAME)))
            .map_err(|_| Error::Other)?
            .metadata
            .map(|metadata| metadata.len())
            .unwrap_or_default();
        if file_size < MIN_SIZE {
            // The stored file is missing or too short, so we fall back to an empty array.
            trace!("Sending empty array instead of missing or corrupted file");
            let start = offset.min(MIN_SIZE);
            let end = (offset + length).min(MIN_SIZE);
            chunk.extend_from_slice(&EMPTY_ARRAY[start..end]).unwrap();
            return Ok(chunk);
        }

        while offset + chunk.len() < offset + length {
            let n = MAX_MESSAGE_LENGTH.min(length - chunk.len());
            let reply = try_syscall!(client.partial_read_file(
                location,
                PathBuf::from(FILENAME),
                offset + chunk.len(),
                n
            ))
            .map_err(|_| Error::Other)?;
            chunk
                .extend_from_slice(&reply.data)
                .map_err(|_| Error::Other)?;
            if offset + chunk.len() >= reply.file_length {
                break;
            }
        }

        trace!("Read chunk with {} bytes", chunk.len());
        Ok(chunk)
    }

    fn start_write(
        _client: &mut C,
        location: Location,
        offset: usize,
        expected_length: usize,
    ) -> Result<Self> {
        debug!(
            "ChunkedStorage::start_write: offset = {offset}, expected_length = {expected_length}"
        );
        let create_file = offset == 0;
        Ok(ChunkedStorage {
            location,
            create_file,
            expected_length,
        })
    }

    fn extend_buffer(&mut self, client: &mut C, data: &[u8]) -> Result<usize> {
        debug!("ChunkedStorage::extend_buffer: |data| = {}", data.len());
        let mut n = 0;
        for chunk in data.chunks(trussed::config::MAX_MESSAGE_LENGTH) {
            trace!("Writing {} bytes", chunk.len());
            let path = PathBuf::from(FILENAME_TMP);
            let mut message = Message::new();
            message.extend_from_slice(chunk).unwrap();
            if self.create_file {
                try_syscall!(client.write_file(self.location, path, message, None)).map_err(
                    |_err| {
                        error!("failed to write initial chunk: {_err:?}");
                        Error::Other
                    },
                )?;
                self.create_file = false;
                n = data.len();
            } else {
                n = try_syscall!(client.append_file(self.location, path, message))
                    .map(|reply| reply.file_length)
                    .map_err(|_err| {
                        error!("failed to append chunk: {_err:?}");
                        Error::Other
                    })?;
            }
        }
        Ok(n)
    }

    fn validate_checksum(&mut self, client: &mut C) -> Result<bool> {
        use sha2::{digest::Digest as _, Sha256};

        debug!("ChunkedStorage::validate_checksum");

        let mut digest = Sha256::new();
        let mut received_hash: Bytes<HASH_SIZE> = Bytes::new();
        let mut bytes_read = 0;

        let (mut chunk, mut len) =
            try_syscall!(client.start_chunked_read(self.location, PathBuf::from(FILENAME_TMP)))
                .map(|reply| (reply.data, reply.len))
                .map_err(|_err| {
                    error!("Failed to read file: {:?}", _err);
                    Error::Other
                })?;
        loop {
            trace!("read chunk: {}", chunk.len());

            let remaining_data = self
                .expected_length
                .saturating_sub(bytes_read)
                .saturating_sub(HASH_SIZE);
            let data_end = remaining_data.min(chunk.len());
            digest.update(&chunk[..data_end]);
            if received_hash
                .extend_from_slice(&chunk[data_end..chunk.len()])
                .is_err()
            {
                return Ok(false);
            }

            bytes_read += chunk.len();
            if bytes_read >= len {
                break;
            }

            (chunk, len) = try_syscall!(client.read_file_chunk())
                .map(|reply| (reply.data, reply.len))
                .map_err(|_err| {
                    error!("Failed to read chunk: {:?}", _err);
                    Error::Other
                })?;
        }

        let actual_hash = digest.finalize();
        Ok(bytes_read == self.expected_length
            && received_hash.as_slice() == &actual_hash[..HASH_SIZE])
    }

    fn commit(&mut self, client: &mut C) -> Result<()> {
        debug!("ChunkedStorage::commit");
        try_syscall!(client.rename(
            self.location,
            PathBuf::from(FILENAME_TMP),
            PathBuf::from(FILENAME)
        ))
        .map_err(|_| Error::Other)?;
        Ok(())
    }

    fn abort(&mut self, client: &mut C) -> Result<()> {
        debug!("ChunkedStorage::abort");
        try_syscall!(client.remove_file(self.location, PathBuf::from(FILENAME_TMP)))
            .map_err(|_| Error::Other)?;
        Ok(())
    }
}
