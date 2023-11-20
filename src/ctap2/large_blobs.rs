use ctap_types::{sizes::LARGE_BLOB_MAX_FRAGMENT_LENGTH, Error};
use trussed::{
    client::Client,
    syscall, try_syscall,
    types::{Bytes, Location, Mechanism, Message, PathBuf},
};

use crate::Result;

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
    /// This value must be at least 1024 according to the CTAP2.1 spec.  Currently, it must not be
    /// more than 1024 because the large-blob array must fit into a Trussed message.
    pub max_size: usize,
}

pub fn size<C: Client>(client: &mut C, location: Location) -> Result<usize> {
    Ok(
        try_syscall!(client.entry_metadata(location, PathBuf::from(FILENAME)))
            .map_err(|_| Error::Other)?
            .metadata
            .map(|metadata| metadata.len())
            .unwrap_or_default()
            // If the data is shorter than MIN_SIZE, it is missing or corrupted and we fall back to
            // an empty array which has exactly MIN_SIZE
            .min(MIN_SIZE),
    )
}

pub fn read_chunk<C: Client>(
    client: &mut C,
    location: Location,
    offset: usize,
    length: usize,
) -> Result<Chunk> {
    SelectedStorage::read(client, location, offset, length)
}

pub fn write_chunk<C: Client>(
    client: &mut C,
    state: &mut State,
    location: Location,
    data: &[u8],
) -> Result<()> {
    write_impl::<_, SelectedStorage>(client, state, location, data)
}

pub fn reset<C: Client>(client: &mut C) {
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

    let mut writer = S::start_write(client, state.expected_next_offset, state.expected_length)?;
    state.expected_next_offset = writer.extend_buffer(client, data)?;
    if state.expected_next_offset == state.expected_length {
        if writer.validate_checksum(client) {
            writer.commit(client, location)
        } else {
            Err(Error::IntegrityFailure)
        }
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct State {
    pub expected_length: usize,
    pub expected_next_offset: usize,
}

trait Storage<C>: Sized {
    fn read(client: &mut C, location: Location, offset: usize, length: usize) -> Result<Chunk>;

    fn start_write(client: &mut C, offset: usize, expected_length: usize) -> Result<Self>;

    fn extend_buffer(&mut self, client: &mut C, data: &[u8]) -> Result<usize>;

    fn validate_checksum(&mut self, client: &mut C) -> bool;

    fn commit(&mut self, client: &mut C, location: Location) -> Result<()>;
}

type SelectedStorage = SimpleStorage;

// Basic implementation using a file in the volatile storage as a buffer based on the core Trussed
// API.  Maximum size for the entire large blob array: 1024 bytes.
struct SimpleStorage {
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

    fn start_write(client: &mut C, offset: usize, expected_length: usize) -> Result<Self> {
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

        Ok(Self { buffer })
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

    fn validate_checksum(&mut self, client: &mut C) -> bool {
        let Some(n) = self.buffer.len().checked_sub(HASH_SIZE) else {
            return false;
        };
        let mut message = Message::new();
        message.extend_from_slice(&self.buffer[..n]).unwrap();
        let checksum = syscall!(client.hash(Mechanism::Sha256, message)).hash;
        checksum[..HASH_SIZE] == self.buffer[n..]
    }

    fn commit(&mut self, client: &mut C, location: Location) -> Result<()> {
        try_syscall!(client.write_file(
            location,
            PathBuf::from(FILENAME),
            self.buffer.clone(),
            None
        ))
        .map_err(|_| Error::Other)?;
        try_syscall!(client.remove_file(Location::Volatile, PathBuf::from(FILENAME_TMP))).ok();
        Ok(())
    }
}
