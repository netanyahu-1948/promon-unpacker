pub const MODULUS: u64 = u32::MAX as u64;

pub fn checksum(data: &[u8]) -> u64 {
    let mut low = 0u64;
    let mut high = 0u64;

    for word in data.chunks_exact(4) {
        low = (low + u32::from_le_bytes(word.try_into().unwrap()) as u64) % MODULUS;
        high = (high + low) % MODULUS;
    }

    (high << 32) | low
}
