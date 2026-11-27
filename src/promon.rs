/* warning: your eyes may burn while reading this code, shitcode. */
use std::io;

use crate::crypto::chacha8::ChaCha8;
use crate::crypto::fletcher64;

/* method works in v8/v9 versions
 * search for: 1F 20 03 D5 ?? ?? ?? 50 1F 20 03 D5 ?? ?? ?? 10
 * result is always smth like this: (regs not always same)
 * nop
 * adr x8, ncc_end
 * nop
 * adr x9, ncc_start

 * or another easier method:
 * decompile the first constructor in init array (takes a LOT of time)
 * scroll until you see a chacha8 call that looks like that:
 * x12_3 = sub_624b00(ncc_address, ncc_address, size, &nonce, &key);
 * for (i = 0; i != 0x20; i += 1)
 *      (&var_468)[i] = 0; // wipe key
 * just from this call you can get everything, just xref ncc_address and it will show this:
 * void* x12 = &data_6a8246; // ncc end
 * char* ncc_address = &data_6a8080; // ncc start
 * and you don't need to get key because the script automatically gets it
 * all the nonces are in that &nonce array btw
 */

const NCC_ADDRESS: usize = 0x6a8080;
const NCC_END: usize = 0x6a8246;
const NCC_SIZE: usize = (NCC_END - NCC_ADDRESS + 1) as usize;

// All these are from that nonce array in the &nonce array from the chacha8 call in the constructor except TEXT
const NCC_NONCE: [u8; 8] = [0x74, 0x08, 0x19, 0xeb, 0xc4, 0x09, 0x9f, 0x1a];
const GCC_NONCE: [u8; 8] = [0xee, 0x39, 0x65, 0x57, 0x20, 0x6a, 0x8f, 0xe6];
const TEXT_NONCE: [u8; 8] = [0x81, 0x74, 0x0e, 0x98, 0x06, 0x6f, 0x9c, 0xa3];
const RODATA_NONCE: [u8; 8] = [0xd1, 0xae, 0xc9, 0xc4, 0xac, 0x18, 0xd3, 0x96];

const DESCRIPTOR_ADDRESS: usize = NCC_ADDRESS + 1;
const TEXT_DESCRIPTOR_VA: usize = 0x6a6f78;

#[repr(C)]
struct Section {
    address: u64,
    size: u64,
}

impl Section {
    fn read(lib: &[u8], offset: usize) -> io::Result<Self> {
        Ok(Self {
            address: u64::from_le_bytes(read(lib, offset)?),
            size: u64::from_le_bytes(read(lib, offset + 8)?),
        })
    }

    fn range(&self, lib: &[u8]) -> io::Result<std::ops::Range<usize>> {
        let addr = resolve_address(lib, self.address as usize)?;
        let end = addr.checked_add(self.size as usize)
            .ok_or(io::ErrorKind::InvalidData)?;

        Ok(addr..end)
    }
}

#[repr(C)]
struct DescriptorTable {
    constructor_address: i64,
    build_id: Section,
    text: Section,
    gcc: Section,
    ncc: Section,
    rodata: Section,
}

impl DescriptorTable {
    fn read(lib: &[u8], address: usize) -> io::Result<Self> {
        let addr = resolve_address(lib, address)?;

        Ok(Self {
            constructor_address: i64::from_le_bytes(read(lib, addr)?),
            build_id: Section::read(lib, addr + 0x08)?,
            text: Section::read(lib, addr + 0x18)?,
            gcc: Section::read(lib, addr + 0x28)?,
            ncc: Section::read(lib, addr + 0x38)?,
            rodata: Section::read(lib, addr + 0x48)?,
        })
    }
}

// this sht is vibecoded as helllllll, im lazy
fn read<const N: usize>(lib: &[u8], offset: usize) -> io::Result<[u8; N]> {
    lib.get(offset..)
        .and_then(|data| data.get(..N))
        .and_then(|data| data.try_into().ok())
        .ok_or(io::ErrorKind::UnexpectedEof.into())
}

// this sht is vibecoded too
fn resolve_address(lib: &[u8], address: usize) -> io::Result<usize> {
    if read::<6>(lib, 0)? != *b"\x7fELF\x02\x01" {
        return Err(io::ErrorKind::InvalidData.into());
    }

    let phoff = u64::from_le_bytes(read(lib, 0x20)?) as usize;
    let phentsize = u16::from_le_bytes(read(lib, 0x36)?) as usize;
    let phnum = u16::from_le_bytes(read(lib, 0x38)?) as usize;

    for i in 0..phnum {
        let ph = phoff + i * phentsize;

        if u32::from_le_bytes(read(lib, ph)?) != 1 {
            continue;
        }

        let offset = u64::from_le_bytes(read(lib, ph + 0x08)?) as usize;
        let vaddr = u64::from_le_bytes(read(lib, ph + 0x10)?) as usize;
        let filesz = u64::from_le_bytes(read(lib, ph + 0x20)?) as usize;

        if address >= vaddr && address - vaddr < filesz {
            return Ok(offset + (address - vaddr));
        }
    }

    Err(io::ErrorKind::InvalidInput.into())
}

fn read_va<const N: usize>(lib: &[u8], address: usize) -> io::Result<[u8; N]> {
    read(lib, resolve_address(lib, address)?)
}

fn get_ncc_key(size: usize) -> [u8; 32] {
    let key = [(size >> 2) as u8, 0x88, (size ^ 2) as u8, (size >> 1) as u8, ((size >> 3) as u8).wrapping_add(0x54), 0x41, 0x50, size as u8, ((size >> 1) as u8).wrapping_sub(0x32), ((size >> 2) ^ 0x83) as u8, ((size >> 5) ^ 0x34) as u8, ((size >> 1) ^ 0x54) as u8, ((size >> 3) ^ 0x98) as u8, ((size >> 6) ^ 0x11) as u8, 0x11, 0x55];
    let mut result = [0u8; 32];

    result[..16].copy_from_slice(&key);
    result[16..].copy_from_slice(&key);

    result
}

fn get_gcc_key(sum: u64) -> [u8; 32] {
    let key = [(sum >> 7) as u8, 0xc3, ((sum >> 10) as u8).wrapping_add(0x6f), (sum >> 23) as u8, 0x25, (sum >> 5) as u8, ((sum >> 20) ^ 0x54) as u8, 0x46, (sum >> 21) as u8, ((sum >> 15) as u8).wrapping_sub(0x3c), 0x76, (sum >> 1) as u8, ((sum >> 12) ^ 0xd4) as u8, 0x34, (sum >> 9) as u8, 0xa8];
    let mut result = [0u8; 32];

    result[..16].copy_from_slice(&key);
    result[16..].copy_from_slice(&key);

    result
}

fn get_rodata_key(sum: u64) -> [u8; 32] {
    let key = [0x6b, (sum >> 12) as u8, ((sum >> 3) ^ 0xc4) as u8, (sum >> 9) as u8, ((sum >> 18) as u8).wrapping_sub(0x61), 0x61, ((sum >> 22) as u8).wrapping_add(0x56), ((sum >> 19) as u8).wrapping_sub(0x72), 0x6b, ((sum >> 22) & 0x21) as u8, (sum >> 12) as u8, ((sum >> 5) as u8).wrapping_sub(0x44), (sum >> 25) as u8, 0x65, 0x43, 0x84];
    let mut result = [0u8; 32];

    result[..16].copy_from_slice(&key);
    result[16..].copy_from_slice(&key);

    result
}

fn get_text_key(sum: u64, mut key: [u8; 32]) -> [u8; 32] {
    let mask = [(sum >> 14) as u8, 0xab, ((sum >> 9) as u8).wrapping_add(0x0f), (sum >> 1) as u8, 0x11, (sum >> 5) as u8, ((sum >> 20) ^ 0x54) as u8, 0x91, (sum >> 21) as u8, ((sum >> 15) as u8).wrapping_add(0x54), 0x25, (sum >> 23) as u8, ((sum >> 12) ^ 0xe4) as u8, 0x65, (sum >> 10) as u8, 0x09];

    for i in 0..32 {
        key[i] ^= mask[i % 16];
    }

    key
}

fn decrypt_section(lib: &mut [u8], section: &Section, key: &[u8; 32], nonce: &[u8; 8]) -> io::Result<()> {
    let range = section.range(lib)?;
    ChaCha8::new(key, nonce).apply_keystream(&mut lib[range]);

    Ok(())
}

pub fn decrypt(lib: &mut [u8]) -> io::Result<()> {
    let ncc = Section {
        address: NCC_ADDRESS as u64,
        size: NCC_SIZE as u64,
    };

    decrypt_section(lib, &ncc, &get_ncc_key(NCC_SIZE), &NCC_NONCE)?;
    println!("(promon-unpacker) decrypted .ncc!");

    let descriptor = DescriptorTable::read(lib, DESCRIPTOR_ADDRESS)?;
    println!("(promon-unpacker) constructor (unpacked): {:#x}", descriptor.constructor_address.unsigned_abs());

    for (name, section) in [("build_id", &descriptor.build_id), ("text", &descriptor.text), ("gcc", &descriptor.gcc), ("ncc", &descriptor.ncc), ("rodata", &descriptor.rodata)] {
        println!("(promon-unpacker) .{}: {:#x}, size: {:#x}", name, section.address, section.size);
    }

    let data = &lib[descriptor.ncc.range(lib)?];
    let checksum = fletcher64::checksum(data);

    let v1 = checksum & fletcher64::MODULUS;
    let v2 = u32::from_le_bytes(read(data, 0)?) as u64;
    let v3 = (v1 + fletcher64::MODULUS - v2) % fletcher64::MODULUS;

    decrypt_section(lib, &descriptor.gcc, &get_gcc_key(v3), &GCC_NONCE)?;
    println!("(promon-unpacker) decrypted .gcc!");

    decrypt_section(lib, &descriptor.rodata, &get_rodata_key(v1), &RODATA_NONCE)?;
    println!("(promon-unpacker) decrypted .rodata!");

    let salt = read_va(lib, TEXT_DESCRIPTOR_VA + 0x10)?;

    decrypt_section(lib, &descriptor.text, &get_text_key(checksum, salt), &TEXT_NONCE)?;
    println!("(promon-unpacker) decrypted .text!");

    Ok(())
}
