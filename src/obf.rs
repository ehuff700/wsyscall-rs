use crate::SALT;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
/// Custom wrapper struct for a 32-bit dbj2 hash which is required as the input for some functions.
pub struct Hash(u32);
impl Hash {
    /// Creates a new `Hash`
    pub const fn new(hash: u32) -> Self {
        Self(hash)
    }
}

#[macro_export]
/// Converts a string literal (or ident) into a u16 slice and hashes it using a custom implementation of dbj2.
macro_rules! hash {
    ($item:literal) => {{
        const U8_SLICE: &[u8] = $item.as_bytes();
        const SLICE: &[u16] = $crate::w!(U8_SLICE);
        const HASH: u32 = $crate::obf::hash_with_salt_u16(SLICE);
        $crate::obf::Hash::new(HASH)
    }};
    ($item:ident) => {{
        const U8_SLICE: &[u8] = stringify!($item).as_bytes();
        const SLICE: &[u16] = $crate::w!(U8_SLICE);
        const HASH: u32 = $crate::obf::hash_with_salt_u16(SLICE);
        $crate::obf::Hash::new(HASH)
    }};
}

#[inline]
pub const fn hash_with_salt_u16(input: &[u16]) -> u32 {
    let mut index = 0;
    let mut hash = SALT;
    while index < input.len() {
        hash = (hash << 5)
            .wrapping_add(hash)
            .wrapping_add(input[index] as u32);
        index += 1;
    }
    hash
}

#[inline]
pub const fn hash_with_salt_u8(input: &[u8]) -> u32 {
    let mut index = 0;
    let mut hash = SALT;
    while index < input.len() {
        hash = (hash << 5)
            .wrapping_add(hash)
            .wrapping_add(input[index] as u32);
        index += 1;
    }
    hash
}
/// Converts a UTF-8 encoded string to a UTF-16 encoded slice.
///
/// Pulled from the `windows-sys` crate with a few modifications.
#[macro_export]
macro_rules! w {
    ($s:literal) => {{
        const INPUT_SLICE: &[u8] = $s.as_bytes();
        $crate::w!(INPUT_SLICE)
    }};
    ($s:expr) => {{
        const OUTPUT_LEN: usize = $crate::obf::utf16_len($s);
        const OUTPUT: &[u16; OUTPUT_LEN] = {
            let mut buffer = [0; OUTPUT_LEN];
            let mut input_pos = 0;
            let mut output_pos = 0;
            while let Some((mut code_point, new_pos)) = $crate::obf::decode_utf8_char($s, input_pos)
            {
                input_pos = new_pos;
                if code_point <= 0xffff {
                    buffer[output_pos] = code_point as u16;
                    output_pos += 1;
                } else {
                    code_point -= 0x10000;
                    buffer[output_pos] = 0xd800 + (code_point >> 10) as u16;
                    output_pos += 1;
                    buffer[output_pos] = 0xdc00 + (code_point & 0x3ff) as u16;
                    output_pos += 1;
                }
            }
            &{ buffer }
        };
        OUTPUT
    }};
}

#[macro_export]
/// Creates a wide string from a UTF-8 encoded slice.
///
/// This widestring is returned as a `WindowsStr` type, and is null terminated (and thus safe to use for WinAPIs accepting a *const u16).
macro_rules! widestr {
    ($s:literal) => {{
        const INPUT_SLICE: &[u8] = $s.as_bytes();
        const OUTPUT_LEN: usize = $crate::obf::utf16_len(INPUT_SLICE) + 1; // +1 for null terminator
        const OUTPUT: &[u16; OUTPUT_LEN] = {
            let mut buffer = [0; OUTPUT_LEN];
            let mut input_pos = 0;
            let mut output_pos = 0;
            while let Some((mut code_point, new_pos)) =
                $crate::obf::decode_utf8_char(INPUT_SLICE, input_pos)
            {
                input_pos = new_pos;
                if code_point <= 0xffff {
                    buffer[output_pos] = code_point as u16;
                    output_pos += 1;
                } else {
                    code_point -= 0x10000;
                    buffer[output_pos] = 0xd800 + (code_point >> 10) as u16;
                    output_pos += 1;
                    buffer[output_pos] = 0xdc00 + (code_point & 0x3ff) as u16;
                    output_pos += 1;
                }
            }
            &{ buffer }
        };
        // SAFETY:
        // This function translates valid utf-8 bytes to utf-16, therefore the resulting slice will be valid utf-16.
        unsafe { $crate::wintypes::WindowsStr::from_utf16_unchecked(OUTPUT) }
    }};
}
#[doc(hidden)]
pub const fn decode_utf8_char(bytes: &[u8], mut pos: usize) -> Option<(u32, usize)> {
    if bytes.len() == pos {
        return None;
    }
    let ch = bytes[pos] as u32;
    pos += 1;
    if ch <= 0x7f {
        return Some((ch, pos));
    }
    if (ch & 0xe0) == 0xc0 {
        if bytes.len() - pos < 1 {
            return None;
        }
        let ch2 = bytes[pos] as u32;
        pos += 1;
        if (ch2 & 0xc0) != 0x80 {
            return None;
        }
        let result: u32 = ((ch & 0x1f) << 6) | (ch2 & 0x3f);
        if result <= 0x7f {
            return None;
        }
        return Some((result, pos));
    }
    if (ch & 0xf0) == 0xe0 {
        if bytes.len() - pos < 2 {
            return None;
        }
        let ch2 = bytes[pos] as u32;
        pos += 1;
        let ch3 = bytes[pos] as u32;
        pos += 1;
        if (ch2 & 0xc0) != 0x80 || (ch3 & 0xc0) != 0x80 {
            return None;
        }
        let result = ((ch & 0x0f) << 12) | ((ch2 & 0x3f) << 6) | (ch3 & 0x3f);
        if result <= 0x7ff || (0xd800 <= result && result <= 0xdfff) {
            return None;
        }
        return Some((result, pos));
    }
    if (ch & 0xf8) == 0xf0 {
        if bytes.len() - pos < 3 {
            return None;
        }
        let ch2 = bytes[pos] as u32;
        pos += 1;
        let ch3 = bytes[pos] as u32;
        pos += 1;
        let ch4 = bytes[pos] as u32;
        pos += 1;
        if (ch2 & 0xc0) != 0x80 || (ch3 & 0xc0) != 0x80 || (ch4 & 0xc0) != 0x80 {
            return None;
        }
        let result =
            ((ch & 0x07) << 18) | ((ch2 & 0x3f) << 12) | ((ch3 & 0x3f) << 6) | (ch4 & 0x3f);
        if result <= 0xffff || 0x10ffff < result {
            return None;
        }
        return Some((result, pos));
    }
    None
}

#[doc(hidden)]
pub const fn utf16_len(bytes: &[u8]) -> usize {
    let mut pos = 0;
    let mut len = 0;
    while let Some((code_point, new_pos)) = decode_utf8_char(bytes, pos) {
        pos = new_pos;
        len += if code_point <= 0xffff { 1 } else { 2 };
    }
    len
}

impl core::ops::Deref for Hash {
    type Target = u32;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl core::fmt::Display for Hash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use crate::wintypes::WindowsStr;

    use super::*;
    use alloc::{string::ToString, vec::Vec};

    extern crate std;

    #[test]
    fn test_obf() {
        let hash = hash!("Hello World");
        let expected_hash = hash!("Hello World");
        assert_eq!(hash, expected_hash);
        std::println!("Calculated hash: {}", hash);
        let hash_2 = hash!("Another string");
        let expected_hash_2 = hash!("Another string");
        assert_eq!(hash_2, expected_hash_2);
        assert_ne!(hash_2, expected_hash);
    }

    #[test]
    // Need to make sure no trailing \0 is added
    fn test_w_macro() {
        let w_hello_world = w!("Hello World");
        let expected_w_hello_world: [u16; 11] = [
            0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64,
        ];
        assert_eq!(w_hello_world, &expected_w_hello_world);
    }

    #[test]
    fn test_hash_with_slice() {
        let input = "Hello World";
        let u8_bytes = input.as_bytes();
        let u16_bytes = input.encode_utf16().collect::<Vec<u16>>();
        let expected_hash = hash_with_salt_u16(u16_bytes.as_slice());
        assert_eq!(hash_with_salt_u8(u8_bytes), expected_hash);
    }

    #[test]
    fn test_widestr_macro() {
        const W: &WindowsStr = widestr!("Hello World");
        assert_eq!(W.to_string(), "Hello World\0");
    }
}
