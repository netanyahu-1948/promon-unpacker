macro_rules! quarter_round {
    ($a:expr, $b:expr, $c:expr, $d:expr) => {
        $a = $a.wrapping_add($b);
        $d = ($d ^ $a).rotate_left(16);
        $c = $c.wrapping_add($d);
        $b = ($b ^ $c).rotate_left(12);
        $a = $a.wrapping_add($b);
        $d = ($d ^ $a).rotate_left(8);
        $c = $c.wrapping_add($d);
        $b = ($b ^ $c).rotate_left(7);
    };
}

pub struct ChaCha8 {
    input: [u32; 16],
    output: [u8; 64],
    offset: usize,
}

impl ChaCha8 {
    const ROUNDS: usize = 8;
    const BLOCK_SIZE: usize = 64;
    
    pub fn new(key: &[u8; 32], nonce: &[u8; 8]) -> Self {
        Self {
            input: [
                // ChaCha8 constant -> expand 32-byte k
                0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,

                // Key
                u32::from_le_bytes(key[0..4].try_into().unwrap()),
                u32::from_le_bytes(key[4..8].try_into().unwrap()),
                u32::from_le_bytes(key[8..12].try_into().unwrap()),
                u32::from_le_bytes(key[12..16].try_into().unwrap()),
                u32::from_le_bytes(key[16..20].try_into().unwrap()),
                u32::from_le_bytes(key[20..24].try_into().unwrap()),
                u32::from_le_bytes(key[24..28].try_into().unwrap()),
                u32::from_le_bytes(key[28..32].try_into().unwrap()),

                // Block Counter
                0, 0,

                // Nonce
                u32::from_le_bytes(nonce[0..4].try_into().unwrap()),
                u32::from_le_bytes(nonce[4..8].try_into().unwrap()),
            ],
            output: [0; Self::BLOCK_SIZE],
            offset: Self::BLOCK_SIZE,
        }
    }

    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        for byte in data {
            if self.offset == Self::BLOCK_SIZE {
                let mut state = self.input;

                for _ in 0..Self::ROUNDS / 2 {
                    quarter_round!(state[0], state[4], state[8], state[12]);
                    quarter_round!(state[1], state[5], state[9], state[13]);
                    quarter_round!(state[2], state[6], state[10], state[14]);
                    quarter_round!(state[3], state[7], state[11], state[15]);

                    quarter_round!(state[0], state[5], state[10], state[15]);
                    quarter_round!(state[1], state[6], state[11], state[12]);
                    quarter_round!(state[2], state[7], state[8], state[13]);
                    quarter_round!(state[3], state[4], state[9], state[14]);
                }

                for (i, word) in state.iter().enumerate() {
                    let word = word.wrapping_add(self.input[i]);
                    self.output[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
                }

                self.input[12] = self.input[12].wrapping_add(1);
                if self.input[12] == 0 {
                    self.input[13] = self.input[13].wrapping_add(1);
                }

                self.offset = 0;
            }

            *byte ^= self.output[self.offset];
            self.offset += 1;
        }
    }
}
