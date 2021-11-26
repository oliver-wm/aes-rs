#![allow(dead_code)]
#![allow(unused_variables)]
// https://blog.nindalf.com/posts/implementing-aes/ - credits :)

mod rsa_constants;

const STATEMATRIX: [u8; 16] = [0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15];
const BLOCKSIZE: usize = 16;

struct CipherAES {
    expkey: [u32; 16],
}

fn main() {
    assert_eq!(shift_rows(&mut [0x8e9f01c6,0x4ddc01c6,0xa15801c6,0xbc9d01c6]),
                               [0x8e9f01c6,0xdc01c64d,0x01c6a158,0xc6bc9d01]);
    assert_eq!(sub_bytes(&mut [0x8e9ff1c6, 0x4ddce1c7, 0xa158d1c8, 0xbc9dc1c9]),
                              [0x19dba1b4, 0xe386f8c6, 0x326a3ee8, 0x655e78dd]);
    assert_eq!(mix_columns(&mut [0xdbf201c6,0x130a01c6,0x532201c6,0x455c01c6]),
                                [0x8e9f01c6,0x4ddc01c6,0xa15801c6,0xbc9d01c6]);
}

impl CipherAES {
    fn new(key: &[u8]) -> CipherAES {
        CipherAES { expkey:key_expansion(key) }
    }

    fn encrypt(self, dst: &[u8], src: &[u8]) {
        let mut state: [u32;4] = [0;4];
        pack(state, &src[0..BLOCKSIZE]);
        encrypt_aes(&mut state, self.expkey);
        unpack(&dst[0..BLOCKSIZE], state);
    }

    fn decrypt(self, dst: &[u8], src: &[u8]) {
        let mut state: [u32;4] = [0;4];
        pack(state, &src[0..BLOCKSIZE]);
        decrypt_aes(&mut state, self.expkey);
        unpack(&dst[0..BLOCKSIZE], state);
    }
}

fn key_expansion(key: &[u8]) -> [u32; 16] {
unimplemented!();
}

fn pack(to_pack: [u32; 4], bytes: &[u8]){
unimplemented!();
}

fn unpack(to_pack: &[u8], bytes: [u32; 4]){
unimplemented!();
}

fn initialize_aes_sbox(mut ssbox: [u8; 256]) -> [u8; 256] {
    let mut p: u8 = 1;
    let mut q: u8 = 1;

    let rotl8 = |x: u8, shift: u32| -> u8 {
        (x) << (shift) | (x) >> (8 - (shift))
    };
    /* loop invariant: p * q == 1 in the Galois field */
    loop {
        /* multiply p by 3 */
        p = p ^ (p << 1) ^ (if (p & 0x80) != 0 {0x1B} else {0});

        /* divide q by 3 (equals multiplication by 0xf6) */
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        q ^= if (q & 0x80) != 0 {0x09} else {0};

        /* compute the affine transformation */
        let xformed: u8 = q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4);
        ssbox[p as usize] = xformed ^ 0x63;
        if p == 1 { break; }
    }

    /* 0 is a special case since it has no inverse */
    ssbox[0] = 0x63;

    ssbox
}

fn decrypt_aes(state: &mut [u32], expkey: [u32;16]) {
    let mut keyi: usize = expkey.len() - 4;
    add_round_key(state, &expkey[keyi..keyi+4]);
    keyi -= 4;
    let rounds: usize = expkey.len()/4 - 2;
    for i in 0..rounds {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, &expkey[keyi..keyi+4]);
        keyi -= 4;
        inv_mix_columns(state);
    }
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, &expkey[keyi..keyi+4]);
}

fn encrypt_aes(state: &mut [u32], expkey: [u32;16]){
    let mut keyi: usize = 0;
    add_round_key(state, &expkey[keyi..keyi+4]);
    keyi += 4;
    let rounds: usize = expkey.len() / 4 - 2;
    for i in 0..rounds {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, &expkey[keyi..keyi+4]);
        keyi += 4;
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, &expkey[keyi..keyi+4]);
}

fn add_round_key(state: &mut [u32], key: &[u32]){
    for i in 0..4 {
        state[i] ^= key[i];
    }
}

fn sub_bytes(state: &mut [u32]) -> &[u32] {
    for i in 0..4 {
        let bytes = state[i].to_be_bytes();
        state[i] = 0;
        state[i] |= (rsa_constants::SBOX[bytes[0] as usize] as u32) << 24;
        state[i] |= (rsa_constants::SBOX[bytes[1] as usize] as u32) << 16;
        state[i] |= (rsa_constants::SBOX[bytes[2] as usize] as u32) << 8;
        state[i] |=  rsa_constants::SBOX[bytes[3] as usize] as u32;
    }
    state
}

fn shift_rows(state: &mut [u32]) -> &[u32] {
    for i in 1..4 {
        state[i] = rot_word_left(state[i], i as u32);
    }
    state
}

fn rot_word_left(st: u32, rotate: u32) -> u32 {
    st << (8 * rotate) | st >> (8 * (4 - rotate))
}

fn mix_columns(state: &mut [u32]) -> &[u32] {

    let mixer = |a0: u8,a1: u8,a2: u8,a3: u8| -> (u8, u8, u8, u8) {
        let r0 = (rsa_constants::GMUL2[a0 as usize] ^ rsa_constants::GMUL3[a1 as usize] ^ a2 ^ a3) as u8;
        let r1 = (a0 ^ rsa_constants::GMUL2[a1 as usize] ^ rsa_constants::GMUL3[a2 as usize] ^ a3) as u8;
        let r2 = (a0 ^ a1 ^ rsa_constants::GMUL2[a2 as usize] ^ rsa_constants::GMUL3[a3 as usize]) as u8;
        let r3 = (rsa_constants::GMUL3[a0 as usize] ^ a1 ^ a2 ^ rsa_constants::GMUL2[a3 as usize]) as u8;
        (r0, r1, r2, r3)
    };

    for i in 0..4 {
        let a0 = ((state[0] >> ((3 - i) * 8)) & 0xff) as u8;
        let a1 = ((state[1] >> ((3 - i) * 8)) & 0xff) as u8;
        let a2 = ((state[2] >> ((3 - i) * 8)) & 0xff) as u8;
        let a3 = ((state[3] >> ((3 - i) * 8)) & 0xff) as u8;

        let (r0, r1, r2, r3) = mixer(a0, a1, a2, a3);

        let mask: u32 = !(0xff << (3 - i) * 8);

        state[0] = (state[0] & mask) | ((r0 as u32) << ((3 - i) * 8));
        state[1] = (state[1] & mask) | ((r1 as u32) << ((3 - i) * 8));
        state[2] = (state[2] & mask) | ((r2 as u32) << ((3 - i) * 8));
        state[3] = (state[3] & mask) | ((r3 as u32) << ((3 - i) * 8));
    }
    state
}


fn inv_mix_columns(state: &mut [u32]){
unimplemented!();
}

fn inv_shift_rows(state: &mut [u32]){
unimplemented!();
}

fn inv_sub_bytes(state: &mut [u32]){
unimplemented!();
}

fn inv_add_round_key(state: &mut [u32]){
unimplemented!();
}
