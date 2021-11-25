#![allow(dead_code)]
#![allow(unused_variables)]

const SBOX: [u8; 256] = [99, 124, 119, 123, 242, 107, 111, 197, 48, 01, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 04, 199, 35, 195, 24, 150, 05, 154, 07, 18, 128, 226, 235, 39, 178, 117, 09, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 00, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 02, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 06, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 08, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 03, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22];

fn main() {
    assert_eq!(shift_rows(&mut [0x8e9f01c6,0x4ddc01c6,0xa15801c6,0xbc9d01c6]),
                               [0x8e9f01c6,0xdc01c64d,0x01c6a158,0xc6bc9d01]);
    assert_eq!(sub_bytes(&mut [0x8e9ff1c6, 0x4ddce1c7, 0xa158d1c8, 0xbc9dc1c9]),
                              [0x19dba1b4, 0xe386f8c6, 0x326a3ee8, 0x655e78dd]);

    // let reversesbox = initialize_aes_sbox(SBOX);
    // println!("{:02x?}", reversesbox);
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

fn encrypt(state: &mut [u32], expkey: [u32;16], rounds: i32){
    let mut keyi: usize = 0;
    add_round_key(state, &expkey[keyi..keyi+4]);
    keyi += 4;
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

fn add_round_key(state: &[u32], expkey: &[u32]){
    unimplemented!();
}

fn sub_bytes(state: &mut [u32]) -> &[u32] {
    let mut result: [u32; 4] = [0; 4];
    for i in 0..4 {
        let bytes = state[i].to_be_bytes();
        result[i] |= (SBOX[bytes[0] as usize] as u32) << 24;
        result[i] |= (SBOX[bytes[1] as usize] as u32) << 16;
        result[i] |= (SBOX[bytes[2] as usize] as u32) << 8;
        result[i] |= SBOX[bytes[3] as usize] as u32;
    }

    for i in 0..4 {
        state[i] = result[i];
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


fn mix_columns(state: &[u32]){
    unimplemented!();
}

/*
fn inv_mix_columns(){

}

fn inv_shift_rows(){

}

fn inv_sub_bytes(){
input[i] = invsbox[input[i]]; // i = 0, 1, ..., 15

}

fn inv_add_round_key(){

}
*/