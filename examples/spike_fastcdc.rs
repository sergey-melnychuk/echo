//! Stage 0 spike, fastcdc 5: chunk a 10 MiB file with StreamCDC, edit one
//! byte in the middle, re-chunk, and count how many chunks change.
//!
//! Throwaway code. Findings go to NOTES.md.

use std::collections::HashSet;
use std::io::Cursor;

use fastcdc::v2020::StreamCDC;

fn chunks(data: &[u8], min: usize, avg: usize, max: usize) -> Vec<(u64, usize, blake3::Hash)> {
    StreamCDC::new(Cursor::new(data), min, avg, max)
        .map(|c| {
            let c = c.unwrap();
            (c.offset, c.length, blake3::hash(&c.data))
        })
        .collect()
}

fn xorshift(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn main() {
    let size = 10 * 1024 * 1024;
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut data = Vec::with_capacity(size);
    while data.len() < size {
        data.extend_from_slice(&xorshift(&mut seed).to_le_bytes());
    }
    let mut edited = data.clone();
    edited[size / 2] ^= 0xff;
    let mut inserted = data.clone();
    inserted.insert(size / 3, 0x42); // shifts everything after by one byte

    for (min, avg, max) in [
        (16usize << 10, 64usize << 10, 256usize << 10),
        (8 << 10, 32 << 10, 128 << 10),
    ] {
        let a = chunks(&data, min, avg, max);
        let b = chunks(&edited, min, avg, max);
        let c = chunks(&inserted, min, avg, max);
        let set_a: HashSet<_> = a.iter().map(|x| x.2).collect();
        let new_b = b.iter().filter(|x| !set_a.contains(&x.2)).count();
        let new_c = c.iter().filter(|x| !set_a.contains(&x.2)).count();
        let lens: Vec<usize> = a.iter().map(|x| x.1).collect();
        println!(
            "min {}K avg {}K max {}K: {} chunks, min len {}, max len {}, mean {}; one-byte edit -> {} new chunks; one-byte insert -> {} new chunks",
            min >> 10,
            avg >> 10,
            max >> 10,
            a.len(),
            lens.iter().min().unwrap(),
            lens.iter().max().unwrap(),
            lens.iter().sum::<usize>() / lens.len(),
            new_b,
            new_c
        );
        assert!(new_b <= 3);
        assert_eq!(a.iter().map(|x| x.1).sum::<usize>(), size);
    }
    // Determinism: the same input yields the same boundaries.
    assert_eq!(
        chunks(&data, 16 << 10, 64 << 10, 256 << 10),
        chunks(&data, 16 << 10, 64 << 10, 256 << 10)
    );
    println!("OK");
}
