use core::hint::black_box;

use openvm as _;
use openvm_sha2::Sha256;

const NUM_LEAVES: usize = 1024;
const TREE_DEPTH: usize = 10;

fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(black_box(data));
    hasher.finalize()
}

fn sha256_hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(left);
    combined[32..].copy_from_slice(right);
    sha256_hash(&combined)
}

pub fn main() {
    let mut nodes = [[0u8; 32]; NUM_LEAVES];

    let mut seed: u64 = 0xDEAD_BEEF_CAFE_BABE;
    for i in 0..NUM_LEAVES {
        let bytes = seed.to_le_bytes();
        nodes[i] = black_box(sha256_hash(&bytes));
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    }

    for depth in 0..TREE_DEPTH {
        let level_size = NUM_LEAVES >> (depth + 1);
        for i in 0..level_size {
            let left = nodes[2 * i];
            let right = nodes[2 * i + 1];
            nodes[i] = black_box(sha256_hash_pair(&left, &right));
        }
    }

    black_box(nodes[0]);
}
