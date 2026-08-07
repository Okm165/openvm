use core::hint::black_box;
use openvm as _;

use openvm_keccak256::keccak256;

pub fn main() {
    let iterations: u64 = openvm::io::read();
    let mut hash = black_box(keccak256(&vec![]));

    for _ in 0..iterations {
        hash = keccak256(&hash);
    }

    black_box(hash);
}
