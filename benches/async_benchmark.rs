use std::time::Duration;

use create3::{generate_salt, generate_salt_async};
use criterion::{black_box, criterion_group, criterion_main, Criterion};


fn generate_salt_benchmark(c: &mut Criterion) {
    let prefix = black_box("0000");
    let deployer = black_box(hex::decode("0fC5025C764cE34df352757e82f7B5c4Df39A836").unwrap());

    c.bench_function("single-threaded generate salt", |b| {
        b.iter(|| generate_salt(&deployer, prefix))
    });
}

fn generate_salt_async_benchmark(c: &mut Criterion) {
    let prefix = black_box("0000");
    let deployer = black_box(hex::decode("0fC5025C764cE34df352757e82f7B5c4Df39A836").unwrap());

    c.bench_function("multi-threaded generate salt", |b| {
        b.iter(|| generate_salt_async(&deployer, prefix))
    });
}

criterion_group!(
    name = benches;   
    config = Criterion::default().measurement_time(Duration::from_secs(15));
    targets = generate_salt_benchmark, generate_salt_async_benchmark
);
criterion_main!(benches);
