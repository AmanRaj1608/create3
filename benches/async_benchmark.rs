use std::time::Duration;

use create3::{
    generate_salt, generate_salt_multithread, generate_salt_prefix,
    generate_salt_prefix_multithread,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn generate_salt_benchmark(c: &mut Criterion) {
    let prefix = black_box("0000");
    let deployer = black_box(hex::decode("0fC5025C764cE34df352757e82f7B5c4Df39A836").unwrap());

    c.bench_function("single-threaded generate salt", |b| {
        b.iter(|| generate_salt(&deployer, prefix))
    });
}

fn generate_salt_multithread_benchmark(c: &mut Criterion) {
    let prefix = black_box("0000");
    let deployer = black_box(hex::decode("0fC5025C764cE34df352757e82f7B5c4Df39A836").unwrap());

    c.bench_function("multi-threaded generate salt", |b| {
        b.iter(|| generate_salt_multithread(&deployer, prefix, 6))
    });
}

fn generate_salt_prefix_benchmark(c: &mut Criterion) {
    let prefix = black_box("0000");
    let salt_prefix = black_box("my_prefix_");
    let deployer = black_box(hex::decode("0fC5025C764cE34df352757e82f7B5c4Df39A836").unwrap());

    c.bench_function("single-threaded generate salt", |b| {
        b.iter(|| generate_salt_prefix(&deployer, salt_prefix, prefix))
    });
}

fn generate_salt_prefix_multithread_benchmark(c: &mut Criterion) {
    let prefix = black_box("0000");
    let salt_prefix = black_box("my_prefix_");
    let deployer = black_box(hex::decode("0fC5025C764cE34df352757e82f7B5c4Df39A836").unwrap());

    c.bench_function("multi-threaded generate salt", |b| {
        b.iter(|| generate_salt_prefix_multithread(&deployer, salt_prefix, prefix, 6))
    });
}

criterion_group!(
    name = generate_salt_benches;
    config = Criterion::default().measurement_time(Duration::from_secs(15));
    targets = generate_salt_benchmark, generate_salt_multithread_benchmark, generate_salt_prefix_benchmark, generate_salt_prefix_multithread_benchmark
);
criterion_main!(generate_salt_benches);
