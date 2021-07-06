use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use eddo::gen_keypair;
use rand::rngs::OsRng;

const KB: usize = 1024;

pub fn criterion_benchmark(c: &mut Criterion) {
    let (public, private) = gen_keypair(&mut OsRng);

    {
        let mut group = c.benchmark_group("signing");
        for &size in &[KB, 4 * KB, 16 * KB, 64 * KB, 256 * KB, 1024 * KB] {
            let data = vec![0; size];
            group.throughput(Throughput::Bytes(size as u64));
            group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
                b.iter(|| private.sign(black_box(&data)));
            });
        }
        group.finish();
    }

    {
        let mut group = c.benchmark_group("verification");
        for &size in &[KB, 4 * KB, 16 * KB, 64 * KB, 256 * KB, 1024 * KB] {
            let data = vec![0; size];
            let signature = private.sign(&data);
            group.throughput(Throughput::Bytes(size as u64));
            group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
                b.iter(|| public.verify(black_box(&data), black_box(signature)));
            });
        }
        group.finish();
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
