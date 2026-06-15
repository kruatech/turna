//! cargo bench -p proto-stun

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

const MAGIC: u32 = 0x2112A442;

fn stun_pkt(n_attrs: usize) -> Vec<u8> {
    let mut p = vec![0u8; 20];
    p[0] = 0x00;
    p[1] = 0x01;
    p[4..8].copy_from_slice(&MAGIC.to_be_bytes());
    #[allow(clippy::needless_range_loop)]
    for i in 8..20 {
        p[i] = i as u8;
    }
    for _ in 0..n_attrs {
        p.extend_from_slice(&[0x00, 0x06, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF]);
    }
    let bl = (p.len() - 20) as u16;
    p[2] = (bl >> 8) as u8;
    p[3] = bl as u8;
    p
}

fn channel_pkt(sz: usize) -> Vec<u8> {
    let mut p = Vec::with_capacity(4 + sz + 3);
    p.extend_from_slice(&0x4001u16.to_be_bytes());
    p.extend_from_slice(&(sz as u16).to_be_bytes());
    p.extend(std::iter::repeat_n(0xABu8, sz));
    while p.len() % 4 != 0 {
        p.push(0);
    }
    p
}

fn classify(data: &[u8]) -> u8 {
    if data.len() < 4 {
        return 0;
    }
    let f = u16::from_be_bytes([data[0], data[1]]);
    if (0x4000..=0x7FFF).contains(&f) {
        return 1;
    }
    if data.len() >= 20
        && data[0] & 0xC0 == 0
        && u32::from_be_bytes([data[4], data[5], data[6], data[7]]) == MAGIC
    {
        return 2;
    }
    0
}

fn bench_classify(c: &mut Criterion) {
    let s = stun_pkt(0);
    let ch = channel_pkt(160);
    let mut g = c.benchmark_group("classify");
    g.bench_function("stun", |b| b.iter(|| classify(black_box(&s))));
    g.bench_function("channel", |b| b.iter(|| classify(black_box(&ch))));
    g.finish();
}

fn bench_find_attr(c: &mut Criterion) {
    let mut g = c.benchmark_group("find_attr");
    for n in [1, 5, 10, 20] {
        let p = stun_pkt(n);
        g.bench_with_input(BenchmarkId::from_parameter(n), &p, |b, p| {
            b.iter(|| {
                let body = &p[20..];
                let mut off = 0;
                while off + 4 <= body.len() {
                    let al = u16::from_be_bytes([body[off + 2], body[off + 3]]) as usize;
                    if off + 4 + al > body.len() {
                        break;
                    }
                    black_box(&body[off + 4..off + 4 + al]);
                    off += 4 + al + ((4 - (al % 4)) % 4);
                }
            })
        });
    }
    g.finish();
}

criterion_group!(benches, bench_classify, bench_find_attr);
criterion_main!(benches);
