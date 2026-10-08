//! Any input gives a task, a job, problems or an error, never a panic.

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn arbitrary_xml(text in "[ -~\n<>/&;=\"']{0,600}") {
        let _ = tasks::task::read(text.as_bytes());
        let _ = tasks::detect(text.as_bytes());
    }

    #[test]
    fn arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..2000)) {
        let _ = tasks::task::read(&data);
        let _ = tasks::job::read(&data);
    }

    #[test]
    fn damaged_jobs(at in 0usize..896, bytes in proptest::collection::vec(any::<u8>(), 1..32), cut in 70usize..896) {
        let mut data = Vec::new();
        let compressed = include_bytes!("fixtures/plaso/wintask.job.gz");
        std::io::Read::read_to_end(&mut common::gzip::Decoder::new(&compressed[..]), &mut data).unwrap();
        for (i, b) in bytes.iter().enumerate() {
            if let Some(slot) = data.get_mut(at + i) {
                *slot = *b;
            }
        }
        data.truncate(cut);
        let _ = tasks::job::read(&data);
    }
}
