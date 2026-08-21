//! Capture file names that are not plain ASCII.
//!
//! On Windows libpcap reads the path in the local code page unless pcap_init has been asked for
//! UTF-8, and that choice is made once for the whole process and cannot be taken back. These
//! tests therefore need a test binary to themselves.
#![cfg(any(not(windows), libpcap_1_10_0))]

use tempfile::TempDir;

use pcap::{Capture, Linktype};

/// "capture", in twenty languages.
const NAMES: &[&str] = &[
    "捕获",          // Chinese
    "キャプチャ",    // Japanese
    "캡처",          // Korean
    "захват",        // Russian
    "σύλληψη",       // Greek
    "التقاط",        // Arabic
    "לכידה",         // Hebrew
    "कैप्चर",          // Hindi
    "ক্যাপচার",         // Bengali
    "பிடிப்பு",       // Tamil
    "క్యాప్చర్",         // Telugu
    "จับภาพ",         // Thai
    "ຈັບພາບ",         // Lao
    "ចាប់យក",         // Khmer
    "ဖမ်းယူ",          // Burmese
    "გადაღება",      // Georgian
    "գրավում",       // Armenian
    "ቀረጻ",           // Amharic
    "upptökuþáttur", // Icelandic
    "yakalayış",     // Turkish
];

#[cfg(not(windows))]
fn use_utf8_paths() {}

#[cfg(windows)]
fn use_utf8_paths() {
    pcap::init(pcap::CharEncoding::Utf8).unwrap();
}

#[test]
fn savefile_round_trip_with_non_ascii_names() {
    use_utf8_paths();

    let dir = TempDir::new().unwrap();

    for name in NAMES {
        let tmpfile = dir.path().join(format!("{name}.pcap"));

        let cap = Capture::dead(Linktype(1)).unwrap();
        let save = cap.savefile(&tmpfile).unwrap();
        drop(save);

        assert!(
            tmpfile.exists(),
            "{name} was not written where it was asked for"
        );

        Capture::from_file(&tmpfile).unwrap();
    }
}
