#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    secure_host_fuzz::os_release(data);
});
