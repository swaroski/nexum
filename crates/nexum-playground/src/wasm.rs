//! The wasm ABI: the only `unsafe` in this crate. Strings cross the boundary
//! as (pointer, length) into memory allocated by `alloc`; randomness comes
//! from the host's `crypto.getRandomValues` via the `env.fill_random` import.
#![allow(unsafe_code)]

#[link(wasm_import_module = "env")]
unsafe extern "C" {
    /// Fill `len` bytes at `ptr` with cryptographically secure random bytes.
    fn fill_random(ptr: *mut u8, len: usize);
}

fn random(dest: &mut [u8]) {
    // SAFETY: the host writes exactly `dest.len()` bytes into `dest`.
    unsafe { fill_random(dest.as_mut_ptr(), dest.len()) }
}

fn random02(dest: &mut [u8]) -> Result<(), getrandom02::Error> {
    random(dest);
    Ok(())
}
getrandom02::register_custom_getrandom!(random02);

/// getrandom 0.3+/0.4 custom backend (enabled for wasm32 in .cargo/config.toml).
#[unsafe(no_mangle)]
unsafe extern "Rust" fn __getrandom_v03_custom(
    dest: *mut u8,
    len: usize,
) -> Result<(), getrandom::Error> {
    // SAFETY: getrandom guarantees `dest` is valid for `len` bytes.
    random(unsafe { std::slice::from_raw_parts_mut(dest, len) });
    Ok(())
}

/// Allocate `len` bytes for the host to write a UTF-8 input into.
#[unsafe(no_mangle)]
pub extern "C" fn alloc(len: usize) -> *mut u8 {
    let mut v = Vec::<u8>::with_capacity(len);
    let p = v.as_mut_ptr();
    std::mem::forget(v);
    p
}

/// Free memory returned by `alloc` or `evaluate`.
///
/// # Safety
/// `ptr`/`cap` must come from `alloc(cap)` or from `evaluate`'s result.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dealloc(ptr: *mut u8, cap: usize) {
    // SAFETY: per the contract above, this is a Vec allocation of `cap`.
    drop(unsafe { Vec::from_raw_parts(ptr, 0, cap) });
}

/// Evaluate the JSON input at `ptr..ptr+len`. Returns `(out_ptr << 32) | out_len`;
/// the output buffer's capacity equals its length (free with `dealloc`).
///
/// # Safety
/// `ptr..ptr+len` must be initialized memory obtained from `alloc`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn evaluate(ptr: *const u8, len: usize) -> u64 {
    // SAFETY: per the contract above.
    let input = unsafe { std::slice::from_raw_parts(ptr, len) };
    let out = match std::str::from_utf8(input) {
        Ok(s) => crate::evaluate_json(s),
        Err(_) => r#"{"error":"input is not UTF-8"}"#.to_owned(),
    };
    let mut out = out.into_bytes().into_boxed_slice();
    let (p, n) = (out.as_mut_ptr(), out.len());
    std::mem::forget(out);
    ((p as u64) << 32) | n as u64
}
