use matcher_rs::{
    credman::{CredmanApi, CredmanApiImpl},
    internal_start,
};
use std::ffi::{CString};

fn main() {
    if let Err(err) = internal_start() {
        let mut credman = CredmanApiImpl {};
        credman.add_string_id_entry(
            c"Error",
            None,
            Some(c"Error"),
            Some(&CString::new(err.to_string()).unwrap()),
            None,
            None,
        );
    }
}
