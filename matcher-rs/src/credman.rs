use std::{ffi::CStr, os::raw::c_void};

use crate::bindings::{AddStringIdEntry, GetCredentialsSize, GetRequestBuffer, GetRequestSize, ReadCredentialsBuffer};

pub trait CredmanApi {
    fn get_request_buffer(&self) -> Vec<u8>;
    fn get_registered_data(&self) -> Vec<u8>;
    fn add_string_id_entry(
        &mut self,
        entry_id: &CStr,
        icon: Option<&[u8]>,
        title: Option<&CStr>,
        subtitle: Option<&CStr>,
        disclaimer: Option<&CStr>,
        warning: Option<&CStr>,
    );
}

pub struct CredmanApiImpl;

impl CredmanApi for CredmanApiImpl {
    fn get_request_buffer(&self) -> Vec<u8> {
        let mut size: u32 = 0;
        unsafe {
            GetRequestSize(&mut size);
        }
        let mut r = Vec::new();
        r.resize(size as usize, 0);
        unsafe {
            GetRequestBuffer(r.as_mut_ptr() as *mut c_void);
        }
        return r;
    }
    fn get_registered_data(&self) -> Vec<u8> {
        let mut size: u32 = 0;
        unsafe {
            GetCredentialsSize(&mut size);
        }
        let mut r = Vec::new();
        r.resize(size.try_into().unwrap(), 0);
        unsafe {
            ReadCredentialsBuffer(r.as_mut_ptr() as *mut c_void, 0, size as usize);
        }
        return r;
    }
    fn add_string_id_entry(
        &mut self,
        entry_id: &CStr,
        icon: Option<&[u8]>,
        title: Option<&CStr>,
        subtitle: Option<&CStr>,
        disclaimer: Option<&CStr>,
        warning: Option<&CStr>,
    ) {
        let icon_bytes = icon.map_or(std::ptr::null(), |x| x.as_ptr()) as *const i8;
        let icon_length = icon.map_or(0, |x| x.len());
        unsafe {
            AddStringIdEntry(
                entry_id.as_ptr(),
                icon_bytes,
                icon_length,
                title.map_or(std::ptr::null(), |x| x.as_ptr()),
                subtitle.map_or(std::ptr::null(), |x| x.as_ptr()),
                disclaimer.map_or(std::ptr::null(), |x| x.as_ptr()),
                warning.map_or(std::ptr::null(), |x| x.as_ptr()),
            );
        }
    }
}
