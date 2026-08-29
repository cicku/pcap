// GRCOV_EXCL_START
#![allow(dead_code)]
#![allow(non_camel_case_types)]

#[cfg(not(windows))]
use libc::FILE;
use libc::{c_char, c_int, c_uchar, c_uint, c_ushort, sockaddr, timeval};

#[cfg(test)]
use mockall::automock;
#[cfg(windows)]
use windows_sys::Win32::Foundation::HANDLE;

use crate::Error;

pub const PCAP_IF_LOOPBACK: u32 = 0x00000001;
pub const PCAP_IF_UP: u32 = 0x00000002;
pub const PCAP_IF_RUNNING: u32 = 0x00000004;
pub const PCAP_IF_WIRELESS: u32 = 0x00000008;
pub const PCAP_IF_CONNECTION_STATUS: u32 = 0x00000030;
pub const PCAP_IF_CONNECTION_STATUS_UNKNOWN: u32 = 0x00000000;
pub const PCAP_IF_CONNECTION_STATUS_CONNECTED: u32 = 0x00000010;
pub const PCAP_IF_CONNECTION_STATUS_DISCONNECTED: u32 = 0x00000020;
pub const PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE: u32 = 0x00000030;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_program {
    pub bf_len: c_uint,
    pub bf_insns: *mut bpf_insn,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_insn {
    pub code: c_ushort,
    pub jt: c_uchar,
    pub jf: c_uchar,
    pub k: c_uint,
}

pub enum pcap_t {}

pub enum pcap_dumper_t {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct pcap_file_header {
    pub magic: c_uint,
    pub version_major: c_ushort,
    pub version_minor: c_ushort,
    pub thiszone: c_int,
    pub sigfigs: c_uint,
    pub snaplen: c_uint,
    pub linktype: c_uint,
}

pub type pcap_direction_t = c_uint;

pub const PCAP_D_INOUT: pcap_direction_t = 0;
pub const PCAP_D_IN: pcap_direction_t = 1;
pub const PCAP_D_OUT: pcap_direction_t = 2;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct pcap_pkthdr {
    pub ts: timeval,
    pub caplen: c_uint,
    pub len: c_uint,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct pcap_stat {
    pub ps_recv: c_uint,
    pub ps_drop: c_uint,
    pub ps_ifdrop: c_uint,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct pcap_if_t {
    pub next: *mut pcap_if_t,
    pub name: *mut c_char,
    pub description: *mut c_char,
    pub addresses: *mut pcap_addr_t,
    pub flags: c_uint,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct pcap_addr_t {
    pub next: *mut pcap_addr_t,
    pub addr: *mut sockaddr,
    pub netmask: *mut sockaddr,
    pub broadaddr: *mut sockaddr,
    pub dstaddr: *mut sockaddr,
}

#[cfg(windows)]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct pcap_send_queue {
    pub maxlen: c_uint,
    pub len: c_uint,
    pub buffer: *mut c_char,
}

#[cfg(windows)]
pub const WINPCAP_MINTOCOPY_DEFAULT: c_int = 16000;

// This is not Option<fn>, pcap functions do not check if the handler is null so it is wrong to
// pass them Option::<fn>::None.
pub type pcap_handler =
    extern "C" fn(arg1: *mut c_uchar, arg2: *const pcap_pkthdr, arg3: *const c_uchar) -> ();

// Looking the library up by hand instead of importing it is what lets a binary using this crate
// start where Npcap is not installed. An import of wpcap.dll is resolved before main() runs and
// the process is killed outright when it cannot be, leaving nowhere to say what is missing.
#[cfg(windows)]
mod loader {
    use std::ffi::c_void;
    use std::iter;
    use std::ptr;
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicPtr, Ordering};

    use windows_sys::Win32::Foundation::{HMODULE, MAX_PATH};
    use windows_sys::Win32::System::LibraryLoader::{
        GetProcAddress, LOAD_LIBRARY_FLAGS, LOAD_WITH_ALTERED_SEARCH_PATH, LoadLibraryExW,
    };
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

    // A module handle is a raw pointer and therefore neither Send nor Sync, but it belongs to
    // the process rather than to the thread that opened the library, and this one is never
    // freed.
    struct Module(HMODULE);

    // SAFETY: see the note on Module.
    unsafe impl Send for Module {}
    unsafe impl Sync for Module {}

    static LIBRARY: OnceLock<Option<Module>> = OnceLock::new();

    // An entry point of the library, resolved the first time it is called. The name is handed to
    // GetProcAddress and so has to be NUL terminated.
    pub struct Entry {
        name: &'static str,
        address: AtomicPtr<c_void>,
    }

    impl Entry {
        pub const fn new(name: &'static str) -> Entry {
            Entry {
                name,
                address: AtomicPtr::new(ptr::null_mut()),
            }
        }

        pub fn address(&self) -> *mut c_void {
            let cached = self.address.load(Ordering::Relaxed);
            if !cached.is_null() {
                return cached;
            }

            // Nothing reaches the entry points taking a handle without one of the entry points
            // that look the library up having succeeded first.
            let module = library().expect("wpcap.dll is not loaded");
            let address = match unsafe { GetProcAddress(module.0, self.name.as_ptr()) } {
                Some(address) => address as *const () as *mut c_void,
                // The build script picks which entry points to declare from the version of the
                // library it finds, so this only happens if an older one replaces it afterwards.
                None => panic!(
                    "wpcap.dll does not export {}",
                    self.name.trim_end_matches('\0')
                ),
            };

            // Both threads of a race resolve the same name to the same address, so the store
            // does not have to be ordered against anything.
            self.address.store(address, Ordering::Relaxed);
            address
        }
    }

    pub fn is_available() -> bool {
        library().is_some()
    }

    fn library() -> Option<&'static Module> {
        LIBRARY.get_or_init(open).as_ref()
    }

    // Npcap always installs wpcap.dll into the Npcap subdirectory of the system directory, and
    // only puts a copy in the system directory itself when installed in WinPcap compatible mode.
    // Take the ordinary search order first, so that an application shipping its own copy keeps
    // getting that one, and fall back to the subdirectory nothing searches on its own.
    fn open() -> Option<Module> {
        load("wpcap.dll", 0).or_else(|| {
            let path = format!("{}\\Npcap\\wpcap.dll", system_directory()?);
            // wpcap.dll imports Packet.dll, which lives beside it and nowhere else, so the
            // directory of the library has to be searched as well.
            load(&path, LOAD_WITH_ALTERED_SEARCH_PATH)
        })
    }

    fn load(path: &str, flags: LOAD_LIBRARY_FLAGS) -> Option<Module> {
        let path: Vec<u16> = path.encode_utf16().chain(iter::once(0)).collect();
        let module = unsafe { LoadLibraryExW(path.as_ptr(), ptr::null_mut(), flags) };

        (!module.is_null()).then_some(Module(module))
    }

    fn system_directory() -> Option<String> {
        let mut buffer = [0u16; MAX_PATH as usize];
        // The return is the number of characters written, or the number the buffer should have
        // held when it is too small, or zero when the call failed.
        let len = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
        if len == 0 || len > buffer.len() {
            return None;
        }

        String::from_utf16(&buffer[..len]).ok()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_load() {
            assert!(load("wpcap.dll", 0).is_some());
            assert!(load("no-such-library.dll", 0).is_none());

            // The only place a default Npcap installation puts it.
            let path = format!("{}\\Npcap\\wpcap.dll", system_directory().unwrap());
            assert!(load(&path, LOAD_WITH_ALTERED_SEARCH_PATH).is_some());
        }

        #[test]
        fn test_is_available() {
            assert!(is_available());
        }
    }
}

// The entry points that do not take a handle have to know the library is there before they call
// into it. It is linked in everywhere but Windows, where a binary is meant to run without it and
// report what is missing rather than fail to start.
#[cfg(not(windows))]
pub fn ensure_available() -> Result<(), Error> {
    Ok(())
}

#[cfg(windows)]
pub fn ensure_available() -> Result<(), Error> {
    if loader::is_available() {
        Ok(())
    } else {
        Err(Error::LibraryNotFound)
    }
}

// Everywhere but Windows the declarations below are what they look like, entry points imported
// from the library the binary is linked against.
#[cfg(not(windows))]
macro_rules! pcap_ffi {
    (
        $(#[$modattr:meta])*
        pub mod $module:ident {
            $(#[$linkattr:meta])*
            unsafe extern "C" {
                $(
                    $(#[$fnattr:meta])*
                    pub fn $name:ident($($arg:ident: $argty:ty),* $(,)?) $(-> $ret:ty)?;
                )*
            }
        }
    ) => {
        $(#[$modattr])*
        pub mod $module {
            use super::*;

            $(#[$linkattr])*
            unsafe extern "C" {
                $(
                    $(#[$fnattr])*
                    pub fn $name($($arg: $argty),*) $(-> $ret)?;
                )*
            }
        }
    };
}

// On Windows each one becomes a call through an address the library is asked for the first time
// it is needed, so that nothing is imported from wpcap.dll. Nothing is linked against either,
// so the attribute naming a library to import from is dropped.
#[cfg(windows)]
macro_rules! pcap_ffi {
    (
        $(#[$modattr:meta])*
        pub mod $module:ident {
            $(#[$linkattr:meta])*
            unsafe extern "C" {
                $(
                    $(#[$fnattr:meta])*
                    pub fn $name:ident($($arg:ident: $argty:ty),* $(,)?) $(-> $ret:ty)?;
                )*
            }
        }
    ) => {
        $(#[$modattr])*
        pub mod $module {
            use super::*;

            $(
                $(#[$fnattr])*
                pub unsafe fn $name($($arg: $argty),*) $(-> $ret)? {
                    static ENTRY: super::loader::Entry =
                        super::loader::Entry::new(concat!(stringify!($name), "\0"));

                    let entry: unsafe extern "C" fn($($argty),*) $(-> $ret)? =
                        unsafe { std::mem::transmute(ENTRY.address()) };

                    unsafe { entry($($arg),*) }
                }
            )*
        }
    };
}

pcap_ffi! {
    #[cfg_attr(test, automock)]
    pub mod ffi {
        unsafe extern "C" {
            // [OBSOLETE] pub fn pcap_lookupdev(arg1: *mut c_char) -> *mut c_char;
            // pub fn pcap_lookupnet(arg1: *const c_char, arg2: *mut c_uint, arg3: *mut c_uint,
            //                       arg4: *mut c_char) -> c_int;
            pub fn pcap_create(arg1: *const c_char, arg2: *mut c_char) -> *mut pcap_t;
            pub fn pcap_set_snaplen(arg1: *mut pcap_t, arg2: c_int) -> c_int;
            pub fn pcap_set_promisc(arg1: *mut pcap_t, arg2: c_int) -> c_int;
            // pub fn pcap_can_set_rfmon(arg1: *mut pcap_t) -> c_int;
            pub fn pcap_set_timeout(arg1: *mut pcap_t, arg2: c_int) -> c_int;
            pub fn pcap_set_buffer_size(arg1: *mut pcap_t, arg2: c_int) -> c_int;
            pub fn pcap_activate(arg1: *mut pcap_t) -> c_int;
            // pub fn pcap_open_live(arg1: *const c_char, arg2: c_int, arg3: c_int, arg4: c_int,
            //                       arg5: *mut c_char) -> *mut pcap_t;
            pub fn pcap_open_dead(arg1: c_int, arg2: c_int) -> *mut pcap_t;
            pub fn pcap_open_offline(arg1: *const c_char, arg2: *mut c_char) -> *mut pcap_t;
            pub fn pcap_close(arg1: *mut pcap_t);
            pub fn pcap_loop(
                arg1: *mut pcap_t,
                arg2: c_int,
                arg3: pcap_handler,
                arg4: *mut c_uchar,
            ) -> c_int;
            pub fn pcap_dispatch(
                arg1: *mut pcap_t,
                arg2: c_int,
                arg3: pcap_handler,
                arg4: *mut c_uchar,
            ) -> c_int;
            // pub fn pcap_next(arg1: *mut pcap_t, arg2: *mut pcap_pkthdr) -> *const c_uchar;
            pub fn pcap_next_ex(
                arg1: *mut pcap_t,
                arg2: *mut *mut pcap_pkthdr,
                arg3: *mut *const c_uchar,
            ) -> c_int;
            pub fn pcap_breakloop(arg1: *mut pcap_t);
            pub fn pcap_stats(arg1: *mut pcap_t, arg2: *mut pcap_stat) -> c_int;
            pub fn pcap_setfilter(arg1: *mut pcap_t, arg2: *mut bpf_program) -> c_int;
            pub fn pcap_setdirection(arg1: *mut pcap_t, arg2: pcap_direction_t) -> c_int;
            // pub fn pcap_getnonblock(arg1: *mut pcap_t, arg2: *mut c_char) -> c_int;
            pub fn pcap_setnonblock(arg1: *mut pcap_t, arg2: c_int, arg3: *mut c_char) -> c_int;
            pub fn pcap_sendpacket(arg1: *mut pcap_t, arg2: *const c_uchar, arg3: c_int) -> c_int;
            // pub fn pcap_statustostr(arg1: c_int) -> *const c_char;
            // pub fn pcap_strerror(arg1: c_int) -> *const c_char;
            pub fn pcap_geterr(arg1: *mut pcap_t) -> *mut c_char;
            // pub fn pcap_perror(arg1: *mut pcap_t, arg2: *mut c_char);
            pub fn pcap_compile(
                arg1: *mut pcap_t,
                arg2: *mut bpf_program,
                arg3: *const c_char,
                arg4: c_int,
                arg5: c_uint,
            ) -> c_int;
            // pub fn pcap_compile_nopcap(arg1: c_int, arg2: c_int, arg3: *mut bpf_program,
            //                            arg4: *const c_char, arg5: c_int, arg6: c_uint) -> c_int;
            pub fn pcap_freecode(arg1: *mut bpf_program);
            pub fn pcap_offline_filter(
                arg1: *const bpf_program,
                arg2: *const pcap_pkthdr,
                arg3: *const c_uchar,
            ) -> c_int;
            pub fn pcap_datalink(arg1: *mut pcap_t) -> c_int;
            // pub fn pcap_datalink_ext(arg1: *mut pcap_t) -> c_int;
            pub fn pcap_list_datalinks(arg1: *mut pcap_t, arg2: *mut *mut c_int) -> c_int;
            pub fn pcap_set_datalink(arg1: *mut pcap_t, arg2: c_int) -> c_int;
            pub fn pcap_free_datalinks(arg1: *mut c_int);
            pub fn pcap_datalink_name_to_val(arg1: *const c_char) -> c_int;
            pub fn pcap_datalink_val_to_name(arg1: c_int) -> *const c_char;
            pub fn pcap_datalink_val_to_description(arg1: c_int) -> *const c_char;
            // pub fn pcap_snapshot(arg1: *mut pcap_t) -> c_int;
            // pub fn pcap_is_swapped(arg1: *mut pcap_t) -> c_int;
            pub fn pcap_major_version(arg1: *mut pcap_t) -> c_int;
            pub fn pcap_minor_version(arg1: *mut pcap_t) -> c_int;
            // pub fn pcap_file(arg1: *mut pcap_t) -> *mut FILE;
            pub fn pcap_fileno(arg1: *mut pcap_t) -> c_int;
            pub fn pcap_dump_open(arg1: *mut pcap_t, arg2: *const c_char) -> *mut pcap_dumper_t;
            // pub fn pcap_dump_file(arg1: *mut pcap_dumper_t) -> *mut FILE;
            // pub fn pcap_dump_ftell(arg1: *mut pcap_dumper_t) -> c_long;
            pub fn pcap_dump_flush(arg1: *mut pcap_dumper_t) -> c_int;
            pub fn pcap_dump_close(arg1: *mut pcap_dumper_t);
            pub fn pcap_dump(arg1: *mut c_uchar, arg2: *const pcap_pkthdr, arg3: *const c_uchar);
            pub fn pcap_findalldevs(arg1: *mut *mut pcap_if_t, arg2: *mut c_char) -> c_int;
            pub fn pcap_freealldevs(arg1: *mut pcap_if_t);
            // pub fn pcap_lib_version() -> *const c_char;
            // pub fn bpf_image(arg1: *const bpf_insn, arg2: c_int) -> *mut c_char;
            // pub fn bpf_dump(arg1: *const bpf_program, arg2: c_int);

            // pub fn pcap_free_tstamp_types(arg1: *mut c_int) -> ();
            // pub fn pcap_list_tstamp_types(arg1: *mut pcap_t, arg2: *mut *mut c_int) -> c_int;
            // pub fn pcap_tstamp_type_name_to_val(arg1: *const c_char) -> c_int;
            // pub fn pcap_tstamp_type_val_to_description(arg1: c_int) -> *const c_char;
            // pub fn pcap_tstamp_type_val_to_name(arg1: c_int) -> *const c_char;
            #[cfg(libpcap_1_2_1)]
            pub fn pcap_set_tstamp_type(arg1: *mut pcap_t, arg2: c_int) -> c_int;

            // pub fn pcap_get_tstamp_precision(arg1: *mut pcap_t) -> c_int;
            #[cfg(libpcap_1_5_0)]
            pub fn pcap_open_dead_with_tstamp_precision(
                arg1: c_int,
                arg2: c_int,
                arg3: c_uint,
            ) -> *mut pcap_t;
            #[cfg(libpcap_1_5_0)]
            pub fn pcap_open_offline_with_tstamp_precision(
                arg1: *const c_char,
                arg2: c_uint,
                arg3: *mut c_char,
            ) -> *mut pcap_t;
            #[cfg(libpcap_1_5_0)]
            pub fn pcap_set_immediate_mode(arg1: *mut pcap_t, arg2: c_int) -> c_int;
            #[cfg(libpcap_1_5_0)]
            pub fn pcap_set_tstamp_precision(arg1: *mut pcap_t, arg2: c_int) -> c_int;

            #[cfg(libpcap_1_7_2)]
            pub fn pcap_dump_open_append(
                arg1: *mut pcap_t,
                arg2: *const c_char,
            ) -> *mut pcap_dumper_t;

            // From libpcap 1.9.0, not bound:
            // pcap_bufsize
            // pcap_createsrcstr
            // pcap_dump_ftell64
            // pcap_findalldevs_ex
            // pcap_get_required_select_timeout
            // pcap_open
            // pcap_parsesrcstr
            // pcap_remoteact_accept
            // pcap_remoteact_cleanup
            // pcap_remoteact_close
            // pcap_remoteact_list
            // pcap_set_protocol_linux
            // pcap_setsampling

            // From libpcap 1.9.1, not bound:
            // pcap_datalink_val_to_description_or_dlt

            // From libpcap 1.10.0, not bound:
            // pcap_init
            // pcap_remoteact_accept_ex
        }
    }
}

#[cfg(not(windows))]
pcap_ffi! {
    #[cfg_attr(test, automock)]
    pub mod ffi_unix {
        #[link(name = "pcap")]
        unsafe extern "C" {
            // pub fn pcap_inject(arg1: *mut pcap_t, arg2: *const c_void, arg3: size_t) -> c_int;
            pub fn pcap_set_rfmon(arg1: *mut pcap_t, arg2: c_int) -> c_int;
            pub fn pcap_get_selectable_fd(arg1: *mut pcap_t) -> c_int;
            // wpcap exports no FILE * entry points: libpcap may be linked against a different C
            // runtime than its caller. On Windows pcap.h defines these names as macros that pull
            // the OS handle out of the FILE * and call pcap_hopen_offline()/pcap_dump_hopen().
            pub fn pcap_fopen_offline(arg1: *mut FILE, arg2: *mut c_char) -> *mut pcap_t;
            pub fn pcap_dump_fopen(arg1: *mut pcap_t, fp: *mut FILE) -> *mut pcap_dumper_t;

            #[cfg(libpcap_1_5_0)]
            pub fn pcap_fopen_offline_with_tstamp_precision(
                arg1: *mut FILE,
                arg2: c_uint,
                arg3: *mut c_char,
            ) -> *mut pcap_t;
        }
    }
}

#[cfg(target_os = "macos")]
pcap_ffi! {
    #[cfg_attr(test, automock)]
    pub mod ffi_macos {
        unsafe extern "C" {
            #[cfg(libpcap_1_5_3)]
            pub fn pcap_set_want_pktap(arg1: *mut pcap_t, arg2: c_int) -> c_int;
        }
    }
}

#[cfg(windows)]
pcap_ffi! {
    #[cfg_attr(test, automock)]
    pub mod ffi_windows {
        unsafe extern "C" {
            pub fn pcap_setmintocopy(arg1: *mut pcap_t, arg2: c_int) -> c_int;
            pub fn pcap_getevent(p: *mut pcap_t) -> HANDLE;
            pub fn pcap_sendqueue_alloc(memsize: c_uint) -> *mut pcap_send_queue;
            pub fn pcap_sendqueue_destroy(queue: *mut pcap_send_queue);
            pub fn pcap_sendqueue_queue(
                queue: *mut pcap_send_queue,
                pkt_header: *const pcap_pkthdr,
                pkt_data: *const c_uchar,
            ) -> c_int;
            pub fn pcap_sendqueue_transmit(
                p: *mut pcap_t,
                queue: *mut pcap_send_queue,
                sync: c_int,
            ) -> c_uint;
        }
    }
}

// The conventional solution is to use `mockall_double`. However, automock's requirement for an
// inner module would require changing the imports in all the files using this module. This approach
// allows all the other modules to keep using the `raw` module as before.
#[cfg(not(test))]
pub use ffi::*;

#[cfg(not(test))]
#[cfg(not(windows))]
pub use ffi_unix::*;

#[cfg(not(test))]
#[cfg(target_os = "macos")]
pub use ffi_macos::*;

#[cfg(not(test))]
#[cfg(windows)]
pub use ffi_windows::*;

#[cfg(test)]
pub use mock_ffi::*;

#[cfg(test)]
#[cfg(not(windows))]
pub use mock_ffi_unix::*;

#[cfg(test)]
#[cfg(target_os = "macos")]
pub use mock_ffi_macos::*;

#[cfg(test)]
#[cfg(windows)]
pub use mock_ffi_windows::*;

#[cfg(test)]
pub mod testmod {
    use std::{ffi::CString, sync::Mutex};

    use once_cell::sync::Lazy;

    use super::*;

    pub struct GeterrContext(__pcap_geterr::Context);

    // Must be acquired by any test using mock FFI.
    pub static RAWMTX: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    pub fn as_pcap_t<T: ?Sized>(value: &mut T) -> *mut pcap_t {
        value as *mut T as *mut pcap_t
    }

    pub fn as_pcap_dumper_t<T: ?Sized>(value: &mut T) -> *mut pcap_dumper_t {
        value as *mut T as *mut pcap_dumper_t
    }

    pub fn geterr_expect(pcap: *mut pcap_t) -> GeterrContext {
        // Lock must be acquired by caller.
        assert!(RAWMTX.try_lock().is_err());

        let err = CString::new("oh oh").unwrap();
        let ctx = pcap_geterr_context();
        ctx.checkpoint();
        ctx.expect()
            .withf_st(move |arg1| *arg1 == pcap)
            .return_once_st(|_| err.into_raw());

        GeterrContext(ctx)
    }
}
// GRCOV_EXCL_STOP
