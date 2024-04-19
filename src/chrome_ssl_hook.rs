use frida_gum::{interceptor::Interceptor, Gum, MatchPattern, MemoryRange, Module, NativePointer};
use lazy_static::lazy_static;
use std::{
    cell::UnsafeCell,
    env::current_exe,
    ffi::c_void,
    mem::{size_of, transmute},
    ops::Sub,
    ptr::{null, null_mut},
    sync::Mutex,
};
use windows::{
    core::PCSTR,
    Win32::{
        Foundation::HMODULE,
        System::{
            ProcessStatus::{GetModuleInformation, MODULEINFO},
            Threading::GetCurrentProcess,
        },
    },
};

lazy_static! {
    static ref GUM: Gum = unsafe { Gum::obtain() };
    pub static ref ENABLED: Mutex<UnsafeCell<bool>> = Mutex::new(UnsafeCell::new(false));
    static ref ORIGINAL: Mutex<UnsafeCell<Option<TargetFunc>>> = Mutex::new(UnsafeCell::new(None));
}

static mut TARGET: Option<NativePointer> = None;

type TargetFunc = unsafe extern "C" fn(s: *mut c_void, name: PCSTR) -> i32;

unsafe extern "C" fn detour(s: *mut c_void, name: PCSTR) -> i32 {
    let name1 = name.to_string().unwrap();
    let result = if name1.eq_ignore_ascii_case("pixiv.net") {
        ORIGINAL.lock().unwrap().get_mut().unwrap()(s, PCSTR(null()))
    } else if name1.eq_ignore_ascii_case("www.pixiv.net") {
        ORIGINAL.lock().unwrap().get_mut().unwrap()(s, PCSTR(null()))
    } else if name1.eq_ignore_ascii_case("a.pixiv.org") {
        ORIGINAL.lock().unwrap().get_mut().unwrap()(s, PCSTR(null()))
    } else {
        ORIGINAL.lock().unwrap().get_mut().unwrap()(s, name)
    };
    return result;
}

fn find_target() -> NativePointer {
    let current = current_exe().unwrap();
    let basename = current.file_stem().unwrap().to_str().unwrap();
    log::info!("{}", basename);
    let mut module_handle = 0isize;
    while Module::find_export_by_name(None, "ChromeMain").unwrap().0 == null_mut::<c_void>() {
        module_handle = Module::find_base_address(format!("{}.dll", basename).as_str()).0 as isize;
    }
    let module_info = MODULEINFO::default();
    unsafe {
        GetModuleInformation(
            GetCurrentProcess(),
            HMODULE(module_handle),
            transmute(&module_info),
            size_of::<MODULEINFO>() as u32,
        )
        .unwrap()
    };
    let memory_range = MemoryRange::new(
        NativePointer(module_info.lpBaseOfDll),
        module_info.SizeOfImage as usize,
    );
    let result = memory_range.scan(&MatchPattern::from_string(
        "C7 44 24 20 ?? ?? ?? ?? 4C 8D 0D ?? ?? ?? ?? 31 F6 B9 10 00 00 00 31 D2 41 B8 D5 00 00 00",
    ).unwrap());
    let address = result[0].address;
    log::info!("found pattern at {:?}", address);
    let memory_range = MemoryRange::new(NativePointer(address.sub(200) as *mut c_void), 200);
    let result1 = memory_range.scan(&MatchPattern::from_string("41 56").unwrap());
    let result2 = memory_range.scan(&MatchPattern::from_string("56 57").unwrap());
    let address = if !result1.is_empty() {
        result1[0].address
    } else {
        result2[0].address
    };
    log::info!("found target at {:?}", address);
    NativePointer(address as *mut c_void)
}

pub fn install(auto_enable: bool) {
    eventlog::init("Pixeval.Bypass", log::Level::Trace).ok();
    let mut interceptr = Interceptor::obtain(&GUM);
    let target = find_target();
    interceptr.begin_transaction();
    unsafe {
        TARGET = Some(target);
        *ORIGINAL.lock().unwrap().get_mut() = Some(transmute(
            interceptr
                .replace_fast(TARGET.unwrap(), NativePointer(detour as *mut c_void))
                .unwrap()
                .0,
        ));
    }
    interceptr.end_transaction();
    *ENABLED.lock().unwrap().get_mut() = auto_enable;
    log::info!("chrome ssl hook installed");
}

pub fn remove() {
    let mut interceptor = Interceptor::obtain(&GUM);
    interceptor.begin_transaction();
    unsafe {
        interceptor.revert(TARGET.unwrap());
    }
    interceptor.end_transaction();
}
