use frida_gum::{interceptor::Interceptor, Gum, MatchPattern, MemoryRange, Module, NativePointer};
use lazy_static::lazy_static;
use std::{
    cell::UnsafeCell,
    ffi::c_void,
    mem::transmute,
    ops::{Add, Sub},
    ptr::null,
    sync::Mutex,
    time::{Duration, Instant},
};
use windows::core::PCSTR;

use super::HookError;

lazy_static! {
    static ref GUM: Gum = unsafe { Gum::obtain() };
    pub static ref ENABLED: Mutex<UnsafeCell<bool>> = Mutex::new(UnsafeCell::new(false));
    static ref ORIGINAL: Mutex<UnsafeCell<Option<TargetFunc>>> = Mutex::new(UnsafeCell::new(None));
}

static mut TARGET: Option<NativePointer> = None;

type TargetFunc = unsafe extern "C" fn(s: *mut c_void, name: PCSTR) -> i32;

unsafe extern "C" fn detour(s: *mut c_void, name: PCSTR) -> i32 {
    let name1 = name.to_string().unwrap();
    if name1.ends_with("pixiv.net") {
        return ORIGINAL.lock().unwrap().get_mut().unwrap()(s, PCSTR(null()));
    } else if name1.ends_with("pximg.net") {
        return ORIGINAL.lock().unwrap().get_mut().unwrap()(s, PCSTR(null()));
    };
    return ORIGINAL.lock().unwrap().get_mut().unwrap()(s, name);
}

fn find_target() -> Result<NativePointer, HookError> {
    let end_time = Instant::now().checked_add(Duration::from_secs(1)).unwrap();
    let chrome_main = loop {
        if let Some(address) = Module::find_export_by_name(None, "ChromeMain") {
            break Some(address);
        } else {
            if Instant::now() > end_time {
                break None;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    .ok_or(HookError::ModuleNotFound())?;
    let module = Module::enumerate_modules()
        .into_iter()
        .filter(|m| {
            m.base_address <= chrome_main.0 as usize
                && (chrome_main.0 as usize) < m.base_address.add(m.size)
        })
        .next()
        .unwrap();
    let memory_range = MemoryRange::new(
        NativePointer(module.base_address as *mut c_void),
        module.size,
    );
    let result = memory_range.scan(&MatchPattern::from_string(
        "C7 44 24 20 ?? ?? ?? ?? 4C 8D 0D ?? ?? ?? ?? 31 F6 B9 10 00 00 00 31 D2 41 B8 D5 00 00 00",
    ).unwrap());
    if result.is_empty() {
        return Err(HookError::TargetNotFound);
    }
    let address = result[0].address;
    let memory_range = MemoryRange::new(NativePointer(address.sub(200) as *mut c_void), 200);
    let result1 = memory_range.scan(&MatchPattern::from_string("41 56 56 57 53").unwrap());
    let result2 = memory_range.scan(&MatchPattern::from_string("56 57 48 83").unwrap());
    let address = match (result1.last(), result2.last()) {
        (None, None) => None,
        (None, Some(address)) => Some(address.address),
        (Some(address), None) => Some(address.address),
        (Some(address1), Some(address2)) => Some(std::cmp::max(address1.address, address2.address)),
    };
    address
        .map(|a| NativePointer(a as *mut c_void))
        .ok_or(HookError::TargetNotFound)
}

pub fn install() -> Result<(), HookError> {
    unsafe {
        TARGET = find_target().map(Some)?;
        let mut interceptr = Interceptor::obtain(&GUM);
        interceptr.begin_transaction();
        *ORIGINAL.lock().unwrap().get_mut() = Some(transmute(
            interceptr
                .replace_fast(TARGET.unwrap(), NativePointer(detour as *mut c_void))
                .unwrap()
                .0,
        ));
        interceptr.end_transaction();
        Ok(())
    }
}
