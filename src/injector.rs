use anyhow::Ok;
use dll_syringe::{
    process::{BorrowedProcess, BorrowedProcessModule, OwnedProcess, ProcessModule},
    Syringe,
};
use frida_gum::Module;

pub struct Injection<'a> {
    syringe_ptr: *mut Syringe,
    injected_module: ProcessModule<BorrowedProcess<'a>>,
}

impl<'a> Injection<'a> {
    #[allow(dead_code)]
    pub fn eject(&mut self) -> anyhow::Result<()> {
        unsafe {
            self.syringe_ptr
                .as_ref()
                .unwrap()
                .eject(self.injected_module)?;
        }
        anyhow::Ok(())
    }
}

impl<'a> Drop for Injection<'a> {
    fn drop(&mut self) {
        unsafe { drop(Box::from_raw(self.syringe_ptr)) }
    }
}

fn get_current_module_path() -> String {
    let module = Module::enumerate_modules()
        .into_iter()
        .find(|module| {
            let func_addr = get_current_module_path as usize;
            module.base_address <= func_addr && module.base_address + module.size > func_addr
        })
        .unwrap();
    module.path
}

pub unsafe fn inject<'a>(pid: u32) -> anyhow::Result<Injection<'a>> {
    let process = OwnedProcess::from_pid(pid)?;
    let syringe = Syringe::for_process(process);
    let payload_path = get_current_module_path();
    let syringe_ptr = Box::leak(Box::new(syringe)) as *mut Syringe;
    let injected_module = syringe_ptr.as_ref().unwrap().inject(payload_path)?;
    let injection = Injection {
        syringe_ptr,
        injected_module,
    };
    Ok(injection)
}
