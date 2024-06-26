use dll_syringe::{
    error::{EjectError, InjectError, LoadProcedureError},
    process::{BorrowedProcess, BorrowedProcessModule, OwnedProcess, ProcessModule},
    rpc::{RawRpcFunctionPtr, RemoteRawProcedure},
    Syringe,
};
use frida_gum::Module;

#[derive(thiserror::Error, Debug)]
pub enum InjectorError {
    #[error("target process could not be found")]
    ProcessNotFound(#[from] std::io::Error),
    #[error("inject failed")]
    InjectFailed(#[from] InjectError),
    #[error("eject failed")]
    EjectFailed(#[from] EjectError),
}

pub struct Injection<'a> {
    syringe_ptr: *mut Syringe,
    injected_module: ProcessModule<BorrowedProcess<'a>>,
}

impl<'a> Injection<'a> {
    #[allow(dead_code)]
    pub fn eject(&mut self) -> Result<(), InjectorError> {
        unsafe {
            let _ = self
                .syringe_ptr
                .as_ref()
                .unwrap()
                .eject(self.injected_module)
                .map_err(|e| InjectorError::EjectFailed(e));
        }
        Ok(())
    }

    pub unsafe fn get_func<F: RawRpcFunctionPtr>(
        &mut self,
        name: &str,
    ) -> Result<Option<RemoteRawProcedure<F>>, LoadProcedureError> {
        self.syringe_ptr
            .as_ref()
            .unwrap()
            .get_raw_procedure::<F>(self.injected_module, name)
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

pub unsafe fn inject<'a>(
    pid: u32,
    payload_path: Option<String>,
) -> Result<Injection<'a>, InjectorError> {
    let process = OwnedProcess::from_pid(pid).map_err(|e| InjectorError::ProcessNotFound(e))?;
    let syringe = Syringe::for_process(process);
    let payload_path = payload_path.or(Some(get_current_module_path())).unwrap();
    let syringe_ptr = Box::leak(Box::new(syringe)) as *mut Syringe;
    let injected_module = syringe_ptr
        .as_ref()
        .unwrap()
        .inject(payload_path)
        .map_err(|e| InjectorError::InjectFailed(e))?;
    let injection = Injection {
        syringe_ptr,
        injected_module,
    };
    Ok(injection)
}
