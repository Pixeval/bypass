use std::thread::JoinHandle;

use frida_gum::{Module, ModuleDetails, ModuleDetailsOwned, NativePointer};

pub fn wait_for_export() -> NativePointer {
    loop {
        let chrome_main = Module::find_export_by_name(None, "ChromeMain");
        match chrome_main {
            Some(address) => break address,
            None => continue,
        }
    }
}

pub fn spawn_and_wait_for_module<T: FnOnce(ModuleDetailsOwned) -> () + Send + 'static>(
    module_name: &str,
    cb: T,
) {
    let module_name = module_name.to_string();
    std::thread::spawn(move || {
        cb(loop {
            if let Some(module) = Module::enumerate_modules()
                .into_iter()
                .find(|m| m.name == module_name)
            {
                break module;
            }
        });
    });
}
