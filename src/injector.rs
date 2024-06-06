use frida::Inject;
use frida_gum::Module;

use crate::LogServerInfo;

struct Injector {
    log_server_info: Option<LogServerInfo>,
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

impl Injector {
    pub fn inject(&self, pid: u32) {
        let inject_payload_path = get_current_module_path();
        let mut injector = frida::Injector::new();
        injector.inject_library_file_sync(pid, inject_payload_path, "entrypoint", "localhost");
    }
}
