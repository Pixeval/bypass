using System.Runtime.InteropServices;

namespace Pixeval.Bypass;

public class Injector
{
    [DllImport("bypass", EntryPoint = "injector_inject", CharSet = CharSet.Unicode)]
    public static extern nint Inject(uint pid, string payloadPath);

    [DllImport("bypass", EntryPoint = "injector_eject")]
    public static extern void Eject(nint injection);

    [DllImport("bypass", EntryPoint = "injector_install_dns_hook")]
    public static extern void InstallDnsHook(nint injection, bool autoEnable);

    [DllImport("bypass", EntryPoint = "injector_install_schannel_ssl_hook")]
    public static extern void InstallSchannelSslHook(nint injection, bool autoEnable);

    [DllImport("bypass", EntryPoint = "injector_install_chrome_hook", CharSet = CharSet.Unicode)]
    public static extern void InstallChromeHook(nint injection, bool autoEnable, string injectedDllPath);

    [DllImport("bypass", EntryPoint = "injector_install_chrome_ssl_hook")]
    public static extern void InstallChromeSslHook(nint injection, bool autoEnable);

    [DllImport("bypass", EntryPoint = "injector_set_dns_hook_enabled")]
    public static extern void SetDnsHookEnabled(nint injection, bool enabled);

    [DllImport("bypass", EntryPoint = "injector_set_ssl_hook_enabled")]
    public static extern void SetSchannelSslHookEnabled(nint injection, bool enabled);

    [DllImport("bypass", EntryPoint = "injector_set_chrome_hook_enabled")]
    public static extern void SetChromeHookEnabled(nint injection, bool enabled);

    [DllImport("bypass", EntryPoint = "injector_set_chrome_ssl_hook_enabled")]
    public static extern void SetChromeSllHookEnabled(nint injection, bool enabled);
}
