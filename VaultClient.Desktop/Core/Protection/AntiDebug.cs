using System.Diagnostics;
using System.Runtime.InteropServices;

namespace VaultClient.Desktop.Core.Protection;

/// <summary>
/// Multi-layered debugger detection.
/// Combines managed (.NET) and native (Win32) checks.
///
/// Techniques:
///   1. Debugger.IsAttached (managed)
///   2. IsDebuggerPresent (kernel32 — native debugger)
///   3. CheckRemoteDebuggerPresent (detects remote/cross-process debuggers)
///   4. NtQueryInformationProcess (detects kernel debuggers)
///   5. CloseHandle trick (debuggers intercept invalid handle exceptions)
///   6. Timing check (breakpoints cause timing anomalies)
///   7. Hardware breakpoint detection (DR0-DR3 via thread context)
///   8. Parent process check (normal parent = explorer.exe)
/// </summary>
public static class AntiDebug
{
    // --- Win32 P/Invoke ---

    [DllImport("kernel32.dll")]
    private static extern bool IsDebuggerPresent();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool isDebuggerPresent);

    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern int NtQueryInformationProcess(
        IntPtr processHandle, int processInformationClass,
        out IntPtr processInformation, int processInformationLength, out int returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentThread();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT context);

    [DllImport("kernel32.dll")]
    private static extern uint GetTickCount();

    [StructLayout(LayoutKind.Sequential)]
    private struct CONTEXT
    {
        public uint ContextFlags;
        // Debug registers
        public nuint Dr0;
        public nuint Dr1;
        public nuint Dr2;
        public nuint Dr3;
        public nuint Dr6;
        public nuint Dr7;
        // We need the full struct but only care about debug registers.
        // Pad to minimum required size (716 bytes on x64).
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
        public byte[] Padding;
    }

    private const uint CONTEXT_DEBUG_REGISTERS = 0x00010010; // CONTEXT_i386 | CONTEXT_DEBUG_REGISTERS

    // --- Detection methods ---

    /// <summary>
    /// Runs ALL detection checks. Returns list of triggered detections.
    /// Empty list = no debugger detected.
    /// </summary>
    public static List<DebugDetection> DetectAll()
    {
        var detections = new List<DebugDetection>();

        if (CheckManagedDebugger())
            detections.Add(new DebugDetection("MANAGED_DEBUGGER", "Debugger.IsAttached = true"));

        if (CheckNativeDebugger())
            detections.Add(new DebugDetection("NATIVE_DEBUGGER", "IsDebuggerPresent() = true"));

        if (CheckRemoteDebugger())
            detections.Add(new DebugDetection("REMOTE_DEBUGGER", "CheckRemoteDebuggerPresent() = true"));

        if (CheckNtDebugPort())
            detections.Add(new DebugDetection("KERNEL_DEBUGGER", "NtQueryInformationProcess DebugPort != 0"));

        if (CheckCloseHandleTrick())
            detections.Add(new DebugDetection("HANDLE_EXCEPTION", "CloseHandle trap triggered"));

        if (CheckTimingAnomaly())
            detections.Add(new DebugDetection("TIMING_ANOMALY", "Execution timing inconsistent with normal flow"));

        if (CheckHardwareBreakpoints())
            detections.Add(new DebugDetection("HW_BREAKPOINTS", "Hardware debug registers DR0-DR3 are set"));

        if (CheckSuspiciousParent())
            detections.Add(new DebugDetection("SUSPICIOUS_PARENT", "Parent process is not explorer.exe"));

        return detections;
    }

    /// <summary>Quick check: is ANY debugger detected?</summary>
    public static bool IsDebuggerDetected() => DetectAll().Count > 0;

    // --- Individual checks ---

    /// <summary>1. Managed .NET debugger (Visual Studio, dnSpy, etc.)</summary>
    public static bool CheckManagedDebugger() => Debugger.IsAttached;

    /// <summary>2. Native debugger (x64dbg, WinDbg, OllyDbg)</summary>
    public static bool CheckNativeDebugger()
    {
        try { return IsDebuggerPresent(); }
        catch { return false; }
    }

    /// <summary>3. Remote debugger (cross-process attach)</summary>
    public static bool CheckRemoteDebugger()
    {
        try
        {
            CheckRemoteDebuggerPresent(GetCurrentProcess(), out var isDebugger);
            return isDebugger;
        }
        catch { return false; }
    }

    /// <summary>4. Kernel debugger via NtQueryInformationProcess (ProcessDebugPort = 7)</summary>
    public static bool CheckNtDebugPort()
    {
        try
        {
            var status = NtQueryInformationProcess(
                GetCurrentProcess(), 7, // ProcessDebugPort
                out var debugPort, IntPtr.Size, out _);

            return status == 0 && debugPort != IntPtr.Zero;
        }
        catch { return false; }
    }

    /// <summary>
    /// 5. CloseHandle trick: passing an invalid handle to CloseHandle.
    /// If a debugger is attached, it intercepts the STATUS_INVALID_HANDLE
    /// exception instead of letting the OS return normally.
    /// </summary>
    public static bool CheckCloseHandleTrick()
    {
        try
        {
            CloseHandle(new IntPtr(0x1337DEAD));
            return false; // Normal: no exception
        }
        catch
        {
            return true; // Debugger intercepted the invalid handle
        }
    }

    /// <summary>
    /// 6. Timing check: a simple loop should execute in under ~2ms.
    /// If breakpoints are set or single-stepping, it takes much longer.
    /// </summary>
    public static bool CheckTimingAnomaly()
    {
        try
        {
            var start = GetTickCount();
            // Simple computation that should be near-instant
            var sum = 0L;
            for (var i = 0; i < 1000; i++)
                sum += i;
            var elapsed = GetTickCount() - start;

            // If this trivial loop takes > 100ms, something is wrong
            return elapsed > 100;
        }
        catch { return false; }
    }

    /// <summary>
    /// 7. Hardware breakpoint detection.
    /// Debug registers DR0-DR3 hold breakpoint addresses.
    /// If any are non-zero, a hardware breakpoint is active.
    /// </summary>
    public static bool CheckHardwareBreakpoints()
    {
        try
        {
            var ctx = new CONTEXT
            {
                ContextFlags = CONTEXT_DEBUG_REGISTERS,
                Padding = new byte[512]
            };

            if (!GetThreadContext(GetCurrentThread(), ref ctx))
                return false;

            return ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0;
        }
        catch { return false; }
    }

    /// <summary>
    /// 8. Parent process check.
    /// Normal apps are launched by explorer.exe (or the IDE in dev).
    /// Debuggers launch the process themselves — different parent.
    /// </summary>
    public static bool CheckSuspiciousParent()
    {
        try
        {
            using var current = Process.GetCurrentProcess();
            using var parent = ParentProcessUtilities.GetParentProcess(current.Id);

            if (parent is null) return false;

            var parentName = parent.ProcessName.ToLowerInvariant();

            // Whitelist of normal parent processes
            var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "explorer",      // Normal launch
                "devenv",        // Visual Studio
                "rider64",       // JetBrains Rider
                "dotnet",        // dotnet run
                "cmd",           // Command prompt
                "powershell",    // PowerShell
                "pwsh",          // PowerShell Core
                "windowsterminal", // Windows Terminal
                "code",          // VS Code
                "svchost",       // Service host
                "services",      // Services
                "w3wp",          // IIS worker
            };

            return !allowed.Contains(parentName);
        }
        catch { return false; }
    }
}

/// <summary>
/// Represents a single debugger detection event.
/// </summary>
public sealed record DebugDetection(string Code, string Description);

/// <summary>
/// Utility to find parent process via NtQueryInformationProcess.
/// </summary>
internal static class ParentProcessUtilities
{
    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(
        IntPtr processHandle, int processInformationClass,
        ref PROCESS_BASIC_INFORMATION processInformation,
        int processInformationLength, out int returnLength);

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId; // Parent PID
    }

    public static Process? GetParentProcess(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            var pbi = new PROCESS_BASIC_INFORMATION();
            var status = NtQueryInformationProcess(
                process.Handle, 0, ref pbi,
                Marshal.SizeOf(pbi), out _);

            if (status != 0) return null;

            var parentPid = pbi.InheritedFromUniqueProcessId.ToInt32();
            return Process.GetProcessById(parentPid);
        }
        catch
        {
            return null;
        }
    }
}
