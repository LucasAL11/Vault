using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace VaultClient.Desktop.Core;

/// <summary>
/// Digita texto na janela atualmente focada via SendInput (Win32).
/// O valor nunca passa pelo clipboard — é enviado como eventos de teclado.
/// </summary>
public sealed class AutoTypeService
{
    #region Win32 P/Invoke

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);

    [DllImport("user32.dll")]
    private static extern short VkKeyScan(char ch);

    private const int INPUT_KEYBOARD = 1;
    private const uint KEYEVENTF_UNICODE = 0x0004;
    private const uint KEYEVENTF_KEYUP = 0x0002;
    private const ushort VK_SHIFT = 0x10;

    [StructLayout(LayoutKind.Sequential)]
    private struct INPUT
    {
        public int type;
        public INPUTUNION u;
    }

    [StructLayout(LayoutKind.Explicit)]
    private struct INPUTUNION
    {
        [FieldOffset(0)] public KEYBDINPUT ki;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct KEYBDINPUT
    {
        public ushort wVk;
        public ushort wScan;
        public uint dwFlags;
        public uint time;
        public nint dwExtraInfo;
    }

    #endregion

    /// <summary>
    /// Digita cada caractere da string na janela focada via SendInput.
    /// Após enviar, zera os bytes do valor da memória.
    /// </summary>
    public void Type(byte[] utf8Value)
    {
        try
        {
            var text = Encoding.UTF8.GetString(utf8Value);
            var inputs = BuildInputs(text);
            SendInput((uint)inputs.Length, inputs, Marshal.SizeOf<INPUT>());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(utf8Value);
        }
    }

    private static INPUT[] BuildInputs(string text)
    {
        // Cada caractere gera 2 eventos: key down + key up via Unicode
        var inputs = new INPUT[text.Length * 2];
        for (var i = 0; i < text.Length; i++)
        {
            var scan = (ushort)text[i];

            inputs[i * 2] = new INPUT
            {
                type = INPUT_KEYBOARD,
                u = new INPUTUNION
                {
                    ki = new KEYBDINPUT
                    {
                        wVk = 0,
                        wScan = scan,
                        dwFlags = KEYEVENTF_UNICODE,
                        time = 0,
                        dwExtraInfo = nint.Zero
                    }
                }
            };

            inputs[i * 2 + 1] = new INPUT
            {
                type = INPUT_KEYBOARD,
                u = new INPUTUNION
                {
                    ki = new KEYBDINPUT
                    {
                        wVk = 0,
                        wScan = scan,
                        dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP,
                        time = 0,
                        dwExtraInfo = nint.Zero
                    }
                }
            };
        }
        return inputs;
    }
}
