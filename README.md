# Windows Security SChannel Examples

This project contains C code examples demonstrating the use of the Windows Secure Channel (SChannel) API for TLS/SSL communication and other security-related operations.

## Files

*   `enum_sec_pkgs.c`: Demonstrates how to enumerate available security packages.
*   `schannel_init.c`: Shows a basic example of initializing SChannel for a TLS client and inspecting the ClientHello message.

## Requirements

*   Windows operating system
*   A C compiler that supports Windows development (e.g., MinGW GCC or Microsoft Visual C++)
*   Linker access to `Secur32.lib` (usually part of the Windows SDK)

## Building the Examples

You will need to compile each `.c` file separately.

### Using GCC (MinGW)

```sh
gcc enum_sec_pkgs.c -o enum_sec_pkgs.exe -lsecur32
gcc schannel_init.c -o schannel_init.exe -lsecur32
```

### Using Microsoft Visual C++ (cl.exe)

Open a Developer Command Prompt for Visual Studio.

```sh
cl enum_sec_pkgs.c /link secur32.lib /out:enum_sec_pkgs.exe
cl schannel_init.c /link secur32.lib /out:schannel_init.exe
```

## Running the Examples

After successful compilation, you can run the executables directly from the command line:

```sh
./enum_sec_pkgs.exe
./schannel_init.exe
```

Note that `schannel_init.exe` will attempt to initiate a TLS handshake with `localhost`. For this to fully succeed, a TLS server would need to be listening on `localhost`. However, the program will print the ClientHello structure even without a server present.
