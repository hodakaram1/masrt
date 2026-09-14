# Masiam — Imno GUI + DBKKernel driver

`Imno` is a native Windows GUI memory tool (scanner, cheat table, byte patcher,
pointer resolver, and a DBK64 kernel feature tab) backed by the `DBKKernel`
(DBK64) kernel driver — the Cheat Engine-style kernel driver.

- `Imno/` — the user-mode GUI (`Imno.cpp` / `Imno.h`). Talks to the driver over
  the `IOCTL_CE_*` device-control interface (byte-identical to
  `DBKKernel/IOPLDispatcher.h`).
- `DBKKernel/` — the kernel driver, built as `DBK64.sys` (x64) / `DBK32.sys` (x86).
- `third_party/` — vendored, pinned third-party sources compiled directly into
  the GUI (no vcpkg or external package manager required):
  - **Dear ImGui** `v1.90.9`
  - **GLFW** `3.3.9`
  - **Zydis** `v4.1.0` + **Zycore** `v1.5.0`
- `Imno/CEServer.cpp` / `Imno/CEServer.h` — a **CEServer bridge**: Imno speaks
  Cheat Engine's `CEServer` TCP protocol so a real Cheat Engine can connect
  over the network and use Imno + DBK64 as its memory backend (works on
  protected processes and 32-bit targets).
- `King.sln` — solution that builds `DBKKernel` then `Imno` (Imno depends on
  DBKKernel). `build.bat` builds the Release x64 configuration (default) and
  logs errors to `build_error.log`. The driver's Release config builds
  **without** the `TOBESIGNED` self-check **and without `/INTEGRITYCHECK`**, so
  a test-signed `DBK64.sys` can be loaded in test mode.

## How Imno loads the driver

On startup, `Imno` (run as **Administrator**):

1. Enables `SeDebugPrivilege` (the driver refuses to open without it).
2. Creates/starts the `DBK64` kernel service pointing at `DBK64.sys` next to the
   executable, and writes the four registry values the driver reads at
   `DriverEntry` (`A` = device name, `B` = symlink, `C`/`D` = event names) under
   `HKLM\SYSTEM\CurrentControlSet\Services\DBK64`.
3. Opens `\\.\DBK64` and issues the IOCTLs.

Both projects end up in `<repo>\x64\Release\`, so `DBK64.sys` lands next to
`Imno.exe` (`build.bat` gathers the two artifacts into that folder).

## Requirements to build

Everything the GUI needs is already in the repo (`third_party/`). You only need:

- **Visual Studio 2019** (v142 toolset) **or Visual Studio 2022** (v143 toolset),
  any edition (Community/Professional/Enterprise/BuildTools), with the
  **"Desktop development with C++"** workload (includes the Windows 10 SDK).
  `build.bat` locates MSBuild automatically via `vswhere.exe`.
- **Windows Driver Kit (WDK 10)** for the `WindowsKernelModeDriver10.0` platform
  toolset (needed to build the `DBKKernel` driver), installed for the same
  Visual Studio version.

No vcpkg / Conan / NuGet setup is required — `Imno` compiles Dear ImGui, GLFW,
Zydis and Zycore straight from the vendored sources.

## Building

```
build.bat            # Release x64 (default), writes errors to build_error.log
build.bat Debug      # Debug x64 if you need it
```
or open `King.sln` in Visual Studio, set **Release | x64**, and build.

## Running

1. Make sure `DBK64.sys` is next to `Imno.exe` (it is, after a solution build).
2. **Test-sign the driver** (required on x64 — an *unsigned* driver can never
   load, even in test mode):
   ```
   sign_driver.bat
   ```
   This creates a self-signed code-signing certificate once and signs
   `x64\Release\DBK64.sys` with it.
3. Put the machine in **test mode** once (admin command prompt), then reboot:
   ```
   bcdedit /set testsigning on
   ```
   A "Test Mode" watermark should appear in the desktop corner.
4. **Disable Secure Boot** in the BIOS/UEFI and turn off **Memory Integrity /
   Core isolation (HVCI)** (Windows Security → Device security → Core
   isolation). Both block test-signed drivers.
5. Run `Imno.exe` as **Administrator**. If the driver still does not connect,
   click **Reconnect** in the top bar — Imno now shows the exact reason
   (missing file, service start error, Win32 exit code, device open error) in
   a message box, and also prints it in the Kernel tab's status field.

> The steps in 2–4 are one-time machine setup. With test mode enabled and
> Secure Boot/HVCI off, the test-signed driver loads every time afterwards.

## Using Cheat Engine with Imno (CoServer tab)

Imno can act as a Cheat Engine `CEServer` (the same protocol CE's own remote
server uses). Run `Imno.exe` on the target machine, open the **CoServer** tab,
press **Start Server** (default port `52736`), then on your Cheat Engine side:

1. Open the **Process List** → **Network**.
2. Enter the target machine's IP and the port shown in Imno, and connect.
3. The process list now comes from Imno; scanning, reading and writing memory
   all go through **DBK64**, so protected processes and 32-bit games work even
   when Cheat Engine's own driver would be blocked.

The bridge exposes the memory API surface Cheat Engine uses: process/module/
thread enumeration, open process, read/write, region query, allocation and
memory-protection change. Debugging, injection and speedhack are not supported
and are reported as failures that Cheat Engine tolerates.

The **Log** panel in the CoServer tab shows every command the client sends and
the handle each snapshot returns. If Cheat Engine reports
`I can't get the process list`, run the protocol self-test while the server is
running (it replays Cheat Engine's exact process-list handshake):

```sh
python tools/ceserver_selftest.py 127.0.0.1 52736
```

## Notes

- The scanner enumerates memory regions **through the driver**
  (`IOCTL_CE_QUERY_VIRTUAL_MEMORY`), so it works on protected processes
  (e.g. `svchost`/PPL) and on guarded 32-bit games. Pointers for 32-bit targets
  are resolved as 4-byte pointers automatically.
- The driver's Release configuration is built **without** `TOBESIGNED` (the
  Dark Byte signature self-check), because `Imno.exe` is not signed with Dark
  Byte's key, and **without** `/INTEGRITYCHECK`, because that PE flag forces a
  WHQL/Azure-signature requirement that even test-signed drivers cannot
  satisfy. If you ever obtain a WHQL/attestation signing certificate you can
  re-enable both in `DBKKernel/DBKKernel.vcxproj` and load without test mode.
