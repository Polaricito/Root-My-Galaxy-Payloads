# SM-A546E FZF4 ADB shell port

This is an initial shell-only port for the exact fingerprint containing `A546EXXSKFZF4` and kernel `5.15.189-android13-3-33470412`.

It uses:

- tracefs `sched_blocked_reason` for the exact boot KASLR slide;
- `perf_event_open` plus `mm_page_alloc` for the exact PFN of one user-controlled 4 KiB page;
- either MCAST or SIGRETURN/FPSIMD for the GhostLock stack write;
- the shared configfs, pipe physrw, and workqueue UMH stages after `ashmem_misc.fops` changes.

The app payload is not ready. No fake P0 fingerprint is shipped. An A54 app build fails explicitly until a real FZF4 fingerprint is generated. The A54 `all` target builds only the shell payload and root helper.

## Build

From WSL:

```sh
export ANDROID_NDK_HOME=/path/to/android-ndk-r29
make TARGET=a54x-A546EXXSKFZF4 STACK_WRITER=mcast clean
make TARGET=a54x-A546EXXSKFZF4 STACK_WRITER=mcast all perf-page-test native-mcast-test
```

For the fallback writer, replace `mcast` with `sigreturn`.

## Test order

Run each stage on the exact FZF4 firmware. The standalone perf and slide tests do not invoke GhostLock.

```powershell
.\tools\test-a54x-shell.ps1 -Mode probe -Writer mcast
.\tools\test-a54x-shell.ps1 -Mode slide -Writer mcast
.\tools\test-a54x-shell.ps1 -Mode page -Writer mcast
```

The perf gate must print `PERF_PAGE_OK` with exactly one `order0_match`. The probe pre-faults the two neighboring pages before enabling perf, matching the proven clean path. The slide gate must print `slide-kaslr-ok source=tracefs`. The page gate runs both safe discovery layers and the real compact payload builder, then stops before GhostLock. Stop if any gate fails.

The MCAST overlap probe invokes GhostLock. Run it only on a boot that may be rebooted afterward:

```powershell
.\tools\test-a54x-shell.ps1 -Mode mcast-probe -Writer mcast
```

The first full run is one attempt only:

```powershell
.\tools\test-a54x-shell.ps1 -Mode full -Writer mcast
```

After a reboot, the SIGRETURN backend can be tested with:

```powershell
.\tools\test-a54x-shell.ps1 -Mode full -Writer sigreturn
```

Keep the full log. Important gates are `perf page ready`, `p0 physical write`, `cfi misc_fops`, `cfi write/read`, pipe physrw, and root UMH.
