# USB-Recovery 🔬💾

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![Zero Telemetry](https://img.shields.io/badge/Telemetry-0%25%20Air--Gapped-success.svg)](README.md)
[![Forensic Grade](https://img.shields.io/badge/Forensic-Chain%20of%20Custody-orange.svg)](README.md)
[![Tests Passing](https://img.shields.io/badge/Tests-46000%2B%20PASS-brightgreen.svg)](README.md)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](README.md)

[English](README.md) · [Русский](README.ru.md)

**USB-Recovery** is an enterprise-grade, high-performance open-source Digital Forensics and Incident Response (DFIR) & Data Recovery suite. Built from the ground up for forensic examiners, security researchers, and incident responders, it delivers complete write-blocking integrity, multi-gigabyte-per-second carving, and deep filesystem/artifact reconstruction across raw devices and forensic disk images.

---

## ⚡ Highlights

- **Forensic Containers & Virtual Disks**: Native, pure C# random-access stream readers for **E01 / Ex01 (Expert Witness)**, **AFF4 (Advanced Forensic Format 4)**, **QCOW2 (QEMU / KVM v2/v3)**, **VHD**, **VHDX**, and **VMDK**.
- **Modern Filesystem Scouts**: Metadata-level traversal and carving for **exFAT** (deep deleted directory set carving 0x05+0x40+0x41, contiguous NoFatChain stream extraction, primary/backup VBR checksum), **HFS+ / HFSX** (Apple catalog B-Tree traversal, direct extent mapping, orphan record carving from node slack), **F2FS** (flash-friendly NAT table, inline inode payloads, extent mapping), **Btrfs** (chunk tree & generation traversal), **XFS** (allocation group & BMBT trees), **ZFS** (uberblock & dnode traversal), **APFS**, **Ext4**, **ReFS**, **NTFS**, and **FAT12/16/32**.
- **Deep Windows Forensic Artifacts**:
  - **NTFS USN Change Journal ($UsnJrnl:$J)**: V2/V3 streaming parser, 48-bit MFT indexing, and complete deleted file lifecycle reconstruction.
  - **NTFS $MFT Record Carver**: 1024-byte `FILE` record carver with Fixup array correction, resident payload extraction, data runs unpacking, and timestomping divergence detection.
  - **REGF Windows Registry Hive Engine**: Hierarchical traversal, cell decoding, slack cell carving for wiped keys/values, and automatic system summary extraction (`SYSTEM`, `SOFTWARE`, `SAM`).
  - **Amcache.hve Parser**: Windows 10/11 `InventoryApplicationFile` & Windows 7/8 `File` hive parser with program execution forensics, SHA-1 binary hash extraction, and threat heuristics (TEMP directory execution, double extensions).
  - **Shellbags Parser**: `UsrClass.dat`/`NTUSER.DAT` `BagMRU` hierarchical folder access history on removable USB storage, drive letters, and network shares.
  - **Shimcache / AppCompatCache**: Windows 7/8 (`0xBADC0FFE`) and Windows 10/11 (`10ts`) execution cache parser.
  - **Shannon Entropy Classifier**: Streaming, zero-telemetry entropy classifier calculating byte Shannon entropy ($H = -\sum p \log_2 p$) with automated ransomware anomaly detection.
  - **Rule 902(14) Expert Witness Court Package**: Automated forensic court report generator compliant with Federal Rule of Evidence 902(14) and ISO/IEC 27037 with SHA-256 Chain of Custody hashes.
  - **SRUM Exfiltration & Resource Monitor**: Windows System Resource Usage Monitor (`SRUDB.dat`) ESE parser, mapping application execution, user SIDs, interface LUIDs, byte-accurate network exfiltration, and CPU/energy metrics.
  - **Windows Jump Lists Forensic Parser**: AutomaticDestinations (CFBF/OLE compound format) and CustomDestinations parser, extracting MRU access order, pin status, execution timestamps, NetBIOS hostnames, Volume/File DROIDs, embedded LNK payloads, and threat alerts.
  - **Windows Recycle Bin Forensic Parser**: Windows Vista/7/8/10/11 ($I / $R) parser and carver with User SID resolution, original path reconstruction, payload integrity verification, anti-forensics tampering alerts, and direct file restoration.
  - **Super-Timeline Engine**: Multi-source chronological timeline aggregator (USN, MFT, EVTX, Prefetch, LNK, Browser History, Shimcache, Amcache, Shellbags, SRUM, Jump Lists, Recycle Bin, exFAT, HFS+) with RFC 4180 CSV export.
  - **SQLite B-Tree Carver**: Deep database carver analyzing freeblocks, freelist pages, and orphan record cells.
- **Forensic Benchmark Suite**: High-throughput benchmarking measuring SWAR signature scanning rate, Shannon entropy throughput, MFT parsing speed, and strictly validating zero-leak memory stability.
- **Local Web-UI (`http://127.0.0.1:8080`)**: Zero-dependency local web dashboard featuring interactive tabs for Cluster Allocation Map, Hex Inspector, MFT Carver, Shimcache, Super-Timeline, Amcache, Shellbags, Entropy, Court Report, on-the-fly streaming ZIP downloader, and cryptographic Chain-of-Custody report generator.
- **Zero-Bloat & Air-Gapped**: Strict 64 KiB O(1) buffer bounds, no Large Object Heap (LOH) fragmentation, 100% loopback-only networking (`127.0.0.1`), zero outbound telemetry.

---

## 📊 Competitive Benchmark Matrix

| Capability / Feature | USB-Recovery | PhotoRec / TestDisk | Autopsy / SleuthKit | R-Studio (Commercial) |
| :--- | :---: | :---: | :---: | :---: |
| **License & Price** | **Free & Open Source (AGPL-3)** | Free (GPLv2) | Free (Apache 2.0) | Proprietary ($80 – $900) |
| **Forensic Images** | **E01, AFF4, QCOW2, VHD/X, VMDK, ddrescue** | RAW, partial E01 | RAW, E01 | RAW, E01, VHD/X, VMDK |
| **Btrfs / XFS / ZFS Metadata** | **Native Extent Scouts** | ❌ None | ⚠️ Basic / Partial | Native |
| **USN Journal Deleted Recovery** | **Automatic Lifecycle Reconstruct** | ❌ None | ⚠️ Manual module | Basic |
| **MFT Slack & Timestomping** | **Built-in Carver & Divergence Alert** | ❌ None | Plugin required | Basic |
| **Windows REGF Hive Carver** | **Slack Cell & Key Carving** | ❌ None | RegRipper needed | Viewer only |
| **Shimcache / AppCompatCache** | **Native Win7/10/11 Parser** | ❌ None | Plugin required | ❌ None |
| **Amcache & Execution Forensics** | **Built-in Win7/10/11 & SHA-1 Carve** | ❌ None | Plugin required | ❌ None |
| **Shellbags (USB & Folder History)** | **Native BagMRU Hierarchical Parser** | ❌ None | Plugin required | ❌ None |
| **SRUM Network Exfiltration** | **Built-in ESE Carving & IdMap Correlation** | ❌ None | SrumECmd needed | ❌ None |
| **Windows Jump Lists (Automatic/Custom)** | **Native CFBF & Category LNK Parser** | ❌ None | JLECmd needed | ❌ None |
| **Windows Recycle Bin ($I / $R)** | **Native V1/V2 Parser, File Restoration & Carving** | ❌ None | Plugin required | Basic |
| **Shannon Entropy & Ransomware** | **O(1) Streaming Anomaly Engine** | ❌ None | ❌ None | Basic entropy view |
| **Rule 902(14) Expert Witness Report** | **Automated ISO/IEC 27037 & SHA-256** | ❌ None | Manual export | Basic report |
| **Flash / F2FS Filesystem Scout** | **Native Superblock & NAT Carver** | ❌ None | ❌ None | Basic |
| **Super-Timeline Aggregator** | **Built-in RFC 4180 CSV Export** | ❌ None | Plaso integration | ❌ None |
| **Built-in Cluster Map & Hex Viewer** | **Zero-Dependency Web-UI (127.0.0.1)** | ❌ CLI only | Heavy Java GUI | Desktop GUI only |
| **Memory & Resource Footprint** | **Strict O(1) 64 KiB Buffers** | Light (C) | Heavy (Java VM / Solr) | Moderate (C++) |
| **Write-Blocking Guarantees** | **100% Guaranteed Stream-Level** | OS-dependent | Stream-Level | Stream-Level |

---

## 🖥️ Command Line Interface (CLI)

`USB-Recovery.exe` provides a comprehensive headless CLI for scripted forensic workflows and automated triage:

### Forensic Artifacts & Timeline
```bash
# Generate unified forensic super-timeline from an image or disk
USB-Recovery.exe timeline C:\images\evidence.e01 -o timeline.csv --from 2026-01-01 --to 2026-12-31

# Parse NTFS USN Change Journal and reconstruct deleted file lifecycles
USB-Recovery.exe usn C:\images\volume.raw --deleted --json

# Carve 1024-byte NTFS $MFT FILE records and dump resident payloads to folder
USB-Recovery.exe carve-mft C:\images\disk.aff4 -o C:\cases\mft_dump\

# Inspect Windows REGF registry hive and dump system summary
USB-Recovery.exe registry C:\cases\SYSTEM --summary

# Carve deleted keys and slack cells from registry hive
USB-Recovery.exe registry C:\cases\NTUSER.DAT --carve

# Parse Amcache.hve for binary executions and SHA-1 threat indicators
USB-Recovery.exe amcache C:\cases\Amcache.hve --json

# Parse Shellbags for USB drive history and folder access tracking
USB-Recovery.exe shellbags C:\cases\UsrClass.dat --json

# Parse Windows SRUM database and detect network exfiltration
USB-Recovery.exe srum C:\cases\SRUDB.dat --json

# Parse Windows Jump Lists (.automaticDestinations-ms / .customDestinations-ms)
USB-Recovery.exe jumplist C:\Users\Admin\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations --json

# Parse Windows Recycle Bin, analyze user SIDs, and restore files to destination
USB-Recovery.exe recycle-bin C:\$Recycle.Bin -o C:\recovered_recycle --json

# Scout Volume Shadow Copies (VSS), snapshot catalog & CoW block descriptors
USB-Recovery.exe vss-scout C:\images\evidence.raw --json

# Scout ISO 9660 / Joliet / UDF optical & hybrid USB flash volumes, carve and restore files
USB-Recovery.exe iso-scout C:\images\hybrid_installer.iso -o C:\recovered_iso --json

# Analyze Chromium & Firefox extensions, crypto wallets (MetaMask, Phantom) & LevelDB credentials
USB-Recovery.exe browser-extensions C:\Users\Admin\AppData\Local\Google\Chrome\User Data\Default --json

# Audit Windows Event Log (.evtx), logons, service installations & anti-forensics log wiping
USB-Recovery.exe evtx C:\Windows\System32\winevt\Logs\Security.evtx --json

# Analyze stream Shannon entropy and detect ransomware encryption
USB-Recovery.exe entropy C:\images\evidence.raw --json

# Generate Federal Rule of Evidence 902(14) Expert Witness Court Package
USB-Recovery.exe court-report C:\images\evidence.e01 -o C:\reports\court_package.html

# Scout F2FS flash filesystem superblocks, NAT mappings, and file extents
USB-Recovery.exe f2fs-scout C:\images\nvme_flash.raw

# Scout exFAT flash storage, carve deleted directory entry sets & recover files
USB-Recovery.exe exfat-scout C:\images\sdcard_exfat.raw --json

# Scout Apple HFS+ / HFSX catalog B-Tree and carve orphan file records
USB-Recovery.exe hfs-scout C:\images\macos_disk.raw

# Run high-throughput forensic benchmark and zero-leak memory audit
USB-Recovery.exe benchmark

# Parse Windows Shell Link (.lnk) shortcut files and TrackerDataBlocks
USB-Recovery.exe lnk C:\cases\recent\document.lnk
```

### Disk Images & Interactive Web-UI
```bash
# Launch interactive local Web-UI with Cluster Map & Hex Inspector
USB-Recovery.exe serve C:\images\disk.qcow2 --port 8080 --open-browser

# Inspect disk image structure, partition tables, and filesystem signatures
USB-Recovery.exe probe C:\images\disk.vhdx

# Execute non-interactive deep forensic recovery scan
USB-Recovery.exe scan C:\images\usb.e01 -o C:\recovered --mode full --fs ntfs
```

---

## 🏗️ Architecture & Memory Safety

```
[ Forensic Disk Image / Raw Device ]
               │
  (Strict Read-Only Stream · 0 Bytes Outbound Network)
               │
   ┌───────────┴────────────────────────────────────────┐
   │ Virtual Disk Subsystem                             │
   │ (E01 · AFF4 · QCOW2 · VHD/VHDX · VMDK · ddrescue)   │
   └───────────┬────────────────────────────────────────┘
               │
   ┌───────────┴────────────────────────────────────────┐
   │ FastVectorScanner (SWAR Word-Parallel SIMD)        │
   │ 64 KiB Fixed Buffer · Zero LOH Allocations         │
   └───────────┬────────────────────────────────────────┘
               │
   ┌───────────┼───────────────────────────┬────────────┐
   ▼                           ▼           ▼            ▼
[ $MFT Carver ]       [ USN Journal ]  [ REGF Hive ]  [ SQLite Carver ]
(Resident Payloads)   (Deleted Files)  (Slack Cells)  (Freelist Cells)
   │                           │           │            │
   └───────────┬───────────────┴───────────┴────────────┘
               ▼
   [ ForensicTimeline Engine ]
   (Chronological Super-Timeline · RFC 4180 CSV / JSON)
               ▼
   [ LocalWebServer (127.0.0.1) / Headless CLI ]
   (Cluster Allocation Map · Hex Inspector · ZIP Streamer)
```

- **Zero Memory Leaks**: All carving and parsing engines operate with bounded 64 KiB sliding buffers, keeping allocations far below the .NET Large Object Heap (LOH) 85,000-byte boundary.
- **Zero Disk Bloat**: Test fixtures and ephemeral data are automatically reclaimed with RAII deterministic cleanup.
- **Chain of Custody**: Every recovered artifact is hashed with SHA-256 upon export, preserving evidential integrity for court presentation.

---

## 🛠️ Build & Installation

### Windows (.NET Framework 4.8)
```powershell
# Clone the repository
git clone https://github.com/fl1nky/usb-recovery.git
cd usb-recovery

# Build the standalone executable
powershell -ExecutionPolicy Bypass -File scripts\build-app.ps1

# Run tests
powershell -ExecutionPolicy Bypass -File scripts\package.ps1
```

### Linux / macOS (Headless .NET 8.0)
```bash
dotnet build src/Recovery/Recovery.Net8.csproj -c Release
```

---

## 📄 License

Licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.  
Copyright (C) 2026 USB-Recovery Contributors. 100% Free & Open Source · Zero Telemetry.
