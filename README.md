# Direct Syscall Injector & EDR Hook Evasion Analysis

A low-level C++ and x64 MASM Proof-of-Concept (PoC) demonstrating **user-land EDR hook evasion** through **dynamic System Service Number (SSN) resolution** and custom assembly dispatchers. 

This project was built to stress-test custom user-mode Endpoint Detection and Response (EDR) agents, analyze hook detection/bypass vectors, and document defensive capabilities across the Windows user/kernel boundary.

---

## Overview & Research Background

Traditional EDR solutions inject a user-mode agent DLL into target processes to place inline hooks (`JMP` detours) on Native APIs (`ntdll.dll`). This project explores how adversaries bypass user-space telemetry using direct kernel transitions (`syscall`), while evaluating the trade-offs and limits of user-land inspection engines.

### Key Capabilities
- **Hook Detection Engine:** Scans full API call chains (`kernel32.dll` $\rightarrow$ `kernelbase.dll` $\rightarrow$ `ntdll.dll`) for byte-level detour signatures (`0xE9` / `0xEB`).
- **Dynamic SSN Resolver:** Extracts SSNs directly from unmanaged `ntdll` memory using custom ROR/ROL string hashing.
- **Neighbor Stub Evasion (Halo's Gate Pattern):** If a target API stub is patched/hooked by an EDR, the engine scans adjacent 32-byte stub signatures in memory to calculate valid relative SSNs.
- **Universal Assembly Dispatcher:** Uses dynamic register management (`R10`, `R11`) to prevent return-address overwrite and register corruption during hook trampolines.

---

## Technical Architecture

```text
[ Injector Application ]
       │
       ├──> 1. Parse PEB ──> Locate ntdll.dll Base
       ├──> 2. Export Parsing & ROR/ROL Hash Lookup       ├──> 3. Scan Stub Signature (0x4C, 0x8B, 0xD1, 0xB8)
       │       └── [If Hooked] ──> Search Neighbor Stubs ──> Calculate SSN
       └──> 4. Invoke Assembly Dispatcher (`invoke_syscall`) ──────> [ Windows Kernel ]


Disclaimer: All research and code execution were conducted in an isolated, dedicated laboratory environment strictly for educational and defense-research purposes.
