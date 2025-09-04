#pragma once

// Architecture/platform helpers and registers used by the RunPE logic

#if defined (_M_ARM)
#define EnvARM
#define Unsupported
#define IgnoreMainCode
#elif defined(_M_X64) || defined(_WIN64)
#define Env64
// In the initial suspended thread context:
//  - RDX points to the PEB
//  - PEB->ImageBaseAddress is at offset 0x10 in PEB64
//  - RCX is used by the start thunk to hold the entry address
#define PEB_PTR_REG        Rdx
#define PEB_IMAGEBASE_OFF  0x10
#define ENTRY_REG          Rcx
#else
#define Env86
// In x86:
//  - EBX points to the PEB
//  - PEB->ImageBaseAddress is at offset 0x8 in PEB32
//  - EAX is used by the start thunk to hold the entry address
#define PEB_PTR_REG        Ebx
#define PEB_IMAGEBASE_OFF  8
#define ENTRY_REG          Eax
#endif

#if defined (Unsupported)
#pragma message ("Platform unsupported !!!!")
#endif

