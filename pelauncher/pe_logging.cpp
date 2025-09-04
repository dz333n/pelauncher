#include "stdafx.h"
#include "pe_logging.h"

static LPCWSTR kUnknown = L"UNKNOWN";

LPCWSTR DirName(UINT i)
{
    switch (i)
    {
    case IMAGE_DIRECTORY_ENTRY_EXPORT: return L"EXPORT";
    case IMAGE_DIRECTORY_ENTRY_IMPORT: return L"IMPORT";
    case IMAGE_DIRECTORY_ENTRY_RESOURCE: return L"RESOURCE";
    case IMAGE_DIRECTORY_ENTRY_EXCEPTION: return L"EXCEPTION";
    case IMAGE_DIRECTORY_ENTRY_SECURITY: return L"SECURITY";
    case IMAGE_DIRECTORY_ENTRY_BASERELOC: return L"BASERELOC";
    case IMAGE_DIRECTORY_ENTRY_DEBUG: return L"DEBUG";
    case IMAGE_DIRECTORY_ENTRY_ARCHITECTURE: return L"ARCHITECTURE";
    case IMAGE_DIRECTORY_ENTRY_GLOBALPTR: return L"GLOBALPTR";
    case IMAGE_DIRECTORY_ENTRY_TLS: return L"TLS";
    case IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: return L"LOAD_CONFIG";
    case IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: return L"BOUND_IMPORT";
    case IMAGE_DIRECTORY_ENTRY_IAT: return L"IAT";
    case IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: return L"DELAY_IMPORT";
    case IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: return L"COM_DESCRIPTOR";
    default: return kUnknown;
    }
}

VOID LogDosHeader(HWND hDlg, const IMAGE_DOS_HEADER* dos)
{
    if (!dos) return;
    Logf(hDlg, L"DOS Header: e_magic=0x%04X e_lfanew=0x%08X", dos->e_magic, (UINT)dos->e_lfanew);
}

VOID LogFileHeader(HWND hDlg, const IMAGE_FILE_HEADER* fh)
{
    if (!fh) return;
    Logf(hDlg, L"FileHeader: Machine=0x%04X Sections=%u TimeDateStamp=0x%08X",
        fh->Machine, fh->NumberOfSections, fh->TimeDateStamp);
    Logf(hDlg, L"  SizeOfOptionalHeader=%u Characteristics=0x%04X",
        fh->SizeOfOptionalHeader, fh->Characteristics);
}

VOID LogOptionalHeader32(HWND hDlg, const IMAGE_OPTIONAL_HEADER32* oh)
{
    if (!oh) return;
    Logf(hDlg, L"OptionalHeader32: Magic=0x%04X Linker=%u.%u EntryRVA=0x%08X",
        oh->Magic, oh->MajorLinkerVersion, oh->MinorLinkerVersion, oh->AddressOfEntryPoint);
    Logf(hDlg, L"  BaseOfCode=0x%08X BaseOfData=0x%08X", oh->BaseOfCode, oh->BaseOfData);
    Logf(hDlg, L"  ImageBase=0x%08X SectionAlign=0x%X FileAlign=0x%X",
        oh->ImageBase, oh->SectionAlignment, oh->FileAlignment);
    Logf(hDlg, L"  SizeOfImage=0x%X SizeOfHeaders=0x%X Checksum=0x%X",
        oh->SizeOfImage, oh->SizeOfHeaders, oh->CheckSum);
    Logf(hDlg, L"  Subsystem=%u DllCharacteristics=0x%04X",
        oh->Subsystem, oh->DllCharacteristics);
    Logf(hDlg, L"  OSVer=%u.%u ImgVer=%u.%u SubsysVer=%u.%u",
        oh->MajorOperatingSystemVersion, oh->MinorOperatingSystemVersion,
        oh->MajorImageVersion, oh->MinorImageVersion,
        oh->MajorSubsystemVersion, oh->MinorSubsystemVersion);
    Logf(hDlg, L"  SizeOfStackReserve=0x%X SizeOfStackCommit=0x%X",
        oh->SizeOfStackReserve, oh->SizeOfStackCommit);
    Logf(hDlg, L"  SizeOfHeapReserve=0x%X SizeOfHeapCommit=0x%X",
        oh->SizeOfHeapReserve, oh->SizeOfHeapCommit);
    UINT maxDirs = (oh->NumberOfRvaAndSizes < IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
        ? oh->NumberOfRvaAndSizes
        : IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    for (UINT i = 0; i < maxDirs; ++i)
    {
        const auto& d = oh->DataDirectory[i];
        if (d.VirtualAddress || d.Size)
            Logf(hDlg, L"  DataDir[%02u] %-14s RVA=0x%08X Size=0x%08X", i, DirName(i), d.VirtualAddress, d.Size);
    }
}

VOID LogOptionalHeader64(HWND hDlg, const IMAGE_OPTIONAL_HEADER64* oh)
{
    if (!oh) return;
    Logf(hDlg, L"OptionalHeader64: Magic=0x%04X Linker=%u.%u EntryRVA=0x%08X",
        oh->Magic, oh->MajorLinkerVersion, oh->MinorLinkerVersion, oh->AddressOfEntryPoint);
    Logf(hDlg, L"  BaseOfCode=0x%08X", oh->BaseOfCode);
    Logf(hDlg, L"  ImageBase=0x%016llX SectionAlign=0x%X FileAlign=0x%X",
        (unsigned long long)oh->ImageBase, oh->SectionAlignment, oh->FileAlignment);
    Logf(hDlg, L"  SizeOfImage=0x%llX SizeOfHeaders=0x%X Checksum=0x%X",
        (unsigned long long)oh->SizeOfImage, oh->SizeOfHeaders, oh->CheckSum);
    Logf(hDlg, L"  Subsystem=%u DllCharacteristics=0x%04X",
        oh->Subsystem, oh->DllCharacteristics);
    Logf(hDlg, L"  OSVer=%u.%u ImgVer=%u.%u SubsysVer=%u.%u",
        oh->MajorOperatingSystemVersion, oh->MinorOperatingSystemVersion,
        oh->MajorImageVersion, oh->MinorImageVersion,
        oh->MajorSubsystemVersion, oh->MinorSubsystemVersion);
    Logf(hDlg, L"  SizeOfStackReserve=0x%llX SizeOfStackCommit=0x%llX",
        (unsigned long long)oh->SizeOfStackReserve, (unsigned long long)oh->SizeOfStackCommit);
    Logf(hDlg, L"  SizeOfHeapReserve=0x%llX SizeOfHeapCommit=0x%llX",
        (unsigned long long)oh->SizeOfHeapReserve, (unsigned long long)oh->SizeOfHeapCommit);
    UINT maxDirs = (oh->NumberOfRvaAndSizes < IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
        ? oh->NumberOfRvaAndSizes
        : IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    for (UINT i = 0; i < maxDirs; ++i)
    {
        const auto& d = oh->DataDirectory[i];
        if (d.VirtualAddress || d.Size)
            Logf(hDlg, L"  DataDir[%02u] %-14s RVA=0x%08X Size=0x%08X", i, DirName(i), d.VirtualAddress, d.Size);
    }
}

VOID LogSections(HWND hDlg, const IMAGE_SECTION_HEADER* firstSection, WORD numberOfSections)
{
    if (!firstSection || !numberOfSections) return;
    Logf(hDlg, L"Sections (%u):", numberOfSections);
    for (WORD i = 0; i < numberOfSections; ++i)
    {
        const IMAGE_SECTION_HEADER& sh = firstSection[i];
        char nameA[9] = { 0 };
        memcpy(nameA, sh.Name, 8);
        Logf(hDlg, L"  %2u: %-8hs VA=0x%08X VSz=0x%08X RawPtr=0x%08X RawSz=0x%08X Ch=0x%08X",
            i, nameA, sh.VirtualAddress, sh.Misc.VirtualSize, sh.PointerToRawData, sh.SizeOfRawData, sh.Characteristics);
    }
}

