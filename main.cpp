#include <fstream>
#include <cstdio>
#include <cstring>
#include <vector>
#include <string>
#include <windows.h>
#include "BinaryStream.hpp"
#include "utils.hpp"

using namespace std;

struct PESection
{
    char Name[9];
    uint32_t VirtualSize;
    uint32_t VirtualOffset;
    uint32_t RawSize;
    uint32_t RawOffset;
    uint32_t Flags;
    bool Unreal;
};

PESection Sections[16];
uint16_t SectionCount;

std::fstream Exe;

uint32_t LfaNew;
uint32_t SectionAlignment;
uint32_t FileAlignment;

uint32_t ImageBase;

struct PEImport
{
    std::string ModuleName;
    struct PEFunction
    {
        bool ByOrdinal;
        uint32_t Ordinal;
        std::string Name;
        uint16_t Hint;
        uint32_t OriginalAddress;
    };

    std::vector<PEFunction> Functions;
};

std::vector<PEImport> Imports;

uint32_t EntryPoint;

uint32_t UpdateSections()
{
    Exe.seekg(LfaNew + 0x06);
    Exe.read((char*)&SectionCount, 2);

    Exe.seekg(LfaNew + 0x38);
    Exe.read((char*)&SectionAlignment, 4);
    Exe.read((char*)&FileAlignment, 4);

    uint32_t section_hdr = LfaNew + 0xF8;
    for(uint16_t i = 0; i < SectionCount; i++)
    {
        if(i >= 16) return 1;
        Exe.seekg(section_hdr + i * 0x28);
        Sections[i].Name[8] = 0;
        Exe.read(Sections[i].Name, 8);
        Exe.read((char*)&Sections[i].VirtualSize, 4);
        Exe.read((char*)&Sections[i].VirtualOffset, 4);
        Exe.read((char*)&Sections[i].RawSize, 4);
        Exe.read((char*)&Sections[i].RawOffset, 4);
        Exe.seekg(12, ios::cur);
        Exe.read((char*)&Sections[i].Flags, 4);
        Sections[i].Unreal = false;
    }
    return 0;
}

uint32_t RvaToVa(uint32_t offset)
{
    return offset - ImageBase;
}

uint32_t VaToRva(uint32_t offset)
{
    return offset + ImageBase;
}

uint32_t AbsToVa(uint32_t offset)
{
    for(uint16_t i = 0; i < SectionCount; i++)
        if(offset >= Sections[i].RawOffset && offset < Sections[i].RawOffset + Sections[i].RawSize)
            return offset - Sections[i].RawOffset + Sections[i].VirtualOffset;

    return 0;
}

uint32_t VaToAbs(uint32_t offset)
{
    for(uint16_t i = 0; i < SectionCount; i++)
        if(offset >= Sections[i].VirtualOffset && offset < Sections[i].VirtualOffset + Sections[i].VirtualSize)
            return offset - Sections[i].VirtualOffset + Sections[i].RawOffset;

    return 0;
}

uint32_t AlignInt(uint32_t what, uint32_t alignment)
{
    if (what % alignment == 0)
        return what;
    return what + (alignment - (what % alignment));
}

uint32_t AddImaginarySection(char* name, uint32_t flags, uint32_t size)
{
    if(SectionCount >= 16)
    {
        printf("Fatal error: tried to create invalid section (section count overflow 16)\n");
        return 1;
    }

    uint32_t nsec_size = size;
    uint32_t nsec_flags = flags;

    if(!nsec_size || !nsec_flags)
    {
        printf("Fatal error: tried to create invalid section (size=%X, flags=%08X)\n", nsec_size, nsec_flags);
        return 1;
    }

    uint32_t sec_siz_raw = nsec_size;// + (FileAlignment - nsec_size % FileAlignment);
    uint32_t sec_siz_vrt = nsec_size;// + (SectionAlignment - nsec_size % SectionAlignment);

    // now, find end of last section
    //uint32_t last_raw = Sections[SectionCount-1].RawOffset + (Sections[SectionCount-1].RawSize + (FileAlignment - Sections[SectionCount-1].RawSize % FileAlignment));
    //uint32_t last_vraw = Sections[SectionCount-1].VirtualOffset + (Sections[SectionCount-1].VirtualSize + (SectionAlignment - Sections[SectionCount-1].VirtualSize % SectionAlignment));
    uint32_t last_raw = AlignInt(Sections[SectionCount-1].RawOffset + Sections[SectionCount-1].RawSize, FileAlignment);
    uint32_t last_vraw = AlignInt(Sections[SectionCount-1].VirtualOffset + Sections[SectionCount-1].VirtualSize, SectionAlignment);

    PESection sec;
    sec.Flags = flags;
    sec.Name[8] = 0;
    strncpy(sec.Name, name, 8);
    sec.RawOffset = last_raw;
    sec.RawSize = sec_siz_raw;
    sec.VirtualOffset = last_vraw;
    sec.VirtualSize = sec_siz_vrt;
    sec.Unreal = true;

    Sections[SectionCount] = sec;
    SectionCount++;

    return 0;
}

uint32_t AddSection(char* name, uint32_t flags, uint32_t size)
{
    if(UpdateSections() == 1) return 1;

    if(SectionCount >= 16)
    {
        printf("Fatal error: tried to create invalid section (section count overflow 16)\n");
        return 1;
    }

    char* nsec_name = name;
    uint32_t nsec_size = size;
    uint32_t nsec_flags = flags;

    if(!nsec_size || !nsec_flags)
    {
        printf("Fatal error: tried to create invalid section (size=%X, flags=%08X)\n", nsec_size, nsec_flags);
        return 1;
    }

    uint32_t sec_siz_raw = nsec_size;
    uint32_t sec_siz_vrt = nsec_size;

    // now, find end of last section
    //uint32_t last_raw = Sections[SectionCount-1].RawOffset + (Sections[SectionCount-1].RawSize + (FileAlignment - Sections[SectionCount-1].RawSize % FileAlignment));
    uint32_t last_raw = AlignInt(Sections[SectionCount-1].RawOffset + Sections[SectionCount-1].RawSize, FileAlignment);
    Exe.seekp(last_raw);
    char* sec_zeros = new char[sec_siz_raw];
    memset(sec_zeros, 0, sec_siz_raw);
    Exe.write(sec_zeros, sec_siz_raw);

    // SectionCount + 1
    Exe.seekp(LfaNew + 0x06);
    uint16_t sec_cnt = SectionCount + 1;
    Exe.write((char*)&sec_cnt, 2);

    // Add section to table
    char psec_name[8];
    memset(psec_name, 0, 8);
    strncpy(psec_name, nsec_name, 8);
    uint32_t psec_vsize = sec_siz_vrt;
    //uint32_t psec_vaddr = Sections[SectionCount-1].VirtualOffset + (Sections[SectionCount-1].VirtualSize + (SectionAlignment - Sections[SectionCount-1].VirtualSize % SectionAlignment));
    uint32_t psec_vaddr = AlignInt(Sections[SectionCount-1].VirtualOffset + Sections[SectionCount-1].VirtualSize, SectionAlignment);
    uint32_t psec_rsize = sec_siz_raw;
    uint32_t psec_raddr = last_raw;
    uint32_t psec_reloc = 0;
    uint32_t psec_lines = 0;
    uint16_t psec_relocnum = 0;
    uint16_t psec_linesnum = 0;
    uint32_t psec_flags = nsec_flags;

    Exe.seekp(LfaNew + 0xF8 + SectionCount * 0x28);
    Exe.write(psec_name, 8);
    Exe.write((char*)&psec_vsize, 4);
    Exe.write((char*)&psec_vaddr, 4);
    Exe.write((char*)&psec_rsize, 4);
    Exe.write((char*)&psec_raddr, 4);
    Exe.write((char*)&psec_reloc, 4);
    Exe.write((char*)&psec_lines, 4);
    Exe.write((char*)&psec_relocnum, 2);
    Exe.write((char*)&psec_linesnum, 2);
    Exe.write((char*)&psec_flags, 4);

    // Image size
    Exe.seekg(LfaNew + 0x50);
    uint32_t image_size;
    Exe.read((char*)&image_size, 4);
    //image_size += psec_vsize + (SectionAlignment - psec_vsize % SectionAlignment);
    image_size += AlignInt(psec_vsize, SectionAlignment);
    Exe.seekp(LfaNew + 0x50);
    Exe.write((char*)&image_size, 4);

    return UpdateSections();
}

uint32_t ReadImports()
{
    Exe.seekg(LfaNew + 0x74);
    uint32_t dir_count;
    Exe.read((char*)&dir_count, 4);

    if(dir_count != 16) // odd
    {
        printf("Fatal error: unsupported PE format.\n");
        return 1;
    }

    Exe.seekg(LfaNew + 0x80);
    uint32_t imp_va;
    Exe.read((char*)&imp_va, 4);

    Imports.clear();

    uint32_t i_OriginalFirstThunk;
    uint32_t i_TimeDateStamp;
    uint32_t i_ForwarderChain;
    uint32_t i_Name;
    uint32_t i_FirstThunk;
    uint32_t cur_module = 0;

    while(true)
    {
        PEImport imp;
        Exe.seekg(VaToAbs(imp_va) + 0x14 * cur_module);

        Exe.read((char*)&i_OriginalFirstThunk, 4);
        Exe.read((char*)&i_TimeDateStamp, 4);
        Exe.read((char*)&i_ForwarderChain, 4);
        Exe.read((char*)&i_Name, 4);
        Exe.read((char*)&i_FirstThunk, 4);

        if(!i_Name || !i_FirstThunk) break;

        std::string mod_name = "";
        Exe.seekg(VaToAbs(i_Name));
        char ch;
        do
        {
            Exe.read(&ch, 1);
            mod_name += ch;
        }
        while(ch);

        imp.ModuleName = mod_name;
        imp.Functions.clear();

        uint32_t base_thunk;

        //if(!i_OriginalFirstThunk) base_thunk = VaToAbs(i_FirstThunk);
        //else base_thunk = VaToAbs(i_OriginalFirstThunk);
        base_thunk = VaToAbs(i_FirstThunk);

        uint32_t i_addr;
        uint32_t cur_func = 0;
        while(true)
        {
            Exe.seekg(base_thunk + 4 * cur_func);

            PEImport::PEFunction func;
            func.OriginalAddress = Exe.tellg();
            Exe.read((char*)&i_addr, 4);

            if(!i_addr) break;

            if((i_addr & 0x80000000) != 0x80000000)
            {
                Exe.seekg(VaToAbs(i_addr));
                Exe.read((char*)&func.Hint, 2);
                std::string func_name = "";
                func.ByOrdinal = false;
                func.Ordinal = 0;
                char ch;
                do
                {
                    Exe.read(&ch, 1);
                    func_name += ch;
                }
                while(ch);
                func.Name = func_name;
            }
            else
            {
                func.ByOrdinal = true;
                func.Name = "";
                func.Hint = 0;
                func.Ordinal = i_addr & 0x7FFFFFFF;
            }

            imp.Functions.push_back(func);

            cur_func++;
        }

        Imports.push_back(imp);

        cur_module++;
    }

    return 0;
}

#define INJ_JMP  0
#define INJ_CALL 1

#define ORD_FLAG 0x80000000
#define NUL_FLAG 0x40000000

struct LoadInjection
{
    uint32_t InjectionType;
    uint32_t InjectionAddress;
};

struct LoadFunction
{
    uint32_t NameAddr;
    uint32_t FuncAddr;
    uint32_t Option;
    std::string Name;
    std::vector<LoadInjection> Injections;
};

struct LoadExport
{
    uint32_t FunctionsAddr;
    uint32_t FileNameAddr;
    std::string FileName;
    uint32_t ModuleNameAddr;
    std::string ModuleName;
    std::vector<LoadFunction> Functions;
};

std::vector<LoadExport> Exports;
std::string ExeName = "";

vector<string> ParseCommandLine(string what)
{
    what = Trim(what);
    std::vector<std::string> args;
    std::string current = "";
    bool in_encaps = false;
    for(size_t i = 0; i < what.length(); i++)
    {
        char cch = what[i];
        if(cch == '\\' && i != what.length()-1)
        {
            current += what[i+1];
        }
        else if(cch == ' ')
        {
            if(in_encaps)
                current += cch;
            else
            {
                if(current.length()) args.push_back(current);
                current = "";
            }
        }
        else if(cch == '"') in_encaps = !in_encaps;
        else if(cch == ';' && !in_encaps) break;
        else
        {
            current += cch;
        }
    }
    if(current.length()) args.push_back(current);
    return args;
}

uint32_t LoadConfig(std::string filename)
{
    ifstream cfg;
    cfg.open(filename.c_str(), ios::in);
    if(!cfg.is_open())
    {
        printf("Fatal error: couldn't open file %s for reading!\n", filename.c_str());
        return 1;
    }

    printf("Loading script \"%s\"...\n", filename.c_str());

    LoadExport exp;

    string str;
    while(getline(cfg, str))
    {
        vector<string> args = ParseCommandLine(str);
        if(args.size() < 2) continue;

        if(ToLower(args[0]) == "executable" && !ExeName.length())
        {
            ExeName = args[1];
            printf("Executable name: %s\n", ExeName.c_str());
            exp.ModuleName.clear();
            exp.FileName.clear();
            exp.Functions.clear();
        }
        else if(ToLower(args[0]) == "module" && ExeName.length())
        {
            if(exp.ModuleName.length()) Exports.push_back(exp);
            exp.Functions.clear();
            exp.FileName = args[1];
            printf("Adding module: %s\n", exp.FileName.c_str());
            exp.ModuleName = Basename(TruncateSlashes(FixSlashes(exp.FileName)));
            size_t fp = exp.ModuleName.find_last_of('.');
            if(fp != string::npos)
                exp.ModuleName.erase(fp);
        }
        else if((ToLower(args[0]) == "jmp" || ToLower(args[0]) == "call") && exp.ModuleName.length() && args.size() >= 3)
        {
            bool byOrd = CheckInt(args[1]);
            std::string name = args[1];
            uint32_t ordinal = 0;
            if(byOrd) ordinal = StrToInt(args[1]);

            uint32_t type = INJ_JMP;
            if(ToLower(args[0]) == "call") type = INJ_CALL;

            uint32_t addr = HexToInt(args[2]);

            LoadInjection inj;
            inj.InjectionType = type;
            inj.InjectionAddress = addr;

            bool found = false;
            for(std::vector<LoadFunction>::iterator it = exp.Functions.begin(); it != exp.Functions.end(); ++it)
            {
                LoadFunction& func = (*it);
                if((!byOrd && func.Name == args[1]) ||
                    (byOrd && (func.Option & 0x7FFFFFFF) == ordinal))
                {
                    func.Injections.push_back(inj);
                    found = true;
                }
            }

            if(!found)
            {
                LoadFunction newf;
                if(byOrd) newf.Option = ordinal | ORD_FLAG;
                else
                {
                    newf.Option = 0;
                    newf.Name = name;
                }

                newf.Injections.push_back(inj);
                exp.Functions.push_back(newf);
            }

            if(byOrd) printf("Added injection: %08X <- %s %s.%u\n", addr, (type == INJ_JMP ? "JMP " : "CALL"), exp.ModuleName.c_str(), ordinal);
            else printf("Added injection: %08X <- %s %s!%s\n", addr, (type == INJ_JMP ? "JMP " : "CALL"), exp.ModuleName.c_str(), name.c_str());

        }
    }

    if(exp.ModuleName.length()) Exports.push_back(exp);

    cfg.close();
    return 0;
}

int main(int argc, char* argv[])
{
    if(argc != 2)
    {
        printf("Invalid arguments.\n");
        printf("Usage: DLLInject.exe <script>\n");
        printf("  <script> - a file in following format:\n");
        printf("              EXECUTABLE <executable_name.exe>\n");
        printf("              MODULE <module_name.dll>\n");
        printf("              <CALL|JMP> <ordinal|name> <RVA hex>\n");
        printf("                                ...\n");
        printf("              <CALL|JMP> <ordinal|name> <RVA hex>\n");
        printf("              MODULE <module_name_2.dll>\n");
        printf("              ...\n");
        printf("             Note: only one executable at a time is supported.\n");
        return 0;
    }

    printf("==================\n");
    printf(" DLLInject v1.00\n");
    printf(" (c) 2012 ZZYZX\n");
    printf("------------------\n");

    if(LoadConfig(argv[1]) != 0) return 1;

    Exe.open(ExeName.c_str(), ios::out | ios::in | ios::binary);
    if(!Exe.is_open())
    {
        printf("Fatal error: couldn't open input file for reading!\n");
        return 1;
    }

    uint16_t magic_dos;
    Exe.seekg(0);
    Exe.read((char*)&magic_dos, 2);
    if(magic_dos != 0x5A4D) // MZ
    {
        printf("Fatal error: opened file is not a valid PE!\n");
        return 1;
    }

    Exe.seekg(0x3C);
    Exe.read((char*)&LfaNew, 4);

    Exe.seekg(LfaNew);
    uint32_t magic_win;
    Exe.read((char*)&magic_win, 4);
    if(magic_win != 0x4550)
    {
        printf("Fatal error: opened file is not a valid PE!\n");
        return 1;
    }

    Exe.seekg(LfaNew + 0x34);
    Exe.read((char*)&ImageBase, 4);

    Exe.seekg(LfaNew + 0x28);
    Exe.read((char*)&EntryPoint, 4);

    if(UpdateSections() != 0) return 1;

    printf("Examining PE imports...\n");

    if(ReadImports() == 1) return 1;

    uint32_t aMsvcrtDll = 0;        // "msvcrt.dll"
    uint32_t aSprintf = 0;          // "sprintf"
    uint32_t aUser32Dll = 0;        // "user32.dll"
    uint32_t aMessageBoxA = 0;      // "MessageBoxA"
    uint32_t aDLLInjectLoader_ = 0; // "DLLInject Loader Error"
    uint32_t aModuleNotFound = 0;   // "Module '%s' not found!"
    uint32_t aFunctionNotFnd_1 = 0; // "Function %s.%u not found!"
    uint32_t aFunctionNotFnd_2 = 0; // "Function %s.%s not found!"
    uint32_t aSprintfArray = 0;     // array for sprintf

    uint32_t addr_msvcrt = 0;
    uint32_t addr_sprintf = 0;
    uint32_t addr_user32 = 0;
    uint32_t addr_messagebox = 0;

    uint32_t addr_ep = 0;

    printf("Inserting import data...\n");

    // create .dijdata
    if(AddImaginarySection(".zidata", 0xC0000040, 0x10000) == 1) return 1;
    uint32_t sdbd = VaToRva(Sections[SectionCount-1].VirtualOffset);
    BinaryStream sd;
    addr_ep = sdbd + sd.GetCurrentPosition();
    sd.WriteUInt32(VaToRva(EntryPoint));
    aMsvcrtDll = sdbd + sd.GetCurrentPosition();
    sd.WriteRawString("msvcrt.dll");
    addr_msvcrt = sdbd + sd.GetCurrentPosition();
    sd.WriteUInt32(0); // for HMODULE
    aSprintf = sdbd + sd.GetCurrentPosition();
    sd.WriteRawString("sprintf");
    addr_sprintf = sdbd + sd.GetCurrentPosition();
    sd.WriteUInt32(0); // for sprintf addr
    aUser32Dll = sdbd + sd.GetCurrentPosition();
    sd.WriteRawString("user32.dll");
    addr_user32 = sdbd + sd.GetCurrentPosition();
    sd.WriteUInt32(0); // for HMODULE
    aMessageBoxA = sdbd + sd.GetCurrentPosition();
    sd.WriteRawString("MessageBoxA");
    addr_messagebox = sdbd + sd.GetCurrentPosition();
    sd.WriteUInt32(0);
    aDLLInjectLoader_ = sdbd + sd.GetCurrentPosition();
    sd.WriteRawString("DLLInject Loader Error");
    aModuleNotFound = sdbd + sd.GetCurrentPosition();
    sd.WriteRawString("Module '%s' not found!");
    aFunctionNotFnd_1 = sdbd + sd.GetCurrentPosition();
    sd.WriteRawString("Function %s.%u not found!");
    aFunctionNotFnd_2 = sdbd + sd.GetCurrentPosition();
    sd.WriteRawString("Function %s.%s not found!");
    aSprintfArray = sdbd + sd.GetCurrentPosition();
    sd.WriteFixedString("", 0xFF);
    // now write strings for modules and importing by name
    for(std::vector<LoadExport>::iterator it = Exports.begin(); it != Exports.end(); ++it)
    {
        // module names
        LoadExport& exp = (*it);
        exp.FileNameAddr = sdbd + sd.GetCurrentPosition();
        sd.WriteRawString(exp.FileName);
        exp.ModuleNameAddr = sdbd + sd.GetCurrentPosition();
        sd.WriteRawString(exp.ModuleName);

        for(std::vector<LoadFunction>::iterator jt = exp.Functions.begin(); jt != exp.Functions.end(); ++jt)
        {
            LoadFunction& func = (*jt);
            if((func.Option & ORD_FLAG) != ORD_FLAG)
            {
                func.NameAddr = sdbd + sd.GetCurrentPosition();
                sd.WriteRawString(func.Name);
            }
        }
    }

    // write functions array
    for(std::vector<LoadExport>::iterator it = Exports.begin(); it != Exports.end(); ++it)
    {
        // module names
        LoadExport& exp = (*it);
        exp.FunctionsAddr = sdbd + sd.GetCurrentPosition();

        for(std::vector<LoadFunction>::iterator jt = exp.Functions.begin(); jt != exp.Functions.end(); ++jt)
        {
            LoadFunction& func = (*jt);
            sd.WriteUInt32(func.Option);
            func.FuncAddr = sdbd + sd.GetCurrentPosition();
            sd.WriteUInt32(0); // for GetProcAddress
            if((func.Option & ORD_FLAG) != ORD_FLAG)
                sd.WriteUInt32(func.NameAddr);
        }
        sd.WriteUInt32(NUL_FLAG);
    }

    uint32_t exports_offs = sdbd + sd.GetCurrentPosition();

    // write modules array
    for(std::vector<LoadExport>::iterator it = Exports.begin(); it != Exports.end(); ++it)
    {
        // module names
        LoadExport& exp = (*it);
        sd.WriteUInt32(exp.FileNameAddr);
        sd.WriteUInt32(exp.ModuleNameAddr);
        sd.WriteUInt32(exp.FunctionsAddr);
    }

    sd.WriteUInt32(0);
    sd.WriteUInt32(0);
    sd.WriteUInt32(0);

    printf("Linking loader code...\n");

    uint8_t code_loader_abort[] =
        {
            0x6A, 0x01,                             // push     1
            0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,     // call     [ExitProcess]
            0xC3,                                   // retn

            0xCC, 0xCC, 0xCC, 0xCC,
            0xCC, 0xCC, 0xCC,                       // Align
        };

    uint8_t code_loader_module[] =
        {
            0x55,                                   // push     ebp
            0x8B, 0xEC,                             // mov      ebp, esp
            0x83, 0xEC, 0x08,                       // sub      esp, 8
            0x8B, 0x45, 0x10,                       // mov      eax, [ebp+0x10]
            0x89, 0x45, 0xFC,                       // mov      [ebp-0x04], eax
            0x6A, 0x00,                             // push     0
            0x6A, 0x00,                             // push     0
            0xFF, 0x75, 0x08,                       // push     [ebp+0x08]
            0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,     // call     [LoadLibrary]
            //0x83, 0xC4, 0x08,                       // add      esp, 0x08
            0x90, 0x90, 0x90,
            0x85, 0xC0,                             // test     eax, eax
            0x74, 0x6B,                             // jz       module_error
            0x89, 0x45, 0xF8,                       // mov      [ebp-0x08], eax
            // do_loop_func:
            0x8B, 0x45, 0xFC,                       // mov      eax, [ebp-0x04]
            0x8B, 0x08,                             // mov      ecx, [eax]
            0x81, 0xE1, 0x00, 0x00, 0x00, 0x40,     // and      ecx, 0x40000000
            0x81, 0xF9, 0x00, 0x00, 0x00, 0x40,     // cmp      ecx, 0x40000000
            0x74, 0x4F,                             // jz       end_module_func
            0x8B, 0x08,                             // mov      ecx, [eax]
            0x81, 0xE1, 0x00, 0x00, 0x00, 0x80,     // and      ecx, 0x80000000
            0x81, 0xF9, 0x00, 0x00, 0x00, 0x80,     // cmp      ecx, 0x80000000
            0x75, 0x22,                             // jnz      load_by_name
            0x8B, 0x08,
            0x81, 0xE1, 0xFF, 0xFF, 0x00, 0x00,     // and      ecx, 0x0000FFFF
            0x51,                                   // push     ecx
            0xFF, 0x75, 0xF8,                       // push     [ebp-0x08]
            0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,     // call     [GetProcAddress]
            0x85, 0xC0,                             // test     eax, eax
            0x74, 0x5D,                             // jz       function_error
            0x8B, 0x5D, 0xFC,                       // mov      ebx, [ebp-0x04]
            0x89, 0x43, 0x04,                       // mov      [ebx+0x04], eax
            0x83, 0x45, 0xFC, 0x08,                 // add      dword ptr [ebp-0x04], 0x08
            0xEB, 0xBB,                             // jmp      do_loop_func
            // load_by_name:
            0x8B, 0x58, 0x08,                       // mov      ebx, [eax+0x08]
            0x53,                                   // push     ebx
            0xFF, 0x75, 0xF8,                       // push     [ebp-0x08]
            0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,     // call     [GetProcAddress]
            0x85, 0xC0,                             // test     eax, eax
            0x74, 0x40,                             // jz       function_error
            0x8B, 0x5D, 0xFC,                       // mov      ebx, [ebp-0x04]
            0x89, 0x43, 0x04,                       // mov      [ebx+0x04], eax
            0x83, 0x45, 0xFC, 0x0C,                 // add      dword ptr [ebp-0x04], 0x0C
            0xEB, 0x9E,                             // jmp      do_loop_func
            // end_module_func:
            0x8B, 0xE5,                             // mov      esp, ebp
            0x5D,                                   // pop      ebp
            0xC2, 0x0C, 0x00,                       // retn     0x000C
            // module_error:
            0xFF, 0x75, 0x08,                       // push     [ebp+0x08]
            0x68, 0x00, 0x00, 0x00, 0x00,           // push     offset aModuleNotFound
            0x68, 0x00, 0x00, 0x00, 0x00,           // push     offset aSprintfArray
            0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,     // call     [sprintf]
            0x6A, 0x10,                             // push     0x00000010
            0x68, 0x00, 0x00, 0x00, 0x00,           // push     offset aSprintfArray
            0x68, 0x00, 0x00, 0x00, 0x00,           // push     offset aDLLInjectLoader_
            0x6A, 0x00,                             // push     0
            0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,     // call     [MessageBox]
            0xE8, 0x39, 0xFF, 0xFF, 0xFF,           // call     loader_abort
            0xEB, 0xCC,                             // jmp      end_module_func
            // function_error:
            0x8B, 0x45, 0xFC,                       // mov      eax, [ebp-0x04]
            0x8B, 0x08,                             // mov      ecx, [eax]
            0x81, 0xE1, 0x00, 0x00, 0x00, 0x80,     // and      ecx, 0x80000000
            0x81, 0xF9, 0x00, 0x00, 0x00, 0x80,     // cmp      ecx, 0x80000000
            0x75, 0x32,                             // jnz      function_error_name
            0x8B, 0x18,
            0x81, 0xE1, 0xFF, 0xFF, 0x00, 0x00,     // and      ecx, 0x0000FFFF
            0x51,                                   // push     ecx
            0xFF, 0x75, 0x0C,                       // push     [ebp+0x0C]
            0x68, 0x00, 0x00, 0x00, 0x00,           // push     offset aFunctionNotFnd_1
            0x68, 0x00, 0x00, 0x00, 0x00,           // push     offset aSprintfArray
            0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,     // call     [sprintf]
            0x6A, 0x10,                             // push     0x00000010
            0x68, 0x00, 0x00, 0x00, 0x00,           // push     offset aSprintfArray
            0x68, 0x00, 0x00, 0x00, 0x00,           // push     offset aDLLInjectLoader_
            0x6A, 0x00,                             // push     0
            0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,     // call     [MessageBox]
            0xEB, 0x2D,                             // jmp      function_error_abort
            // function_error_name:
            //0x8B, 0x48, 0x08,                       // mov      ecx, [eax+0x08]
            0x90, 0x90, 0x90,
            0x53,                                   // push     ebx
            0xFF, 0x75, 0x0C,                       // push     [ebp+0x0C]
            0x68, 0x00, 0x00, 0x00, 0x00,           // push     offset aFunctionNotFnd_2
            0x68, 0x00, 0x00, 0x00, 0x00,           // push     offset aSprintfArray
            0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,     // call     [sprintf]
            0x6A, 0x10,                             // push     0x00000010
            0x68, 0x00, 0x00, 0x00, 0x00,           // push     offset aSprintfArray
            0x68, 0x00, 0x00, 0x00, 0x00,           // push     offset aDLLInjectLoader_
            0x6A, 0x00,                             // push     0
            0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,     // call     [MessageBox]
            0xEB, 0x00,                             // jmp      function_error_abort
            // function_error_abort:
            0xE8, 0xC0, 0xFE, 0xFF, 0xFF,           // call     loader_abort
            0xE9, 0x50, 0xFF, 0xFF, 0xFF,           // jmp      end_module_func
            0xCC, 0xCC,                             // Align


        };

    uint8_t code_loader_main[] =
        {
            0x55,                                   // push     ebp
            0x8B, 0xEC,                             // mov      ebp, esp
            0x83, 0xEC, 0x04,                       // sub      esp, 4
            0xB8, 0x00, 0x00, 0x00, 0x00,           // mov      eax, offset exports_offs
            0x89, 0x45, 0xFC,                       // mov      [ebp-4], eax
            // do_loadnext:
            0x8B, 0x5D, 0xFC,                       // mov      ebx, [ebp-4]
            0x8B, 0x03,                             // mov      eax, [ebx]
            0x0B, 0x43, 0x04,                       // and      eax, [ebx+4]
            0x0B, 0x43, 0x08,                       // and      eax, [ebx+8]
            0x85, 0xC0,                             // test     eax, eax
            0x74, 0x13,                             // jz       do_endload
            0xFF, 0x73, 0x08,                       // push     [ebx+8]
            0xFF, 0x73, 0x04,                       // push     [ebx+4]
            0xFF, 0x33,                             // push     [ebx]
            0xE8, 0x9F, 0xFE, 0xFF, 0xFF,           // call     loader_module
            0x83, 0x45, 0xFC, 0x0C,                 // add      dword ptr [ebp-4], 0x0C
            0xEB, 0xDE,                             // jmp      do_loadnext
            // do_endload:
            0x8B, 0xE5,                             // mov      esp, ebp
            0x5D,                                   // pop      ebp
            0xC3,                                   // retn

            0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // Align
        };

    uint8_t code_loader_ep[] =
        {
            0x56,                                   // push     esi
            0x57,                                   // push     edi
            0x68, 0x00, 0x00, 0x00, 0x00,           // push     offset aMsvcrtDll
            0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,     // call     [LoadLibraryA]
            0x85, 0xC0,                             // test     eax, eax
            0x74, 0x5E,                             // jz       ep_error
            0xA3, 0x00, 0x00, 0x00, 0x00,           // mov      [addr_msvcrt], eax
            0x68, 0x00, 0x00, 0x00, 0x00,           // push     offset aSprintf
            0xFF, 0x35, 0x00, 0x00, 0x00, 0x00,     // push     [addr_msvcrt]
            0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,     // call     [GetProcAddress]
            0x85, 0xC0,                             // test     eax, eax
            0x74, 0x44,                             // jz       ep_error
            0xA3, 0x00, 0x00, 0x00, 0x00,           // mov      [addr_sprintf], eax
            0x56,                                   // push     esi
            0x57,                                   // push     edi
            0x68, 0x00, 0x00, 0x00, 0x00,           // push     offset aUser32Dll
            0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,     // call     [LoadLibraryA]
            0x85, 0xC0,                             // test     eax, eax
            0x74, 0x2E,                             // jz       ep_error
            0xA3, 0x00, 0x00, 0x00, 0x00,           // mov      [addr_user32], eax
            0x68, 0x00, 0x00, 0x00, 0x00,           // push     offset aMessageBoxA
            0xFF, 0x35, 0x00, 0x00, 0x00, 0x00,     // push     [addr_user32]
            0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,     // push     [GetProcAddress]
            0x85, 0xC0,                             // test     eax, eax
            0x74, 0x14,                             // jz       ep_error
            0xA3, 0x00, 0x00, 0x00, 0x00,           // mov      [addr_messagebox], eax
            0xE8, 0x5D, 0xFF, 0xFF, 0xFF,           // call     loader_main
            0x5F,                                   // pop      edi
            0x5E,                                   // pop      esi
            0x5F,                                   // pop      edi
            0x5E,                                   // pop      esi
            0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,     // jmp      [EntryPoint]
            // ep_error:
            0x5F,                                   // pop      edi
            0x5E,                                   // pop      esi
            0x5F,                                   // pop      edi
            0x5E,                                   // pop      esi
            0xE8, 0x03, 0xFE, 0xFF, 0xFF,           // call     loader_abort
            0xC3,
        };

    uint32_t addr_loadlibrary = 0;
    uint32_t addr_getprocaddr = 0;
    uint32_t addr_exitprocess = 0;
    for(std::vector<PEImport>::iterator it = Imports.begin(); it != Imports.end(); ++it)
    {
        PEImport& imp = (*it);
        if(ToLower(imp.ModuleName).find("kernel32.dll") == 0)
        {
            for(std::vector<PEImport::PEFunction>::iterator jt = imp.Functions.begin(); jt != imp.Functions.end(); ++jt)
            {
                PEImport::PEFunction& func = (*jt);
                if(func.Name.find("LoadLibrary") == 0)
                    addr_loadlibrary = VaToRva(AbsToVa(func.OriginalAddress));
                else if(func.Name.find("GetProcAddress") == 0)
                    addr_getprocaddr = VaToRva(AbsToVa(func.OriginalAddress));
                else if(func.Name.find("ExitProcess") == 0)
                    addr_exitprocess = VaToRva(AbsToVa(func.OriginalAddress));
            }
            break;
        }
    }

    if(!addr_loadlibrary)
    {
        printf("Fatal error: opened file does NOT link to kernel32.dll!LoadLibrary\n");
        return 1;
    }

    if(!addr_getprocaddr)
    {
        printf("Fatal error: opened file does NOT link to kernel32.dll!GetProcAddress\n");
        return 1;
    }

    if(!addr_exitprocess)
    {
        printf("Fatal error: opened file does NOT link to kernel32.dll!ExitProcess\n");
        return 1;
    }

    // link loader_abort
    *(uint32_t*)(code_loader_abort + 0x04) = addr_exitprocess;

    // link loader_module
    *(uint32_t*)(code_loader_module + 0x15) = addr_loadlibrary;
    *(uint32_t*)(code_loader_module + 0x54) = addr_getprocaddr;
    *(uint32_t*)(code_loader_module + 0x71) = addr_getprocaddr;
    *(uint32_t*)(code_loader_module + 0x8F) = aModuleNotFound;
    *(uint32_t*)(code_loader_module + 0x94) = aSprintfArray;
    *(uint32_t*)(code_loader_module + 0x9A) = addr_sprintf;
    *(uint32_t*)(code_loader_module + 0xA1) = aDLLInjectLoader_;
    *(uint32_t*)(code_loader_module + 0xA6) = aSprintfArray;
    *(uint32_t*)(code_loader_module + 0xAE) = addr_messagebox;
    *(uint32_t*)(code_loader_module + 0xD9) = aFunctionNotFnd_1;
    *(uint32_t*)(code_loader_module + 0xDE) = aSprintfArray;
    *(uint32_t*)(code_loader_module + 0xE4) = addr_sprintf;
    *(uint32_t*)(code_loader_module + 0xEB) = aDLLInjectLoader_;
    *(uint32_t*)(code_loader_module + 0xF0) = aSprintfArray;
    *(uint32_t*)(code_loader_module + 0xF8) = addr_messagebox;
    *(uint32_t*)(code_loader_module + 0x106) = aFunctionNotFnd_2;
    *(uint32_t*)(code_loader_module + 0x10B) = aSprintfArray;
    *(uint32_t*)(code_loader_module + 0x111) = addr_sprintf;
    *(uint32_t*)(code_loader_module + 0x118) = aDLLInjectLoader_;
    *(uint32_t*)(code_loader_module + 0x11D) = aSprintfArray;
    *(uint32_t*)(code_loader_module + 0x125) = addr_messagebox;

    // link loader_main
    *(uint32_t*)(code_loader_main + 0x07) = exports_offs;

    // link loader_ep
    *(uint32_t*)(code_loader_ep + 0x03) = aMsvcrtDll;
    *(uint32_t*)(code_loader_ep + 0x09) = addr_loadlibrary;
    *(uint32_t*)(code_loader_ep + 0x12) = addr_msvcrt;
    *(uint32_t*)(code_loader_ep + 0x17) = aSprintf;
    *(uint32_t*)(code_loader_ep + 0x1D) = addr_msvcrt;
    *(uint32_t*)(code_loader_ep + 0x23) = addr_getprocaddr;
    *(uint32_t*)(code_loader_ep + 0x2C) = addr_sprintf;
    *(uint32_t*)(code_loader_ep + 0x33) = aUser32Dll;
    *(uint32_t*)(code_loader_ep + 0x39) = addr_loadlibrary;
    *(uint32_t*)(code_loader_ep + 0x42) = addr_user32;
    *(uint32_t*)(code_loader_ep + 0x47) = aMessageBoxA;
    *(uint32_t*)(code_loader_ep + 0x4D) = addr_user32;
    *(uint32_t*)(code_loader_ep + 0x53) = addr_getprocaddr;
    *(uint32_t*)(code_loader_ep + 0x5C) = addr_messagebox;
    *(uint32_t*)(code_loader_ep + 0x6B) = addr_ep;
    printf("addr_ep = %08X\n", addr_ep);

    printf("Inserting loader code...\n");

    sd.WriteData(code_loader_abort, sizeof(code_loader_abort));
    sd.WriteData(code_loader_module, sizeof(code_loader_module));
    sd.WriteData(code_loader_main, sizeof(code_loader_main));
    uint32_t new_ep = Sections[SectionCount-1].VirtualOffset + sd.GetCurrentPosition();
    sd.WriteData(code_loader_ep, sizeof(code_loader_ep));
    sd.WriteUInt32(0);

    printf("Writing loader into PE...\n");

    uint32_t difflen = AlignInt(sd.GetLength(), 0x100);

    // done building
    AddSection(".zidata", 0xE0000040, difflen);

    Exe.seekp(Sections[SectionCount-1].RawOffset);
    Exe.write((char*)sd.GetBuffer().data(), sd.GetBuffer().size());

    Exe.seekp(LfaNew + 0x28);
    Exe.write((char*)&new_ep, 4);

    printf("Injecting code...\n");

    // now, write injections
    uint8_t inj_jmp[] = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};
    uint8_t inj_call[] = {0xFF, 0x15, 0x00, 0x00, 0x00, 0x00};

    for(std::vector<LoadExport>::iterator it = Exports.begin(); it != Exports.end(); ++it)
    {
        // module names
        LoadExport& exp = (*it);

        for(std::vector<LoadFunction>::iterator jt = exp.Functions.begin(); jt != exp.Functions.end(); ++jt)
        {
            LoadFunction& func = (*jt);

            for(std::vector<LoadInjection>::iterator kt = func.Injections.begin(); kt != func.Injections.end(); ++kt)
            {
                LoadInjection& inj = (*kt);
                uint32_t addri = RvaToVa(inj.InjectionAddress);
                uint32_t addra = VaToAbs(addri);
                if(!addri || !addra)
                {
                    printf("Warning: RVA %08X NOT found, skipped.\n", inj.InjectionAddress);
                    continue;
                }

                Exe.seekp(addra);
                if(inj.InjectionType == INJ_JMP)
                {
                    *(uint32_t*)(inj_jmp + 2) = func.FuncAddr;
                    Exe.write((char*)inj_jmp, sizeof(inj_jmp));
                }
                else
                {
                    *(uint32_t*)(inj_call + 2) = func.FuncAddr;
                    Exe.write((char*)inj_call, sizeof(inj_call));
                }

            }
        }
    }

    Exe.close();

    return 0;
}
