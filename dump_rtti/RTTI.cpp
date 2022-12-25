// ============================================================================
// dump_rtti/RTTI.cpp
// Part of the Skyrim64 Reverse Engineering Toolkit (SkyRETK)
// 
// Copyright (c) 2022 Nox Sidereum (for 64-bit Skyrim)
//               2017 Himika (for 32-bit Skyrim)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the “Software”), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is furnished
// to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
// 
// (The MIT License)
// ============================================================================
#pragma comment(lib, "Dbghelp.lib")

#include <dbghelp.h>
#include <vector>
#include <sstream>
#include <shlobj.h>
#include <iomanip>
#include <string>

#include "RTTI.h"

// ============================================================================
//   A. Scan for, and save, the addresses of all RTTI type descriptors and 
//      their associated virtual function tables.
// ============================================================================
void LoadVTables(const UInt64 baseAddr, std::map<UInt64, VtblList>& vtblMap)
{
    UInt64 textStart = baseAddr + TEXT_SEG_BEGIN;
    UInt64 textEnd = baseAddr + TEXT_SEG_END;

    UInt64 rdataStart = baseAddr + RDATA_SEG_BEGIN;
    UInt64 rdataEnd = baseAddr + RDATA_SEG_END;
    UInt64 vtblTypeInfo = baseAddr + TYPE_INFO_VTBL;

    UInt64 dataStart = baseAddr + DATA_SEG_BEGIN;
    UInt64 dataEnd = baseAddr + DATA_SEG_END;

    // 1. Given the address of type_info's vftable, we can locate all of the object 
    //    TypeDescriptors by scanning .DATA for 64-bit memory addresses containing 
    //    that address.
    // 
    //    E.g. 0x41E9F968 is the address of the TypeDescriptor for BaseFormComponent.
    //    It has:
    //      -> 00: pVFTable    == 0x419752C0
    //      -> 08: spare       == 0
    //      -> 10: name        == ".?AVBaseFormComponent@@" (null-terminated).
    //
    //    N.B. For this example, we assume the module base address is 0x40000000.
    for (UInt64 i = dataStart; i < dataEnd; i += 8)
    {
        UInt64* p = reinterpret_cast<UInt64*>(i);
        if (*p == vtblTypeInfo) {
            // We have probably found a TypeDescriptor.
            // 
            // 2. Now find the RTTICompleteObjectLocator structure for this TypeDescriptor. 
            //    On x64 platforms, we scan .RDATA for all 32-bit memory addresses containing 
            //    the OFFSET of that TypeDescriptor from the module base. We assume such
            //    addresses are the "pTypeDescriptor" field of an RTTICompleteObjectLocator.
            // 
            //    E.g. 0x41975F90 is the address of the RTTICompleteObjectLocator for 
            //    BaseFormComponent. It has:
            //      -> 00: signature          == 1 (COL_SIG_REV1)
            //      -> 04: offset             == 0
            //      -> 08: cdOffset           == 0
            //      -> 0C: pTypeDescriptor    == 0x01E9F968
            //      -> 10: pClassDescriptor   == 0x01975FB8
            //      -> 14: pObjectBase        == 0x01975F90
            UInt32 pTypeDescriptor = i - baseAddr;
            for (UInt64 j = rdataStart; j < rdataEnd; j += 4)
            {
                UInt32* p = reinterpret_cast<UInt32*>(j);
                if (*p == pTypeDescriptor)
                {
                    // We have probably found the pClassDescriptor field of the object's
                    // RTTICompleteObjectLocator. This field is at offset 0x0C of the COL, 
                    // so decrement our pointer to address the complete COL.
                    //
                    // 3. Now find the meta fields. Scan .RDATA again for all 64-bit memory
                    //    addresses containing the address of the RTTICompleteObjectLocator.
                    //    We assume such addresses are 'meta' fields, appearing 0x8 bytes
                    //    before the start of the object's VFT.
                    //
                    //    E.g. 0x41613320 is the meta field, followed by VFT for 
                    //    BaseFormComponent. It has:
                    //      -> 00: meta                   == 0x41975F90
                    //      -> 08: first VFT entry        == 0x40101DB0
                    //      -> 10: second VFT entry, ...
                    RTTICompleteObjectLocator* col =
                        reinterpret_cast<RTTICompleteObjectLocator*>(j - 0x0C);
                    if (col->signature != COL_SIG_REV1) continue;
                    if (col->cdOffset != 0) continue;

                    UInt64 pCol = reinterpret_cast<UInt64>(col);
                    for (UInt64 k = rdataStart; k < rdataEnd; k += 8)
                    {
                        UInt64* p = reinterpret_cast<UInt64*>(k);
                        if (*p == pCol)
                        {
                            // We have probably found the object's meta field. Increment our 
                            // pointer by 8 bytes to address the object's VFT; check that the 
                            // dereferenced first VFT entry is in the .TEXT (executable) segment
                            // - i.e. probably refers to a valid executable function - and, 
                            // if so, push the address into our typeDescriptor => vtbl mapping.
                            UInt64* vtbl = reinterpret_cast<UInt64*>(p + 1);
                            if (textStart <= *vtbl && *vtbl < textEnd) {
                                UInt64 addr = baseAddr + (UInt64)col->pTypeDescriptor;
                                (col->offset == 0) ?
                                    vtblMap[addr].push_front(vtbl) :
                                    vtblMap[addr].push_back(vtbl);
                            }
                        }
                    }
                }
            }
        }
    }
}

// ============================================================================
//   B. Pretty print classes, including functions and inheritance.
//      Assumes step A above (scanning for VFTs) has already been done.
// ============================================================================
void PrintVirtuals(const UInt64 baseAddr, const std::map<UInt64, VtblList> vtblMap)
{
    UInt64 textStart = baseAddr + TEXT_SEG_BEGIN;
    UInt64 textEnd = baseAddr + TEXT_SEG_END;
    UInt64 pureCall = baseAddr + PURE_CALL_ADDR;

    for (auto& n : vtblMap)
    {
        // Output information for each RTTITypeDescriptor in vtblMap.
        // Each of these entries corresponds to one class.
        UInt64 type_addr = n.first;
        const VtblList& vtblList = n.second;

        _MESSAGE("/*==============================================================================");
        DumpObjectClassHierarchy(vtblList.front(), false, baseAddr);
        _MESSAGE("==============================================================================*/");

        // Iterate over the VFTs for the current RTTITypeDescriptor (class):
        for (auto vtbl : vtblList) {
            bool bOverride = false;
            bool bAdd = false;

            // Attempt to look up the VFT of the current VFT's parent class (if any):
            UInt64* vtparent = GetParentVtbl(vtbl, vtblMap, baseAddr);

            // Now iterate over each entry in the current VFT.
            // Stop when the entry no longer points at a valid executable function
            // (does not contain an address in the .TEXT segment).
            for (int i = 0; textStart <= vtbl[i] && vtbl[i] < textEnd; i++) {
                if (vtparent)
                {
                    if (textStart <= vtparent[i] && vtparent[i] < textEnd)
                    {
                        // If this vtable entry points to the same function as one 
                        // of the vtable entries in the parent, then it hasn't
                        // overridden anything - and we don't show it.
                        if (vtbl[i] == vtparent[i])
                            continue;
                    }
                    else
                    {
                        // We've exhausted all the entries in the parent VFT.
                        // Any further VFT entries in the child are additions.
                        vtparent = nullptr;
                    }
                }

                char buf[64];
                sprintf_s(buf, "Unk_%03X", i);
                std::string name = buf;

                sprintf_s(buf, "%08IX", (UInt64)vtbl[i]);
                std::string offset = buf;

                std::string ret = "????  ";
                std::string params = "????";
                std::string body;

                if (vtbl[i] == pureCall) {
                    body = "(pure)";
                }
                else {
                    SimpleFunctionDecompiler(vtbl[i], ret, params, body, baseAddr);
                }

                if (vtparent && !bOverride) {
                    bOverride = true;
                    std::string className;
                    GetObjectClassName(vtparent, baseAddr, className);
                    _MESSAGE("    // @override %s : (vtbl=%08X)", className.c_str(), vtbl);
                }
                if (!vtparent && !bAdd) {
                    bAdd = true;
                    if (i > 0) {
                        _MESSAGE("    // @add");
                    }
                }

                int numPad = 40;
                numPad -= params.length();
                std::string str = "    virtual ";
                str += ret + ' ' + name + '(' + params + ')';
                if (vtparent) {
                    numPad -= 9;
                    str += " override";
                }
                str += ';';

                if (numPad < 4) {
                    numPad = 4;
                }
                for (int i = numPad; i > 0; --i) {
                    str += ' ';
                }
                
                str += "// " + offset;
                if (!body.empty()) {
                    str += ' ' + body;
                }

                _MESSAGE(str.c_str());
            }
        }
        _MESSAGE("");
    }
}

// ============================================================================
//              Dump the class hierarchy for a given object.
// ----------------------------------------------------------------------------
// vtbl should be a pointer to the object's virtual function table
// (i.e. the address of the first entry in the VFT).
// ============================================================================
void DumpObjectClassHierarchy(const UInt64* vtbl, const bool verbose, const UInt64 baseAddr)
{
    std::stringstream ss;
    std::string name;
    UInt32 offset;
    RTTIClassHierarchyDescriptor* hierarchy;
    if (!GetTypeHierarchyInfo(vtbl, name, offset, hierarchy, baseAddr)) {
        _MESSAGE("<no rtti>");
        return;
    }

    //_MESSAGE("%s +%04X (_vtbl=%08X)", name, offset, *(UInt64*)objBase);
    ss << name;
    ss << " +" << std::hex << std::setfill('0') << std::uppercase << std::setw(4) << std::right << offset;
    ss << " (_vtbl=" << std::setw(8) << (UInt64)vtbl << ')';
    ss << std::endl;

    std::vector<int> depth(hierarchy->numBaseClasses, 0);

    // Iterate over the array of base class pointers
    UInt64 nClasses = hierarchy->numBaseClasses;
    UInt64 pClassArray = baseAddr + (UInt64)hierarchy->pBaseClassArray;
    for (UInt64 i = 0; i < nClasses; i++)
    {
        auto index = i * 4;
        UInt32 pBaseClass = *(UInt32*)(pClassArray + index);
        RTTIBaseClassDescriptor* baseClass =
            reinterpret_cast<RTTIBaseClassDescriptor*>(baseAddr + (UInt64)pBaseClass);

        // _MESSAGE("%04X: ", node->offset);
        ss << std::setw(4) << baseClass->where.mdisp << ": ";

        // indents
        depth[i] = baseClass->numContainedBases + 1;
        for (std::size_t n = 0; n < depth.size(); n++) {
            if (depth[n] > 0) {
                if (n > 0)
                    ss << "|   ";
                depth[n]--;
            }
        }

        TypeDescriptor* type =
            reinterpret_cast<TypeDescriptor*>(baseAddr + (UInt64)baseClass->pTypeDescriptor);
        GetUnmangledTypeName(type, baseAddr, name);
        ss << name;
        if (verbose) {
            // _MESSAGE(" ... %p", node->type->name(), node->type);
            ss << " ... " << std::setw(8) << type;
        }
        ss << std::endl;
    }

    std::string out = ss.str();
    out.pop_back();        // remove the last new line character as _MESSAGE will add one
    _MESSAGE("%s", out.c_str());
}

// ============================================================================
//                      Internal helper functions.
// ============================================================================
static void UnmangleRTTITypeName(const char* mangled, std::string& unmangled)
{
    // ------------------------------------------------------------------------
    // Attempt to convert a mangled RTTI type name into an unmangled one.
    // ------------------------------------------------------------------------
    std::string tmp;
    tmp.assign(mangled);

    // If not already done, convert the stripped mangled name to an 
    // 'RTTI Type Descriptor' mangled name.
    if (tmp.at(0) == '.') {
        // Replace the "." with "??_R0" and append "@8" to the end.
        tmp.erase(0, 1);
        tmp = "??_R0" + tmp + "@8";
    }

    // Demangle and store the result.
    char szUndName[1024];
    if (UnDecorateSymbolName(tmp.c_str(), szUndName, sizeof(szUndName), UNDNAME_COMPLETE)) {
        // Success - return the unmangled name.
        std::string toRemove = " `RTTI Type Descriptor'";
        tmp.assign(szUndName);
        size_t pos = tmp.find(toRemove);
        if (pos != std::string::npos) {
            tmp.erase(pos, toRemove.length());
        }
        unmangled.assign(tmp);
    }
    else {
        // Give up - just return the mangled name (better than nothing!).
        // Among other things, it seems that, as at Dec 2022, UnDecorateSymbolName 
        // can't handle anonymous namespaces. E.g. 
        // "??_R0?AVQueuedMagicItem@?A0x3cefe057@@@8" should demangle to
        // "class `anonymous namespace'::QueuedMagicItem `RTTI Type Descriptor'",
        // according to undname.exe, but UnDecorateSymbolName can't handle it.
        unmangled.assign(mangled);
    }
}

static void GetUnmangledTypeName(const TypeDescriptor* type, const UInt64 baseAddr, 
                                 std::string& unmangled)
{
    if (type->pVFTable == baseAddr + TYPE_INFO_VTBL) {
        // I.e. a Skyrim type
        UnmangleRTTITypeName(type->name, unmangled);
    }
    else
    {
        std::type_info const* pThis = reinterpret_cast<std::type_info const*>(type);
        unmangled.assign(pThis->name());
    }
}

static const TypeDescriptor* GetTypeDescriptor(const UInt64* vtbl, const UInt64 baseAddr)
{
    // ------------------------------------------------------------------------
    // Return a pointer to the TypeDescriptor for the given VFT ('vtbl').
    // ------------------------------------------------------------------------
    const TypeDescriptor* type = nullptr;
    __try
    {
        RTTICompleteObjectLocator* rtti = *(RTTICompleteObjectLocator**)(vtbl - 1);
        type = reinterpret_cast<TypeDescriptor*>(baseAddr + (UInt64)rtti->pTypeDescriptor);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // return the default
    }

    return type;
}

static bool GetTypeHierarchyInfo(const UInt64* vtbl, std::string& name, UInt32& offset,
                                 RTTIClassHierarchyDescriptor*& hierarchy, const UInt64 baseAddr)
{
    // ------------------------------------------------------------------------
    // Try to obtain type hierarchy info for the the given VFT ('vtbl').
    // If successful, return TRUE and store demangled RTTI type name in 'name', 
    // offset in 'offset' and the RTTIClassHierarchy pointer in 'hierarchy'.
    // Return FALSE otherwise.
    // ------------------------------------------------------------------------
    bool success = false;
    const TypeDescriptor* type = nullptr;
    __try
    {
        RTTICompleteObjectLocator* rtti = *(RTTICompleteObjectLocator**)(vtbl - 1);
        type = reinterpret_cast<TypeDescriptor*>(baseAddr + (UInt64)rtti->pTypeDescriptor);

        if (type->pVFTable == baseAddr + TYPE_INFO_VTBL) {
            // I.e. a Skyrim type
            GetUnmangledTypeName(type, baseAddr, name);
            offset = rtti->offset;
            hierarchy =
                reinterpret_cast<RTTIClassHierarchyDescriptor*>(baseAddr + (UInt64)rtti->pClassDescriptor);
            success = true;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // return the default
    }

    return success;
}

static void GetObjectClassName(const UInt64* vtbl, const UInt64 baseAddr, std::string& name)
{
    // ------------------------------------------------------------------------
    // Try to get the demangled RTTI type name for the given VFT ('vtbl').
    // Store result in 'name'.
    // ------------------------------------------------------------------------
    const TypeDescriptor* type = GetTypeDescriptor(vtbl, baseAddr);
    if (type) {
        GetUnmangledTypeName(type, baseAddr, name);
    }
    else {
        name.assign("<no rtti>");
    }
}

static UInt64* GetParentVtbl(const UInt64* vtbl, const std::map<UInt64, VtblList> vtblMap, 
                             const UInt64 baseAddr)
{
    // ------------------------------------------------------------------------
    // Try to locate the parent VFT for the given VFT ('vtbl').
    // Return a pointer to that if found, or NULL otherwise.
    // ------------------------------------------------------------------------
    // Decrement vtbl pointer by one to get the "meta" field, the pointer to the
    // object's RTTICompleteObjectLocator structure.
    RTTICompleteObjectLocator* col = *(RTTICompleteObjectLocator**)(vtbl - 1);

    // Is the derived RTTICompleteObjectLocator valid?
    // N.B. col->pClassDescriptor should not be null, even when the class has no parent.
    if (col->pClassDescriptor)
    {
        RTTIClassHierarchyDescriptor* hierarchy =
            reinterpret_cast<RTTIClassHierarchyDescriptor*>(baseAddr + (UInt64)col->pClassDescriptor);

        // Iterate over the array of 32-bit base class pointer offsets.
        // We skip the first entry because that is the BaseClassDescriptor for the current object.
        UInt64 nClasses = hierarchy->numBaseClasses;
        UInt64 pClassArray = baseAddr + (UInt64)hierarchy->pBaseClassArray;
        for (UInt64 i = 1; i < nClasses; i++)
        {
            UInt64 index = i * 4;
            UInt32 pBaseClass = *(UInt32*)(pClassArray + index);
            RTTIBaseClassDescriptor* baseClass =
                reinterpret_cast<RTTIBaseClassDescriptor*>(baseAddr + (UInt64)pBaseClass);

            if (baseClass->where.mdisp == col->offset)
            {
                // Attempt to locate this base class's TypeDescriptor in our
                // Type=>VFT mapping. If found, then return the first VFT in the
                // associated VFT list as the start of the VFT of the parent.
                auto it = vtblMap.find(baseAddr + (UInt64)baseClass->pTypeDescriptor);
                if (it != vtblMap.cend())
                    return it->second.front();
            }
        }
    }

    // Parent vtbl not found.
    return nullptr;
}

static void SimpleFunctionDecompiler(const UInt64 funcAddr, std::string& retOut, std::string& paramsOut,
                                     std::string& bodyOut, const UInt64 baseAddr)
{
    // ------------------------------------------------------------------------
    // Attempt to decompile a simple two-instruction function of form:
    //         <some instruction>
    //         "retn" | "retn imm16"
    // ------------------------------------------------------------------------
    // See https://www.felixcloutier.com/x86/ret
    //     https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x64-architecture
    UInt8* code = (UInt8*)funcAddr;
    std::size_t size = 0;
    std::string ret = "????  ";
    std::string body;

    // -----------------------------------------
    // XOR ...
    // -----------------------------------------
    if (code[0] == 0x32 && code[1] == 0xC0)
    {
        // xor al, al
        ret = "bool  ";
        body = "{ return false; }";
        size = 2;
    }
    else if (code[0] == 0x33 && code[1] == 0xC0)
    {
        // xor eax, eax
        ret = "UInt32";
        body = "{ return 0; }";
        size = 2;
    }
    else if (code[0] == 0x83 && code[1] == 0xC8 && code[2] == 0xFF)
    {
        // xor al, ???
        ret = "Sint32";
        body = "{ return -1; }";
        size = 3;
    }
    // -----------------------------------------
    // XORPS ...
    // -----------------------------------------
    else if (code[0] == 0x0F && code[1] == 0x57 && code[2] == 0xC0)
    {
        // xorps xmm0, xmm0
        ret = "float";
        body = "{ return 0.0f; }";
        size = 3;
    }
    // -----------------------------------------
    // MOV ...
    // See https://www.felixcloutier.com/x86/mov
    // -----------------------------------------
    else if (code[0] == 0xB0)
    {
        // mov al, imm
        if (code[1] == 0x00)
        {
            ret = "bool  ";
            body = "{ return false; }";
        }
        else if (code[1] == 0x01)
        {
            ret = "bool  ";
            body = "{ return true; }";
        }
        else {
            char buf[32];
            sprintf_s(buf, "{ return 0x%02X; }", code[1]);
            ret = "UInt8 ";
            body = buf;
        }
        size = 2;
    }
    else if (code[0] == 0x8A)
    {
        // mov al, ???
        if (code[1] == 0x41)
        {
            // mov al, [ecx+imm8]
            char buf[48];
            sprintf_s(buf, "{ return (UInt8)unk%X; }", (SInt8)code[2]);
            ret = "UInt8 ";
            body = buf;
            size = 3;
        }
        else if (code[1] == 0x81)
        {
            // mov al, [ecx+imm32]
            char buf[48];
            sprintf_s(buf, "{ return (UInt8)unk%X; }", *(SInt32*)&code[2]);
            ret = "UInt8 ";
            body = buf;
            size = 6;
        }
    }
    else if (code[0] == 0x48 && code[1] == 0x8B)
    {
        // mov rax, ???
        if (code[2] == 0xC1)
        {
            // mov rax, rcx
            ret = "void *";
            body = "{ return this; }";
            size = 3;
        }
        else if (code[2] == 0x41)
        {
            // mov rax, [rcx+imm8]
            char buf[48];
            sprintf_s(buf, "{ return (UInt64)unk%X; }", (SInt8)code[3]);
            ret = "UInt64";
            body = buf;
            size = 4;
        }
        else if (code[2] == 0x81)
        {
            // mov rax, [rcx+imm32]
            char buf[48];
            sprintf_s(buf, "{ return (UInt64)unk%X; }", *(SInt32*)&code[3]);
            ret = "UInt64";
            body = buf;
            size = 7;
        }
    }
    else if (code[0] == 0xB8)
    {
        // mov eax, imm32
        UInt32* p = *(UInt32**)&code[1];
        char buf[32];

        const TypeDescriptor* type = GetTypeDescriptor((UInt64*)p, baseAddr);
        if (type)
        {
            GetUnmangledTypeName(type, baseAddr, ret);
            ret += " *";
            body.reserve(ret.length() + 32);
            body = "{ return (";
            body += ret;
            body += ')';
            sprintf_s(buf, "0x%08X; }", (UInt32)p);
            body += buf;
        }
        else
        {
            sprintf_s(buf, "{ return 0x%08X; }", (UInt32)p);
            ret = "UInt32";
            body = buf;
        }
        size = 5;
    }
    // -----------------------------------------
    // LEA r64,m
    // REX.W + 8D /r
    // See https://www.felixcloutier.com/x86/lea
    // N.B. reg == 000 for RAX
    // -----------------------------------------
    else if (code[0] == 0x48 && code[1] == 0x8D)
    {
        // lea rax, ???
        if (code[2] == 0x41)
        {
            // lea rax, [rcx+imm8]
            char buf[32];
            sprintf_s(buf, "{ return &unk%X; }", (SInt8)code[3]);
            ret = "void *";
            body = buf;
            size = 4;
        }
        else if (code[2] == 0x81)
        {
            // lea rax, [rcx+imm32]
            char buf[32];
            sprintf_s(buf, "{ return &unk%X; }", *(SInt32*)&code[3]);
            ret = "void *";
            body = buf;
            size = 7;
        }
        else if (code[3] == 0x05)
        {
            // lea rax, [rbx+imm32]
            UInt32* p = *(UInt32**)&code[4];
            char buf[32];

            const TypeDescriptor* type = GetTypeDescriptor((UInt64*)p, baseAddr);
            if (type)
            {
                GetUnmangledTypeName(type, baseAddr, ret);
                ret += " *";
                body.reserve(ret.length() + 32);
                body = "{ return (";
                body += ret;
                body += ')';
                sprintf_s(buf, "0x%08X; }", (UInt32)p);
                body += buf;
            }
            else
            {
                sprintf_s(buf, "{ return 0x%08X; }", (UInt32)p);
                ret = "UInt32";
                body = buf;
            }
            size = 7;
        }
    }

    // Increment the code pointer by 'size' bytes, so
    // we're ready to parse the next bytes.
    code += size;

    // Parse the second instruction.
    std::string params;
    if (code[0] == 0xC3)
    {
        // retn
        params = "void";
    }
    else if (code[0] == 0xC2)
    {
        // retn imm16
        UInt16 imm = *(UInt16*)&code[1];
        switch (imm)
        {
        case 0:
            params = "void";
            break;
        case 4:
            params = "UInt32 arg";
            break;
        case 8:
            params = "UInt32 arg1, UInt32 arg2";
            break;
        case 12:
            params = "UInt32 arg1, UInt32 arg2, UInt32 arg3";
            break;
        case 16:
            params = "UInt32 arg1, UInt32 arg2, UInt32 arg3, UInt32 arg4";
            break;
        default:
        {
            char buf[32];
            sprintf_s(buf, "UInt32 * %d", imm / 4);
            params = buf;
        }
        break;
        }

    }
    else
    {
        // second instruction isn't a retn, so give up and
        // don't infer anything about the function.
        return;
    }

    if (size == 0)
    {
        ret = "void  ";
        body = "{ return; }";
    }

    retOut = ret;
    paramsOut = params;
    bodyOut = body;
}
