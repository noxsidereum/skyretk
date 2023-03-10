// ============================================================================
// dump_rtti/RTTI.h
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
#pragma once

#include <list>
#include <map>

#include "common/ITypes.h"

// ============================================================================
//                Section Offsets (from base module address)
// ----------------------------------------------------------------------------
// These are all correct for Skyrim 1.6.659 (GOG version).
// Refer MODULE SUMMARY header in skyretk_dump_rtti.log.
// ============================================================================
// 0: .text (+rx)
const UInt64 TEXT_SEG_BEGIN       = 0x00001000;  // start
const UInt64 PURE_CALL_ADDR       = 0x01471648;
const UInt64 TEXT_SEG_END         = 0x015fcb8c;  // end

// 1: .rdata (+r)
const UInt64 RDATA_SEG_BEGIN      = 0x015fd000;  // start
const UInt64 TYPE_INFO_VTBL       = 0x019752c0;
const UInt64 RDATA_SEG_END        = 0x01e3c276;  // end 

// 2: .data (+rw)
const UInt64 DATA_SEG_BEGIN       = 0x01e3d000;  // start
const UInt64 DATA_SEG_END         = 0x0352baf0;  // end

// ============================================================================
//                          RTTI structures.
// ----------------------------------------------------------------------------
// For more info see the excellent article by Igor Skochinsky
// at http://www.openrce.org/articles/full_view/23.
// In the below, all OFFSETs are relative to the module's base address.
// ============================================================================
struct TypeDescriptor
{
    UInt64        pVFTable;            // 00: points to type_info's vftable.
    UInt64        spare;               // 08: unused field (currently always set to nullptr).
    char          name[];              // 10: null-terminated string with the mangled type name.
};

// "The PMD structure describes how a base class is placed inside 
//  the complete class. In the case of simple inheritance it is
//  situated at a fixed offset from the start of object, and that
//  value is the _mdisp_ field. If it's a virtual base, an additional
//  offset needs to be fetched from the vbtable."
//        - http://www.openrce.org/articles/full_view/23
struct PMD
{
    UInt32        mdisp;               // 00: member displacement
    UInt32        pdisp;               // 04: vbtable displacement
    UInt32        vdisp;               // 08: displacement inside vbtable
};

// Each entry in the Base Class Array has the following structure.
// "The Base Class Array describes all base classes together with information which
//  allows the compiler to cast the derived class to any of them during
//  execution of the _dynamic_cast_ operator."
//        - http://www.openrce.org/articles/full_view/23
struct RTTIBaseClassDescriptor
{
    UInt32        pTypeDescriptor;     // 00: contains the OFFSET to the object's TypeDescriptor.
    UInt32        numContainedBases;   // 04: number of contained bases
    struct PMD    where;               // 08: pointer-to-member displacement info
    UInt32        attributes;          // 14: flags, usually 0
};

// "Class Hierarchy Descriptor describes the inheritance hierarchy
//  of the class. It is shared by all COLs for a class."
//        - http://www.openrce.org/articles/full_view/23
struct RTTIClassHierarchyDescriptor
{
    UInt32        signature;           // 00: always 0?
    UInt32        attributes;          // 04: always 0?
    UInt32        numBaseClasses;      // 08: number of elements in the RTTIBaseClassArray
    UInt32        pBaseClassArray;     // 0C: contains the OFFSET to the first pointer in the RTTIBaseClassArray.
};

// "MSVC compiler puts a pointer to the structure called "Complete Object Locator" [COL]
//  just before the vftable. The structure is called so because it allows compiler
//  to find the location of the complete object from a specific vftable pointer
//  (since a class can have several of them)."
//        - http://www.openrce.org/articles/full_view/23
constexpr auto COL_SIG_REV1 = 1;

struct RTTICompleteObjectLocator
{
    UInt32        signature;           // 00: for x64, this is COL_SIG_REV1
    UInt32        offset;              // 04: offset from complete object to this sub-object.
    UInt32        cdOffset;            // 08: the constructor displacement's offset.
    UInt32        pTypeDescriptor;     // 0C: contains the OFFSET to this object's TypeDescriptor.
    UInt32        pClassDescriptor;    // 10: contains the OFFSET to this object's RTTIClassHierarchyDescriptor.
    UInt32        pSelf;               // 14: contains the OFFSET to this RTTICompleteObjectLocator.
};

typedef std::list<UInt64*> VtblList;

// ============================================================================
//                             Functions.
// ============================================================================
// public:
void LoadVTables(const UInt64 baseAddr, std::map<UInt64, VtblList>& vtblMap);

void PrintVirtuals(const UInt64 baseAddr, const std::map<UInt64, VtblList> vtblMap);

void DumpObjectClassHierarchy(const UInt64* vtbl, const bool verbose, const UInt64 baseAddr);

// private:
static void UnmangleRTTITypeName(const char* mangled, std::string& unmangled);

static void GetUnmangledTypeName(const TypeDescriptor* type, const UInt64 baseAddr, std::string& unmangled);

static const TypeDescriptor* GetTypeDescriptor(const UInt64* vtbl, const UInt64 baseAddr);

static UInt64* GetParentVtbl(const UInt64* vtbl, const std::map<UInt64, VtblList> vtblMap, const UInt64 baseAddr);

static bool GetTypeHierarchyInfo(const UInt64* vtbl, std::string& name, UInt32& offset,
                                 RTTIClassHierarchyDescriptor*& hierarchy, const UInt64 baseAddr);

static void GetObjectClassName(const UInt64* vtbl, const UInt64 baseAddr, std::string& name);

static void SimpleFunctionDecompiler(const UInt64 funcAddr, std::string& retOut, std::string& paramsOut,
                                     std::string& bodyOut, const UInt64 baseAddr);
