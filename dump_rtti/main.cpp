// ============================================================================
// dump_rtti/main.cpp
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
#include <shlobj.h>

#include "common/IDebugLog.h"
#include "skse64_common/skse_version.h"
#include "skse64/PluginAPI.h"

#include "RTTI.h"

IDebugLog		         gLog;
PluginHandle	         g_pluginHandle = kPluginHandle_Invalid;
SKSEMessagingInterface*  g_msgInterface = NULL;

extern "C" {
    void HandleSKSEMessage(SKSEMessagingInterface::Message* msg) {
        if (msg->type != SKSEMessagingInterface::kMessage_DataLoaded) return;

        char modFileName[MAX_PATH];
        HMODULE hModule = GetModuleHandle(NULL);
        DWORD ret = GetModuleFileNameA(hModule, modFileName, MAX_PATH);
        UInt64 baseAddr = reinterpret_cast<UInt64>(hModule);

        // ----------------------------------------------------------------------
        //        Print useful summary info about the loaded executable.
        // ----------------------------------------------------------------------
        _MESSAGE("------------------------------ MODULE SUMMARY ----------------------------------");
        if (ret) {
            _MESSAGE("File name: %s", modFileName);
        }
        _MESSAGE("Base address: %#010x", baseAddr);
        _MESSAGE("Sections:");

        // Thanks Nawaz @
        // https://stackoverflow.com/questions/4308996/finding-the-address-range-of-the-data-segment
        IMAGE_NT_HEADERS* pNtHdr = ImageNtHeader(hModule);
        IMAGE_SECTION_HEADER* pSectionHdr = (IMAGE_SECTION_HEADER*)(pNtHdr + 1);
        std::string scnName;

        for (int scn = 0; scn < pNtHdr->FileHeader.NumberOfSections; ++scn)
        {
            // N.B. pSectionHdr->Name is 8 bytes long. If all 8 bytes are used it won't be 
            // null-terminated. So we do this to avoids potential buffer overruns:
            scnName.assign((const char*)pSectionHdr->Name, 8);
            _MESSAGE("  %3d: %#010x ... %#010x %-10s (%u bytes)",
                     scn,
                     baseAddr + (UInt64)pSectionHdr->VirtualAddress,
                     baseAddr + (UInt64)pSectionHdr->VirtualAddress + (UInt64)pSectionHdr->Misc.VirtualSize,
                     scnName.c_str(),
                     (UInt32)pSectionHdr->Misc.VirtualSize);
            ++pSectionHdr;
        }
        _MESSAGE("--------------------------------------------------------------------------------");

        // 1. Locate the RTTI Type Descriptor for class type_info.
        //    In Skyrim 1.6.659, it should find the string at address 0x41f50eb0,
        //    which means the type_info TypeDescriptor is 2 8-byte pointers earlier,
        //    at 0x41f50ea0.
        // const char* s_typeInfo = ".?AVtype_info@@";
        // const size_t len_typeInfo = strlen(s_typeInfo);

        // 2. Once the type_info TypeDescriptor is found, we can dereference its
        //    pVFTable member to locate the type_info VFT. In Skyrim 1.6.659, that's at
        //    address 0x419752c0.

        // For now we've simply hard-coded the address of the type_info VFT as the
        // constant TYPE_INFO_VTBL. But in future, we could make this code more
        // general by dynamically looking up that address as per the steps 1 & 2 above.

        // ... Locate the VFTs, then print the class structures:
        std::map<UInt64, VtblList> vtblMap;	// TypeDescriptor address, list of vtbl addresses
        LoadVTables(baseAddr, vtblMap);
        PrintVirtuals(baseAddr, vtblMap);
    }

    __declspec(dllexport) SKSEPluginVersionData SKSEPlugin_Version = {
        SKSEPluginVersionData::kVersion,

        1,
        "skyretk_dump_rtti",

        "nox sidereum (2022); himika (2017)",
        "",

        0,  // not version independent (extended field)
        0,  // not version independent
        { RUNTIME_VERSION_1_6_659_GOG, 0 },

        0  // works with any version of the script extender.
    };

    __declspec(dllexport) bool SKSEPlugin_Load(const SKSEInterface* skse) {
        // Initialise the log.
        // We're going to be generating a lot of text, so adjust the log & print
        // levels to ensure that all messages go to the log but only warnings or errors
        // go to the terminal.
        gLog.OpenRelative(CSIDL_MYDOCUMENTS,
            "\\My Games\\Skyrim Special Edition GOG\\SKSE\\skyretk_dump_rtti.log");
        gLog.SetPrintLevel(IDebugLog::kLevel_Warning);
        gLog.SetLogLevel(IDebugLog::kLevel_DebugMessage);

        if (skse->isEditor) {
            _MESSAGE("loaded in editor, marking as incompatible");
            return false;
        }

        _MESSAGE("====================== SkyRETK dump_rtti: SKSEPlugin_Load ======================");
        _MESSAGE("Nox Sidereum's update of Himika's code at https://github.com/himika/libSkyrim.");
        _MESSAGE("Currently only works for GOG Skyrim 1.6.659 because the offsets are hardcoded.");
        _MESSAGE("================================================================================");

        // Register for the "DataLoaded" SKSE callback.
        g_pluginHandle = skse->GetPluginHandle();
        g_msgInterface =
            (SKSEMessagingInterface*)skse->QueryInterface(kInterface_Messaging);
        if (!g_msgInterface) {
            _ERROR("couldn't get messaging interface");
            return false;
        }
        int skseMsgInterfaceVersion = g_msgInterface->interfaceVersion;
        if (skseMsgInterfaceVersion < 1) {
            _ERROR("messaging interface too old (%d expected %d)",
                skseMsgInterfaceVersion, 1);
            return false;
        }
        g_msgInterface->RegisterListener(g_pluginHandle, "SKSE", HandleSKSEMessage);

        return true;
    }
}
