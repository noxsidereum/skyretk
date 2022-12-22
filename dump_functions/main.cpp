// ============================================================================
// dump_functions/main.cpp
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
#include <shlobj.h>

#include "common/IDebugLog.h"
#include "common/ITypes.h"
#include "skse64_common/SafeWrite.h"
#include "skse64_common/skse_version.h"
#include "skse64/PluginAPI.h"

#include "BSScriptFunction.h"
#include "BSScriptVariable.h"
//#include "../dump_rtti/RTTI.h"

IDebugLog		gLog;

// We override the BindNativeMethod pointer in the VFT of class VirtualMachine.
// In Skyrim GOG (1.6.659), this is at offset 0x0194B598 and initially points
// to offset 0x0137B470.
const UInt64 BIND_NATIVE_METHOD_VFT_OFFSET = 0x0194B598;
typedef void (*BindNativeMethodFunction)(UInt64 thisObj, IFunction* fn);
UInt64 bindNativeMethod_Orig;
UInt64 baseAddr;

void bindNativeMethod_Hook(uintptr_t thisObj, IFunction* fn)
{
    // For GOG Skyrim 1.6.659, sizeof(NativeFunctionBase) == 0x50, not 0x2C.
    UInt64 callback = *(UInt64*)((UInt64)fn + 0x50);   // previously 0x2C
    _MESSAGE("<%s> %s (%#010x) callback=%#010x", fn->GetClassName()->c_str(), 
             FunctionToString(fn).c_str(), fn, callback);
    // TODO: Figure out how to get the function's VFT address
    // (this line doesn't work anymore):
    // DumpObjectClassHierarchy((UInt64*)(fn, false, baseAddr);
    ((BindNativeMethodFunction)bindNativeMethod_Orig)(thisObj, fn);
}

void InstallHook()
{
    _MESSAGE("Installing hook...");

    // Overwrite the VirtualMachine VFT pointer to the original BindNativeMethod 
    // function, which is 8 bytes, with the address to our hook. Also save the 
    // address of the original BindNativeMethod function so our hook can return
    // to control to it after it's done.
    baseAddr = reinterpret_cast<UInt64>(GetModuleHandle(NULL));
    UInt64 bindNativeMethod_VFT = baseAddr + BIND_NATIVE_METHOD_VFT_OFFSET;
    bindNativeMethod_Orig = (*(UInt64*)bindNativeMethod_VFT);

    _MESSAGE("  1. Module base address: %#010x.", baseAddr);
    _MESSAGE("  2. Redirecting VM->BindNativeMethod VFT pointer at %#010x.", 
             bindNativeMethod_VFT);
    _MESSAGE("  3. Before hooking, it points to %#010x.",
             (*(UInt64*)bindNativeMethod_VFT));
    SafeWrite64(bindNativeMethod_VFT, (UInt64)&bindNativeMethod_Hook);
    _MESSAGE("  4. After hooking, it points to %#010x.",
             (*(UInt64*)bindNativeMethod_VFT));
    _MESSAGE("done.");
}

extern "C" {
    __declspec(dllexport) SKSEPluginVersionData SKSEPlugin_Version = {
        SKSEPluginVersionData::kVersion,

        1,
        "skyretk_dump_functions",

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
                          "\\My Games\\Skyrim Special Edition GOG\\SKSE\\skyretk_dump_functions.log");
        gLog.SetPrintLevel(IDebugLog::kLevel_Warning);
        gLog.SetLogLevel(IDebugLog::kLevel_DebugMessage);

        if (skse->isEditor) {
            _MESSAGE("loaded in editor, marking as incompatible");
            return false;
        }

        _MESSAGE("=================== SkyRETK dump_functions: SKSEPlugin_Load ====================");
        _MESSAGE("Nox Sidereum's update of Himika's code at https://github.com/himika/libSkyrim.");
        _MESSAGE("Currently only works for GOG Skyrim 1.6.659 because the offsets are hardcoded.");
        InstallHook();
        _MESSAGE("Output line format is:   <1> 2 (3) callback=4");
        _MESSAGE("where:");
        _MESSAGE("  1 = class");
        _MESSAGE("  2 = [<type>] 'Function' <identifier> '(' [<parameters>] ')' ('global' | 'native')*");
        _MESSAGE("  3 = address of NativeFunction object on the heap");
        _MESSAGE("  4 = address of the function in the Skyrim executable image that will be");
        _MESSAGE("      invoked whenever the NativeFunction object is run.");
        _MESSAGE("More detail at https://www.creationkit.com/index.php?title=Function_Reference.");
        _MESSAGE("See https://www.creationkit.com/index.php?title=List_of_Papyrus_Functions for");
        _MESSAGE("descriptions of what the different functions do.");
        _MESSAGE("================================================================================");

        return true;
    }
}
