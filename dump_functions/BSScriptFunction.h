// ============================================================================
// dump_functions/BSScriptFunction.h
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

// Adapted from Skyrim/src/BSScriptFunction.cpp at https://github.com/himika/libSkyrim,
// a useful collection of functions for 32-bit Skyrim, last modified in 2017.
// 
// Other useful references:
//   https://github.com/Ryan-rsm-McKenzie/CommonLibSSE/blob/master/include/RE/I/IFunction.h
#pragma once

#include <string>

#include "skse64/PapyrusNativeFunctions.h"
#include "BSScriptVariable.h"

std::string FunctionToString(IFunction* fn)
{
    UInt64 type = kType_None;

    std::string declName;
    declName.reserve(128);

    fn->GetReturnType(&type);
    if (type != kType_None)
    {
        BSFixedString typeName;
        BSScriptTypeToString(type, typeName);
        declName = typeName.c_str();
        declName += ' ';
    }

    // fn->Unk_OA() in SKSE 2.2.3 == fn->IsEvent()
    declName += (fn->Unk_0A()) ? "Event " : "Function ";
    declName += fn->GetName()->c_str();

    const UInt32 numParams = fn->GetNumParams();
    declName += "(";

    for (UInt32 i = 0; i < numParams; i++)
    {
        if (i != 0)
            declName += ", ";

        BSFixedString paramName;
        BSFixedString typeName;
        fn->GetParam(i, &paramName, &type);
        BSScriptTypeToString(type, typeName);

        declName += typeName.c_str();
        declName += ' ';
        declName += paramName.c_str();
    }
    declName += ')';

    // fn->GetUnk40() in SKSE 2.2.3 == fn->IsStatic()
    if (fn->GetUnk40())
        declName += " global";
    if (fn->IsNative())
        declName += " native";

    return declName;
}