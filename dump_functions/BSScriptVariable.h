// ============================================================================
// dump_functions/BSScriptVariable.h
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

// Adapted from Skyrim/src/BSScriptVariable.cpp and BSScriptVariable.h at 
// https://github.com/himika/libSkyrim, a useful collection of functions for 
// 32-bit Skyrim, last modified in 2017.
// 
// Other useful references:
//   https://github.com/Ryan-rsm-McKenzie/CommonLibSSE/blob/master/include/RE/T/TypeInfo.h
enum BSScriptType
{
	kType_None = 0,
	kType_Object = 1,
	kType_String = 2,
	kType_Int = 3,
	kType_Float = 4,
	kType_Bool = 5,

	kType_NoneArray = 10,
	kType_ObjectArray = 11,
	kType_StringArray = 12,
	kType_IntArray = 13,
	kType_FloatArray = 14,
	kType_BoolArray = 15,

	kType_ArraysEnd

	// From Ryan's CommonLibSSE:
	//  "the type id for classes IS their class ptr.
	//   an object is an array if its first bit is set."
};

UInt64 GetUnmangledType(UInt64 type) {
	if (type < kType_ArraysEnd)
		return type;
	return (type & kType_Object) ? kType_ObjectArray : kType_Object;
}

VMClassInfo* GetScriptClass(UInt64 type) {
	return (type >= kType_ArraysEnd && (type & 1) == 0) ?
		(VMClassInfo*)type : nullptr;
}

void BSScriptTypeToString(UInt64 type, BSFixedString& out)
{
	char buf[0x100];

	// array type -> single type
	bool bIsArray = false;
	UInt64 singleType = GetUnmangledType(type);
	if (singleType > 10)
	{
		bIsArray = true;
		singleType -= 10;
	}

	const char* typeName;

	switch (singleType)
	{
	case kType_None:
		typeName = "None";
		break;
	case kType_Object:
	{
		// himika's code calls this BSScriptClass; 
		// skse calls it VMClassInfo.
		const VMClassInfo* klass = GetScriptClass(type);
		typeName = "None";
		if (klass)
		{
			const BSFixedString& name = klass->name;
			if (name)
				typeName = name.c_str();
		}
	}
	break;
	case kType_String:
		typeName = "String";
		break;
	case kType_Int:
		typeName = "Int";
		break;
	case kType_Float:
		typeName = "Float";
		break;
	case kType_Bool:
		typeName = "Bool";
		break;
	default:
		typeName = "Unknown";
		break;
	}

	strcpy_s(buf, typeName);

	if (bIsArray)
		strcat_s(buf, "[]");

	out = buf;
}