#pragma once

#include <dia2.h>
#include <stdio.h>
#include <fstream>
#include "ntdll.h"
#include <iostream>
#include <vector>
#include <unordered_map>

using namespace std;

class getAddress
{
public:
	unordered_map<DWORD, wchar_t*> addressToName;
public:
	getAddress(void);
	~getAddress(void);
	PVOID GetAllProcAddrFromKernelPdb();
	bool FindPublicAll(IDiaSymbol *pGlobal);
	PVOID GetProcAddrFromKernelPdb(wchar_t* zPdbName, wchar_t* szApiName);

};

