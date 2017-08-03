#pragma once

#include <dia2.h>
#include <stdio.h>
#include <fstream>
#include "ntdll.h"
#include <iostream>
#include <vector>
#include <map>

using namespace std;


class getAddress
{
public:
	map<DWORD,LPCWSTR> addressToName;
public:
	getAddress(void);
	~getAddress(void);
	PVOID GetAllProcAddrFromKernelPdb();
	bool FindPublicAll(IDiaSymbol *pGlobal);
	PVOID GetProcAddrFromKernelPdb(LPCWSTR zPdbName,LPCWSTR szApiName);

};

