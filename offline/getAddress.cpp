#include "getAddress.h"

#include "syscallList.h"

using namespace std;




getAddress::~getAddress(void)
{
}








wofstream outfile;
IDiaDataSource *pSource;
IDiaSession *psession;
IDiaSymbol *pSymbol;

DWORD g_dwMachineType;
DWORD dwMachType;

DWORD krnlBase;
DWORD win32kBase;

DWORD curBase;


void split(vector<wstring> &Result, wstring &Input, const wchar_t* Regex)
{
	int pos = 0;
	int npos = 0;
	int regexlen = wcslen(Regex);
	while ((npos = Input.find(Regex, pos)) != -1)
	{
		wstring tmp = Input.substr(pos, npos - pos);
		Result.push_back(tmp);
		pos = npos + regexlen;
	}
	Result.push_back(Input.substr(pos, Input.length() - pos));
}

bool endWith(const char * str, const char * end)
{
	bool result = false;

	if (str != NULL && end != NULL) {
		int l1 = strlen(str);
		int l2 = strlen(end);
		if (l1 >= l2) {
			if (strcmp(str + l1 - l2, end) == 0) {
				result = true;
			}
		}
	}

	return result;
}
void GetkrnlBase()
{
	PSYSTEM_MODULE_INFORMATION SystemInfo;
	DWORD dwBufferSize;
	NtQuerySystemInformation((SYSTEMINFOCLASS)11, 0, 0, &dwBufferSize);
	SystemInfo = (PSYSTEM_MODULE_INFORMATION)malloc(dwBufferSize);
	NtQuerySystemInformation((SYSTEMINFOCLASS)11, SystemInfo, dwBufferSize, 0);

	krnlBase = (DWORD)SystemInfo->aSM[0].Base;


	for (DWORD i = 1; i <= (SystemInfo->uCount); i++)
	{
		if (endWith(SystemInfo->aSM[i].ImageName, "win32k.sys"))
		{
			win32kBase = SystemInfo->aSM[i].Base;
			cout << SystemInfo->aSM[i].ImageName << endl;;
		}
	}
	//	outfile<<L"krnlBase : "<<hex<<krnlBase<<endl
	//		<<L"win32k Base : "<<hex<<win32kBase<<endl;
}
bool LoadDataFromPdb(LPCWSTR szFilename)
{
	HRESULT hr = CoInitialize(NULL);
	hr = CoCreateInstance(__uuidof(DiaSource),
		NULL,
		CLSCTX_INPROC_SERVER,
		__uuidof(IDiaDataSource),
		(void **)&pSource);

	if (FAILED(hr))
	{
		wprintf(L"Could not CoCreate CLSID_DiaSource. Register msdia80.dll.");
	}



	if (FAILED(pSource->loadDataFromPdb(szFilename)))
	{
		if (FAILED(pSource->loadDataForExe(szFilename, NULL, NULL)))
		{
			wprintf(L"loadDataFromPdb/Exe");
		}
	}
	if (FAILED(pSource->openSession(&psession)))
	{
		wprintf(L"openSession");
	}
	if (FAILED(hr)) {
		return false;
	}

	// Retrieve a reference to the global scope

	hr = psession->get_globalScope(&pSymbol);

	if (hr != S_OK) {
		return false;
	}

	// Set Machine type for getting correct register names

	if (pSymbol->get_machineType(&dwMachType) == S_OK) {
		switch (dwMachType) {
		case IMAGE_FILE_MACHINE_I386: g_dwMachineType = CV_CFL_80386; break;
		case IMAGE_FILE_MACHINE_IA64: g_dwMachineType = CV_CFL_IA64; break;
		case IMAGE_FILE_MACHINE_AMD64: g_dwMachineType = CV_CFL_AMD64; break;
		}
	}


	//	wprintf(L"load succeed.");
	return true;
}

bool FindPublic(IDiaSymbol *pGlobal, LPCWSTR szApiName, DWORD *dwRva)
{
	// Retrieve all the public symbols

	DWORD dwSymTag;
	DWORD dwRVA;
	DWORD dwSeg;
	DWORD dwOff;
	BSTR bstrName;
	BSTR bstrUndname;

	IDiaSymbol *pSymbol;
	IDiaEnumSymbols *pEnumSymbols;
	ULONG celt = 0;

	*dwRva = 0;


	if (FAILED(pGlobal->findChildren(SymTagPublicSymbol, NULL, nsNone, &pEnumSymbols))) {
		return false;
	}

	while (SUCCEEDED(pEnumSymbols->Next(1, &pSymbol, &celt)) && (celt == 1)) {
		//		pSymbol->get_name(&bstrName);
		//		outfile<<L"name1 : "<<bstrName<<endl;
		//		pSymbol->get_undecoratedName(&bstrName);
		//		outfile<<L"undecoratedName : "<<bstrName<<endl;
		//		wprintf(L"undecoratedName = %Ls\n",bstrName);
		if (pSymbol->get_symTag(&dwSymTag) == S_OK&&
			dwSymTag != SymTagThunk &&
			pSymbol->get_name(&bstrName) == S_OK &&
			pSymbol->get_undecoratedName(&bstrUndname) == S_OK &&
			(
			//			TRUE
			//			!_wcsnicmp(szName,bstrName,wcslen(szName))||!_wcsnicmp(szName,bstrUndname,wcslen(szName))||
			//			!_wcsnicmp(szName1,bstrName,wcslen(szName1))||!_wcsnicmp(szName1,bstrName,wcslen(szName1)))
			!_wcsnicmp(szApiName, bstrName, wcslen(bstrName)) || !_wcsnicmp(szApiName, bstrName, wcslen(bstrName))
			)
			){
			pSymbol->get_relativeVirtualAddress(&dwRVA);
//			pSymbol->get_addressSection(&dwSeg);
//			pSymbol->get_addressOffset(&dwOff);
			//				outfile<<L" "<<(dwRVA+krnlBase)<<L" "<<(dwRVA+win32kBase)<<endl;
			//				outfile<<szApiName<<L" : Seg "<<hex<<dwSeg <<L"  off "<<hex<<dwOff<<endl;
			*dwRva = dwRVA;
		}
		SysFreeString(bstrName);
		SysFreeString(bstrUndname);
		pSymbol->Release();
		if (*dwRva){
			pEnumSymbols->Release();

			return true;
		}
	}

	pEnumSymbols->Release();

	return false;
}

void cleanup()
{
	if (pSymbol) {
		pSymbol->Release();
		pSymbol = NULL;
	}



	if (pSource) {
		pSource->Release();
		pSource = NULL;
	}


	if (psession) {
		psession->Release();
		psession = NULL;
	}

	CoUninitialize();
}

PVOID getAddress::GetProcAddrFromKernelPdb(LPCWSTR zPdbName, LPCWSTR szApiName)
{

	DWORD ret = 0;

	if (LoadDataFromPdb(L"ntkrnlmp.pdb"))
	{
		FindPublic(pSymbol, szApiName, &ret);
		cleanup();
		if (ret != 0)
		{
			//			outfile<<szApiName<<" "<<hex<<ret<<endl;

			ret += krnlBase;

			if (addressToName.find(ret) == addressToName.end())
				addressToName[ret] = szApiName;
			else
			{
				wcout << "find conflict addresses!" << endl
					<< szApiName << L" : " << ret << endl
					<< addressToName[ret] << endl;
				outfile << szApiName << "@" << addressToName[ret]<< endl;
			}

			//			outfile<<szApiName<<" "<<hex<<ret<<endl;

		}


		if (ret == 0 && LoadDataFromPdb(L"win32k.pdb"))
		{
			FindPublic(pSymbol, szApiName, &ret);
			if (ret != 0)
			{
				//				outfile<<szApiName<<" "<<hex<<ret<<endl;
				ret += win32kBase;

				//				outfile<<szApiName<<" "<<hex<<ret<<endl;


				if (addressToName.find(ret) == addressToName.end())
					addressToName[ret] = szApiName;
				else
				{
					wcout << "find conflict addresses!" << endl
						<< szApiName << L" : " << ret << endl
						<< addressToName[ret] << endl;
					outfile << szApiName << "@" << addressToName[ret];
				}

			}
			else
			{
				wcout << szApiName << L" cannot be found!" << endl;
//				outfile << szApiName << endl;
			}
			cleanup();
		}

		//		outfile << szApiName << L" : " << ret << endl;
	}


	//	wprintf(L"The address is %Ld\n",ret);

	//if (ret == 0)
	//{
	//	cout << szApiName << endl;
	//}

	return (PVOID)ret;
}

bool getAddress::FindPublicAll(IDiaSymbol *pGlobal)
{
	// Retrieve all the public symbols

	DWORD dwSymTag;
	DWORD dwRVA;
	DWORD dwSeg;
	DWORD dwOff;
	BSTR bstrName;
	BSTR bstrUndname;

	IDiaSymbol *pSymbol;
	IDiaEnumSymbols *pEnumSymbols;
	ULONG celt = 0;



	if (FAILED(pGlobal->findChildren(SymTagPublicSymbol, NULL, nsNone, &pEnumSymbols))) {
		return false;
	}

	while (SUCCEEDED(pEnumSymbols->Next(1, &pSymbol, &celt)) && (celt == 1)) {
		//		pSymbol->get_name(&bstrName);
		//		outfile<<L"name1 : "<<bstrName<<endl;
		//		pSymbol->get_undecoratedName(&bstrName);
		//		outfile<<L"undecoratedName : "<<bstrName<<endl;
		//		wprintf(L"undecoratedName = %Ls\n",bstrName);
		if (pSymbol->get_symTag(&dwSymTag) == S_OK&&
			dwSymTag != SymTagThunk &&
			pSymbol->get_name(&bstrName) == S_OK &&
			pSymbol->get_undecoratedName(&bstrUndname) == S_OK
			){

			for (int i = 0; i < _countof(strs); i++)
			{
				if (!_wcsnicmp(strs[i], bstrName, wcslen(bstrName)))
				{
					pSymbol->get_relativeVirtualAddress(&dwRVA);
					getAddress::addressToName[curBase + dwRVA] = strs[i];
					break;
				}

			}
			

			pSymbol->get_relativeVirtualAddress(&dwRVA);
			pSymbol->get_addressSection(&dwSeg);
			pSymbol->get_addressOffset(&dwOff);
			//				outfile<<L" "<<(dwRVA+krnlBase)<<L" "<<(dwRVA+win32kBase)<<endl;
			//				outfile<<szApiName<<L" : Seg "<<hex<<dwSeg <<L"  off "<<hex<<dwOff<<endl;
//			wcout << dwRVA << L" : " << bstrName << endl;
		}
		SysFreeString(bstrName);
		SysFreeString(bstrUndname);
		pSymbol->Release();
	}

	pEnumSymbols->Release();
	return true;
}


PVOID getAddress::GetAllProcAddrFromKernelPdb()
{
	if (LoadDataFromPdb(L"ntkrnlmp.pdb"))
	{
		curBase = krnlBase;
		FindPublicAll(pSymbol);
	}
	
	if (LoadDataFromPdb(L"win32k.pdb"))
	{
		curBase = win32kBase;
		FindPublicAll(pSymbol);
	}
	return PVOID(0);
}


getAddress::getAddress(void)
{
	outfile.open("C:\\Users\\1\\Desktop\\trace\\conflict.txt");
	DWORD g_dwMachineType = CV_CFL_80386;
	DWORD dwMachType = 0;

	//	outfile.open(L"symbol_output.txt");

	GetkrnlBase();

	GetAllProcAddrFromKernelPdb();

	/*for (int i = 0; i<_countof(single); i++)
		GetProcAddrFromKernelPdb(L"ntkrnlmp.pdb", single[i]);*/


	//	getchar();
	/*
	for(map<DWORD,LPCWSTR>::iterator i=addressToName.begin(); i != addressToName.end();i++)
	{
	wcout<<i->second<<" "<<i->first<<endl;
	}
	*/

	//	outfile.flush();
	//	outfile.close();


}

