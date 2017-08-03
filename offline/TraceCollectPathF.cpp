
//Turns the DEFINE_GUID for EventTraceGuid into a const.
#define INITGUID





#include <windows.h>
#include <stdio.h>
#include <wbemidl.h>
#include <wmistr.h>
#include <evntrace.h>
#include <tdh.h>
#include <in6addr.h>
#include <stdlib.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <sstream>
#include <set>
#include <sddl.h>
#include <time.h>



#include <stdlib.h>

#include <memory>

#include <atlconv.h>

#include <unordered_map>



using namespace std;

#include "getAddress.h"
#include "tlhelp32.h"

#pragma comment(lib, "tdh.lib")

#define LOGFILE_PATH L"G:\\source\\DIA_findSymbolByVA\\record.etl"

struct ProcessAndThread{
	int processID;
	int threadID;
	ProcessAndThread(){
		processID = 0;
		threadID = 0;
	}
};
// Used to calculate CPU usage

ULONG g_TimerResolution = 0;

// Used to determine if the session is a private session or kernel session.
// You need to know this when accessing some members of the EVENT_TRACE.Header
// member (for example, KernelTime or UserTime).

BOOL g_bUserMode = FALSE;

// Handle to the trace file that you opened.

TRACEHANDLE g_hTrace = 0;

// Prototypes

void WINAPI ProcessEvent(PEVENT_RECORD pEvent);
DWORD GetEventInformation(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO & pInfo);
PBYTE PrintProperties(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, DWORD PointerSize, USHORT i, PBYTE pUserData, PBYTE pEndOfUserData);
DWORD GetPropertyLength(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT PropertyLength, DWORD puserdata);
DWORD GetArraySize(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT ArraySize);
DWORD GetMapInfo(PEVENT_RECORD pEvent, LPWSTR pMapName, DWORD DecodingSource, PEVENT_MAP_INFO & pMapInfo);
void RemoveTrailingSpace(PEVENT_MAP_INFO pMapInfo);
DWORD GetPIDbyThreadID(DWORD threadID);
DWORD PCharToDWORD(LPWSTR pFormattedData);
LPWSTR addressTosyscall(DWORD address);
DWORD string16ToDword(string s);
string getEnv(const string& key, const string& defaultValue);
string getArg(char* argv[], int argc, int index, const string& defaultValue);
string GetPathbyPID(DWORD pid);
BOOL DosPathToNtPath(LPTSTR pszDosPath, LPTSTR pszNtPath);
BOOL GetProcessFullPath(DWORD dwPID, TCHAR pszFullPath[MAX_PATH]);
BOOL pidInWhitelist(DWORD pid);
VOID getallthread(VOID);
VOID getallprocess(VOID);
string changeSeparator(string ss);
string GetProcessName(int PID);
int GetProcessID(string ProcessNameOfRat);

//global values
BOOL finishOp;
BOOL SystemFlag = false;
wofstream outFile;
DWORD  MessageCount;
DWORD startPID;
DWORD curPID[4] = { 0L };
DWORD threadID_list[4] = { 0L };
DWORD threadID;
DWORD keyhandle;
DWORD Irp;
DWORD stop;
DWORD start;
DWORD eventcount;
getAddress g;
string path = "";
string systemcallexit = "";
set<DWORD> whiteListPID;
int CPID, filekey;
bool EndFlag = false;
int ProcessIDOfRat;
string ProcessNameOfRat;
string EventType;
string strName = "";
string parm = "";
// hash map for file name
DWORD fileObject;
ProcessAndThread nextsystemcallexit;
unordered_map<DWORD, string> fileNameMap;
unordered_map<int, ofstream*> OutFile_Map;
unordered_map<int, int> messageID_Map;
unordered_map<DWORD, string> KeyNameMap;
unordered_map<DWORD, DWORD> ThreadIDtoPID_map;
unordered_map<DWORD, string> ProcessName_map;
unordered_map<DWORD, DWORD> messageID2ThreadID;
unordered_map<DWORD, ProcessAndThread> IrpToProcessID;
//global values for activeMQ


void wmain(int argc, char* argv[])

{
	outFile.open("TraceOfETW.txt");
	whiteListPID.clear();
	whiteListPID.insert(GetCurrentProcessId());
	//initial publisher
	cout << "Please input ProcessName:";
	cin >> ProcessNameOfRat;

	getallprocess();
	getallthread();

	if (ProcessNameOfRat != "CPID") ProcessIDOfRat = GetProcessID(ProcessNameOfRat); else
	{
		cin >> ProcessIDOfRat;
		cout << GetProcessName(ProcessIDOfRat) << endl;
	}

	cout << "Initialized." << endl;
	MessageCount = 0L;
	start = clock();
begin:
	TDHSTATUS status = ERROR_SUCCESS;
	EVENT_TRACE_LOGFILE trace;
	TRACE_LOGFILE_HEADER* pHeader = &trace.LogfileHeader;

	// Identify the log file from which you want to consume events
	// and the callbacks used to process the events and buffers.

	ZeroMemory(&trace, sizeof(EVENT_TRACE_LOGFILE));


	//consume data from logfile

	//	trace.LogFileName = (LPWSTR) LOGFILE_PATH;
	//    trace.EventRecordCallback = (PEVENT_RECORD_CALLBACK) (ProcessEvent);
	//    trace.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD;


	//consume data in real-time mode

	trace.LoggerName = KERNEL_LOGGER_NAME;
	//	trace.LoggerName = L"Windows Kernel Trace";
	trace.EventRecordCallback = (PEVENT_RECORD_CALLBACK)(ProcessEvent);
	trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;


	g_hTrace = OpenTrace(&trace);
	if (INVALID_PROCESSTRACE_HANDLE == g_hTrace)
	{
		wprintf(L"OpenTrace failed with %lu\n", GetLastError());
		goto cleanup;
	}

	g_bUserMode = pHeader->LogFileMode & EVENT_TRACE_PRIVATE_LOGGER_MODE;

	if (pHeader->TimerResolution > 0)
	{
		g_TimerResolution = pHeader->TimerResolution / 10000;
	}

	//    wprintf(L"Number of events lost:  %lu\n", pHeader->EventsLost);

	// Use pHeader to access all fields prior to LoggerName.
	// Adjust pHeader based on the pointer size to access
	// all fields after LogFileName. This is required only if
	// you are consuming events on an architecture that is 
	// different from architecture used to write the events.

	if (pHeader->PointerSize != sizeof(PVOID))
	{
		pHeader = (PTRACE_LOGFILE_HEADER)((PUCHAR)pHeader +
			2 * (pHeader->PointerSize - sizeof(PVOID)));
	}

	//    wprintf(L"Number of buffers lost: %lu\n\n", pHeader->BuffersLost);


	status = ProcessTrace(&g_hTrace, 1, 0, 0);
	if (status != ERROR_SUCCESS && status != ERROR_CANCELLED)
	{
		wprintf(L"ProcessTrace failed with %lu\n", status);
		goto cleanup;
	}



	status = ProcessTrace(&g_hTrace, 1, 0, 0);
	if (EndFlag) {
		cout << "END" << endl;
		return;
	}
	while (status == ERROR_SUCCESS)
	{
		status = ProcessTrace(&g_hTrace, 1, 0, 0);
		if (EndFlag) {
			cout << "END" << endl;
			return;
		}
	}



cleanup:

	//	wprintf(L"The process is ended with %lu\n", status);
	if (INVALID_PROCESSTRACE_HANDLE != g_hTrace)
	{
		status = CloseTrace(g_hTrace);
	}
	outFile.clear();
	goto begin;

}


// Callback that receives the events. 

VOID WINAPI ProcessEvent(PEVENT_RECORD pEvent)
{
	DWORD status = ERROR_SUCCESS;
	PTRACE_EVENT_INFO pInfo = NULL;
	LPWSTR pwsEventGuid = NULL;
	PBYTE pUserData = NULL;
	PBYTE pEndOfUserData = NULL;
	DWORD PointerSize = 0;
	ULONGLONG TimeStamp = 0;
	ULONGLONG Nanoseconds = 0;
	SYSTEMTIME st;
	SYSTEMTIME stLocal;
	FILETIME ft;


	finishOp = false;
	CPID = 0;
	if (IsEqualGUID(pEvent->EventHeader.ProviderId, EventTraceGuid) &&
		pEvent->EventHeader.EventDescriptor.Opcode == EVENT_TRACE_TYPE_INFO)
	{
		wprintf(L"A Event is being skipped\n");
		; // Skip this event.
	}
	// Skips the event if it is not SysClEnter(51) or CSwitch(36).
	else
	if (
		(pEvent->EventHeader.EventDescriptor.Opcode == 2 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d0)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 1 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d0)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 32 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d0)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 33 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d0)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 39 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d0)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 3 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d0)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 4 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d0)

		|| (pEvent->EventHeader.EventDescriptor.Opcode == 1 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d1)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 4 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d1)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 3 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d1)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 2 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d1)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 36 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d1)

		|| (pEvent->EventHeader.EventDescriptor.Opcode == 10 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d3)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 11 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d3)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 12 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d3)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 13 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d3)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 14 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d3)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 15 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d3)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 32 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d3)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 98 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d3)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 99 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d3)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 105 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d3)

		|| (pEvent->EventHeader.EventDescriptor.Opcode == 0 && pEvent->EventHeader.ProviderId.Data1 == 0x90cbdc39)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 77 && pEvent->EventHeader.ProviderId.Data1 == 0x90cbdc39)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 69 && pEvent->EventHeader.ProviderId.Data1 == 0x90cbdc39)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 70 && pEvent->EventHeader.ProviderId.Data1 == 0x90cbdc39)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 71 && pEvent->EventHeader.ProviderId.Data1 == 0x90cbdc39)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 75 && pEvent->EventHeader.ProviderId.Data1 == 0x90cbdc39)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 65 && pEvent->EventHeader.ProviderId.Data1 == 0x90cbdc39)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 66 && pEvent->EventHeader.ProviderId.Data1 == 0x90cbdc39)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 73 && pEvent->EventHeader.ProviderId.Data1 == 0x90cbdc39)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 35 && pEvent->EventHeader.ProviderId.Data1 == 0x90cbdc39)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 36 && pEvent->EventHeader.ProviderId.Data1 == 0x90cbdc39)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 67 && pEvent->EventHeader.ProviderId.Data1 == 2429279289)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 68 && pEvent->EventHeader.ProviderId.Data1 == 2429279289)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 32 && pEvent->EventHeader.ProviderId.Data1 == 2429279289)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 64)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 74)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 72)

		|| (pEvent->EventHeader.EventDescriptor.Opcode == 10 && pEvent->EventHeader.ProviderId.Data1 == 2924704302)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 12 && pEvent->EventHeader.ProviderId.Data1 == 2924704302)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 13 && pEvent->EventHeader.ProviderId.Data1 == 2924704302)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 15 && pEvent->EventHeader.ProviderId.Data1 == 2924704302)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 17 && pEvent->EventHeader.ProviderId.Data1 == 2924704302)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 18 && pEvent->EventHeader.ProviderId.Data1 == 2924704302)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 19 && pEvent->EventHeader.ProviderId.Data1 == 2924704302)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 20 && pEvent->EventHeader.ProviderId.Data1 == 2924704302)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 21 && pEvent->EventHeader.ProviderId.Data1 == 2924704302)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 24 && pEvent->EventHeader.ProviderId.Data1 == 2924704302)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 25 && pEvent->EventHeader.ProviderId.Data1 == 2924704302)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 26 && pEvent->EventHeader.ProviderId.Data1 == 2924704302)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 27 && pEvent->EventHeader.ProviderId.Data1 == 2924704302)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 11 && pEvent->EventHeader.ProviderId.Data1 == 2924704302)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 16 && pEvent->EventHeader.ProviderId.Data1 == 2924704302)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 14 && pEvent->EventHeader.ProviderId.Data1 == 2924704302)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 22 && pEvent->EventHeader.ProviderId.Data1 == 2924704302)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 23 && pEvent->EventHeader.ProviderId.Data1 == 2924704302)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 11 && pEvent->EventHeader.ProviderId.Data1 == 2924704302)

		|| (pEvent->EventHeader.EventDescriptor.Opcode == 12 && pEvent->EventHeader.ProviderId.Data1 == 2586315456)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 15 && pEvent->EventHeader.ProviderId.Data1 == 2586315456)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 13 && pEvent->EventHeader.ProviderId.Data1 == 2586315456)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 11 && pEvent->EventHeader.ProviderId.Data1 == 2586315456)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 10 && pEvent->EventHeader.ProviderId.Data1 == 2586315456)

		|| (pEvent->EventHeader.EventDescriptor.Opcode == 35 && pEvent->EventHeader.ProviderId.Data1 == 0x45d8cccd)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 36 && pEvent->EventHeader.ProviderId.Data1 == 0x45d8cccd)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 37 && pEvent->EventHeader.ProviderId.Data1 == 0x45d8cccd)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 33 && pEvent->EventHeader.ProviderId.Data1 == 1171836109)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 34 && pEvent->EventHeader.ProviderId.Data1 == 1171836109)

		|| (pEvent->EventHeader.EventDescriptor.Opcode == 10 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d4)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 11 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d4)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 12 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d4)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 13 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d4)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 14 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d4)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 15 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d4)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 52 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d4)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 53 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d4)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 37 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d4)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 34 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d4)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 35 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d4)

		//|| (pEvent->EventHeader.EventDescriptor.Opcode == 66 && pEvent->EventHeader.ProviderId.Data1 == 0xce1dbfb4)
		//|| (pEvent->EventHeader.EventDescriptor.Opcode == 68 && pEvent->EventHeader.ProviderId.Data1 == 0xce1dbfb4)
		//|| (pEvent->EventHeader.EventDescriptor.Opcode == 69 && pEvent->EventHeader.ProviderId.Data1 == 0xce1dbfb4)
		//|| (pEvent->EventHeader.EventDescriptor.Opcode == 52 && pEvent->EventHeader.ProviderId.Data1 == 0xce1dbfb4)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 67 && pEvent->EventHeader.ProviderId.Data1 == 0xce1dbfb4)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 46 && pEvent->EventHeader.ProviderId.Data1 == 0xce1dbfb4)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 51)

		|| (pEvent->EventHeader.EventDescriptor.Opcode == 10 && pEvent->EventHeader.ProviderId.Data1 == 0x2cb15d1d)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 2 && pEvent->EventHeader.ProviderId.Data1 == 0x2cb15d1d)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 3 && pEvent->EventHeader.ProviderId.Data1 == 0x2cb15d1d)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 4 && pEvent->EventHeader.ProviderId.Data1 == 0x2cb15d1d)
		|| (pEvent->EventHeader.EventDescriptor.Opcode == 10 && pEvent->EventHeader.ProviderId.Data1 == 749821213)

		|| (pEvent->EventHeader.EventDescriptor.Opcode == 32 && pEvent->EventHeader.ProviderId.Data1 == 0xd837ca92)
		)
	{
		// Process the event. The pEvent->UserData member is a pointer to 
		// the event specific data, if it exists.
		//if (pEvent->EventHeader.EventDescriptor.Opcode == 2 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d0)
		//{
		//	if (pEvent->EventHeader.ProcessId == ProcessIDOfRat) exit(0); else return;
		//}
		//else
/*		if (pEvent->EventHeader.EventDescriptor.Opcode == 1 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d0){
			cout << "FIND" << endl;
			int userdata = int (pEvent->UserData);
			userdata += 8;
			CPID = *(DWORD*)(userdata);
			userdata += 52;
			USES_CONVERSION;
			char* ch = new char;
			ch = (char*)userdata;
			ProcessName_map[CPID] = ch;
			userdata = 0;
		}else
		if (pEvent->EventHeader.EventDescriptor.Opcode == 3 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d0){
			int userdata = int (pEvent->UserData);
			userdata += 8;
			CPID = *(DWORD*)(userdata);
			userdata += 52;
			USES_CONVERSION;
			char* ch = new char;
			ch = (char*)userdata;
			ProcessName_map[CPID] = ch;
			userdata = 0;
		}
		else*/
		{
			eventcount++;
			stop = clock();
			if ((stop - start)/CLOCKS_PER_SEC>=60){
				cout << eventcount / ((stop - start) / CLOCKS_PER_SEC) << " events per second" << endl;
				start = clock();
				eventcount = 0;
			}
			if (pEvent->EventHeader.EventDescriptor.Opcode == 51)
			{
				DWORD dname = *(DWORD*)(pEvent->UserData);
				LPWSTR name = addressTosyscall(dname);
				if (name != NULL)
				{
					USES_CONVERSION;
					CPID = ThreadIDtoPID_map[curPID[pEvent->BufferContext.ProcessorNumber]];
				  if (CPID != ProcessIDOfRat) goto cleanup;
					parm = "\"SystemCall:" + string(W2A(name)) + '\"';
					threadID = threadID_list[pEvent->BufferContext.ProcessorNumber];
					EventType = "SystemCall";
					if (parm.find("\\") != string::npos)
					{
						parm = changeSeparator(parm);
						//				cout << parm << endl;
					}
					ft.dwHighDateTime = pEvent->EventHeader.TimeStamp.HighPart;
					ft.dwLowDateTime = pEvent->EventHeader.TimeStamp.LowPart;

					FileTimeToSystemTime(&ft, &st);
					SystemTimeToTzSpecificLocalTime(NULL, &st, &stLocal);

					TimeStamp = pEvent->EventHeader.TimeStamp.QuadPart;
					//		wcout<<"Timestamp :"<<TimeStamp<<endl;
					Nanoseconds = (TimeStamp % 10000000) * 100;

					if (threadID == 0 && pEvent->EventHeader.ThreadId != -1) threadID = pEvent->EventHeader.ThreadId;
					string ProcessName = GetProcessName(CPID);
					stringstream ss;
					long long TimeStamp = pEvent->EventHeader.TimeStamp.QuadPart;
					ss << " { ";
					ss << " \"Time\": \"";
					ss << stLocal.wMonth;
					ss << "-";
					ss << stLocal.wDay;
					ss << "-";
					ss << stLocal.wYear;
					ss << " ";
					ss << stLocal.wHour;
					ss << ":";
					ss << stLocal.wMinute;
					ss << ":";
					ss << stLocal.wSecond;
					ss << ".";
					ss << Nanoseconds;
					ss << "\", \"EventType\": \"";
					ss << EventType;
					ss << "\",\"ThreadID\": \"";
					ss << threadID;
					ss << "\",\"";
					ss << "pid\" : \"";
					ss << ProcessIDOfRat;

					if (parm != "") ss << "\",\"parameter\" : "; else  ss << "\",\"parameter\" : \"\"";
					ss << parm;
					ss << " }";
					string messageBody = ss.str();
					MessageCount++;
					if (OutFile_Map.find(threadID) != OutFile_Map.end()) {
						*OutFile_Map[threadID] << messageBody << endl;
					}
					else{
						string FileName = ".\\DATA\\ThreadId" + to_string(threadID) + ".output";
						OutFile_Map[threadID] = new ofstream(FileName.c_str());
						*OutFile_Map[threadID] << messageBody << endl;
					}

					if (MessageCount % 10000 == 0)
					{
						wcout << L"published " << MessageCount << L" messages!" << endl;
					}
					CPID = 0;
					threadID = 0;
					filekey = 0;
					fileObject = 0;
					Irp = 0;
					strName = "";
					parm = "";
					EventType = "";
				}
				goto cleanup;
			}
			status = GetEventInformation(pEvent, pInfo);
			if (pEvent->EventHeader.EventDescriptor.Opcode == 36 && pEvent->EventHeader.ProviderId.Data1 == 0x45d8cccd)
			{
				USES_CONVERSION;
				parm += "\"IsServerPort: ";
				parm += to_string(*(DWORD*)pEvent->UserData);
				parm += "\", ";
				parm += "\"PortName: ";
				parm += (string)W2A((wchar_t*)((int)pEvent->UserData + 4));
				parm += "\" ";
				CPID = pEvent->EventHeader.ProcessId;
				threadID = pEvent->EventHeader.ThreadId;
				EventType = (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->TaskNameOffset)) + (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->OpcodeNameOffset));
				finishOp = true;
			}
			if (ERROR_SUCCESS != status)
			{
				wprintf(L"GetEventInformation failed with %lu\n", status);
				goto cleanup;
			}

			// Determine whether the event is defined by a MOF class, in an
			// instrumentation manifest, or a WPP template; to use TDH to decode
			// the event, it must be defined by one of these three sources.

			if (DecodingSourceWbem == pInfo->DecodingSource)  // MOF class
			{
				HRESULT hr = StringFromCLSID(pInfo->EventGuid, &pwsEventGuid);

				if (FAILED(hr))
				{
					wprintf(L"StringFromCLSID failed with 0x%x\n", hr);
					status = hr;
					goto cleanup;
				}

				//            wprintf(L"\nEvent GUID: %s\n", pwsEventGuid);
				CoTaskMemFree(pwsEventGuid);
				pwsEventGuid = NULL;

				//            wprintf(L"Event version: %d\n", pEvent->EventHeader.EventDescriptor.Version);
				//            wprintf(L"Event type: %d\n", pEvent->EventHeader.EventDescriptor.Opcode);
			}
			else if (DecodingSourceXMLFile == pInfo->DecodingSource) // Instrumentation manifest
			{
				wprintf(L"Event ID: %d\n", pInfo->EventDescriptor.Id);
			}
			else // Not handling the WPP case
			{
				goto cleanup;
			}

			// Print the time stamp for when the event occurred.



			// If the event contains event-specific data use TDH to extract
			// the event data. For this example, to extract the data, the event 
			// must be defined by a MOF class or an instrumentation manifest.

			// Need to get the PointerSize for each event to cover the case where you are
			// consuming events from multiple log files that could have been generated on 
			// different architectures. Otherwise, you could have accessed the pointer
			// size when you opened the trace above (see pHeader->PointerSize).

			if (EVENT_HEADER_FLAG_32_BIT_HEADER == (pEvent->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER))
			{
				PointerSize = 4;
			}
			else
			{
				PointerSize = 8;
			}

			pUserData = (PBYTE)pEvent->UserData;
			pEndOfUserData = (PBYTE)pEvent->UserData + pEvent->UserDataLength;

			// Print the event data for all the top-level properties. Metadata for all the 
			// top-level properties come before structure member properties in the 
			// property information array.

			//		cout << "Trying to lalalla" << endl;

			for (USHORT i = 0; i < pInfo->TopLevelPropertyCount; i++)
			{
				pUserData = PrintProperties(pEvent, pInfo, PointerSize, i, pUserData, pEndOfUserData);
				if (NULL == pUserData)
				{
					wprintf(L"Printing top level properties failed.\n");
					goto cleanup;
				}
				if (finishOp)
					break;
			}
			//getchar();
		}

	cleanup:

		if (pInfo)
		{
			free(pInfo);
		}

		if (ERROR_SUCCESS != status || NULL == pUserData || EndFlag)
		{
			CloseTrace(g_hTrace);
		}
	}
}


// Print the property.

PBYTE PrintProperties(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, DWORD PointerSize, USHORT i, PBYTE pUserData, PBYTE pEndOfUserData)
{
	TDHSTATUS status = ERROR_SUCCESS;
	USHORT PropertyLength = 0;
	DWORD FormattedDataSize = 0;
	USHORT UserDataConsumed = 0;
	USHORT UserDataLength = 0;
	LPWSTR pFormattedData = NULL;
	DWORD LastMember = 0;  // Last member of a structure
	USHORT ArraySize = 0;
	PEVENT_MAP_INFO pMapInfo = NULL;
	int OPcode = pEvent->EventHeader.EventDescriptor.Opcode;
	ULONGLONG TimeStamp = 0;
	ULONGLONG Nanoseconds = 0;
	SYSTEMTIME st;
	SYSTEMTIME stLocal;
	FILETIME ft;


	int eventType = OPcode;

	// Get the length of the property.
	if (finishOp) goto cleanup;
	status = GetPropertyLength(pEvent, pInfo, i, &PropertyLength,(DWORD)pUserData);

	if (ERROR_SUCCESS != status)
	{
		wprintf(L"GetPropertyLength failed.\n");
		pUserData = NULL;
		goto cleanup;
	}

	// Get the size of the array if the property is an array.

	status = GetArraySize(pEvent, pInfo, i, &ArraySize);

	for (USHORT k = 0; k < ArraySize; k++)
	{
		// If the property is a structure, print the members of the structure.

		if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyStruct) == PropertyStruct)
		{
			LastMember = pInfo->EventPropertyInfoArray[i].structType.StructStartIndex +
				pInfo->EventPropertyInfoArray[i].structType.NumOfStructMembers;

			for (USHORT j = pInfo->EventPropertyInfoArray[i].structType.StructStartIndex; j < LastMember; j++)
			{
				pUserData = PrintProperties(pEvent, pInfo, PointerSize, j, pUserData, pEndOfUserData);
				if (NULL == pUserData)
				{
					wprintf(L"Printing the members of the structure failed.\n");
					pUserData = NULL;
					goto cleanup;
				}
			}
		}
		else
		{
			// Get the name/value mapping if the property specifies a value map.

			status = GetMapInfo(pEvent,
				(PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].nonStructType.MapNameOffset),
				pInfo->DecodingSource,
				pMapInfo);

			if (ERROR_SUCCESS != status)
			{
				wprintf(L"GetMapInfo failed\n");
				pUserData = NULL;
				goto cleanup;
			}

			// Get the size of the buffer required for the formatted data.

			status = TdhFormatProperty(
				pInfo,
				pMapInfo,
				PointerSize,
				pInfo->EventPropertyInfoArray[i].nonStructType.InType,
				pInfo->EventPropertyInfoArray[i].nonStructType.OutType,
				PropertyLength,
				(USHORT)(pEndOfUserData - pUserData),
				pUserData,
				&FormattedDataSize,
				pFormattedData,
				&UserDataConsumed);

			if (ERROR_INSUFFICIENT_BUFFER == status)
			{
				if (pFormattedData)
				{
					free(pFormattedData);
					pFormattedData = NULL;
				}

				pFormattedData = (LPWSTR)malloc(FormattedDataSize);
				if (pFormattedData == NULL)
				{
					wprintf(L"Failed to allocate memory for formatted data (size=%lu).\n", FormattedDataSize);
					status = ERROR_OUTOFMEMORY;
					pUserData = NULL;
					goto cleanup;
				}

				status = TdhFormatProperty(
					pInfo,
					pMapInfo,
					PointerSize,
					pInfo->EventPropertyInfoArray[i].nonStructType.InType,
					pInfo->EventPropertyInfoArray[i].nonStructType.OutType,
					PropertyLength,
					(USHORT)(pEndOfUserData - pUserData),
					pUserData,
					&FormattedDataSize,
					pFormattedData,
					&UserDataConsumed);
			}


			if (ERROR_SUCCESS == status)
			{
				if (pEvent->EventHeader.ProviderId.Data1 == 0x90cbdc39 && (pEvent->EventHeader.EventDescriptor.Opcode == 0 || pEvent->EventHeader.EventDescriptor.Opcode == 32 || pEvent->EventHeader.EventDescriptor.Opcode == 35 || pEvent->EventHeader.EventDescriptor.Opcode == 36)){
					if (i == 0){
						threadID = curPID[pEvent->BufferContext.ProcessorNumber];
						CPID = ThreadIDtoPID_map[threadID];
						if (CPID != ProcessIDOfRat){
							finishOp = TRUE;
							goto cleanup;
						}
					}
					if (wcscmp(L"FileObject", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						)
					{
						fileObject = *(DWORD*)pUserData;
					}
					else
					if (wcscmp(L"FileName", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						)
					{
						USES_CONVERSION;
						parm = "\"FileName:" + string(W2A(pFormattedData)) + '\"';

						fileNameMap[fileObject] = parm;
						finishOp = TRUE;
						EventType = (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->TaskNameOffset)) + (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->OpcodeNameOffset));
						goto cleanup;
					}
					pUserData += UserDataConsumed;
				}else
				
				if (pEvent->EventHeader.ProviderId.Data1 == 0x90cbdc39 && (pEvent->EventHeader.EventDescriptor.Opcode == 72 || pEvent->EventHeader.EventDescriptor.Opcode == 77)){
					if (wcscmp(L"TTID", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						)
						{
							threadID = PCharToDWORD(pFormattedData);
							CPID = GetPIDbyThreadID(threadID);
							if (CPID != ProcessIDOfRat){
								finishOp = TRUE;
								goto cleanup;
							}
						}
						else
					if (wcscmp(L"FileObject", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
							)
						{
							fileObject = *(DWORD*)pUserData;
							USES_CONVERSION;
							parm += "\"";
							parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
							parm += ": ";
							parm += string(W2A(pFormattedData));
							parm += "\", ";
						}
						else
					if (wcscmp(L"FileName", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
							)
						{
							USES_CONVERSION;
							if (fileNameMap.find(fileObject) != fileNameMap.end())parm += fileNameMap[fileObject]; else parm = parm + "\"\"";
							finishOp = TRUE;
							EventType = (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->TaskNameOffset)) + (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->OpcodeNameOffset));
							goto cleanup;
					}
					else{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
						pUserData += UserDataConsumed;
				}else


				if (pEvent->EventHeader.ProviderId.Data1 == 0x90cbdc39 && (pEvent->EventHeader.EventDescriptor.Opcode == 64))
				{
					if (wcscmp(L"TTID", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						)
					{
						threadID = PCharToDWORD(pFormattedData);
						CPID = GetPIDbyThreadID(threadID);
						if (!CPID) CPID = ThreadIDtoPID_map[threadID];
						if (CPID != ProcessIDOfRat){
							finishOp = TRUE;
							goto cleanup;
						}
					}
					else
					if (wcscmp(L"FileObject", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						)
					{
						fileObject = *(DWORD*)pUserData;
					}
					else
					if (wcscmp(L"OpenPath", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						)
					{
						USES_CONVERSION;
						string ss= "\"OpenPath:" + string(W2A(pFormattedData)) + "\" ";
						fileNameMap[fileObject] = ss;
						parm += ss;
						finishOp = TRUE;
						EventType = (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->TaskNameOffset)) + (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->OpcodeNameOffset));
						goto cleanup;
					}
					else{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
					pUserData += UserDataConsumed;
				}else

				if (pEvent->EventHeader.ProviderId.Data1 == 0x90cbdc39 && (pEvent->EventHeader.EventDescriptor.Opcode == 67 || pEvent->EventHeader.EventDescriptor.Opcode == 68))
				{
					if (wcscmp(L"TTID", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						)
					{
						threadID = PCharToDWORD(pFormattedData);
						if (ThreadIDtoPID_map.find(threadID) != ThreadIDtoPID_map.end())CPID = ThreadIDtoPID_map[threadID]; else CPID = GetPIDbyThreadID(threadID);
						if (CPID != ProcessIDOfRat){
							finishOp = TRUE;
							goto cleanup;
						}
					}
					else
					if (wcscmp(L"FileKey", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						)
					{
						filekey = *(DWORD*)pUserData;
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
					else
					if (wcscmp(L"FileObject", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						)
					{
						fileObject = *(DWORD*)pUserData;
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}else
					if (wcscmp(L"IoFlags", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						){
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
						EventType = (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->TaskNameOffset)) + (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->OpcodeNameOffset));
						if (fileNameMap.find(filekey) != fileNameMap.end()) parm += fileNameMap[filekey]; else{
							if (fileNameMap.find(fileObject) != fileNameMap.end())parm += fileNameMap[fileObject]; else parm += "\"\" ";
						}
						finishOp = TRUE;
						goto cleanup;
					}
					else{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
					pUserData += UserDataConsumed;
				}else


				if (pEvent->EventHeader.ProviderId.Data1 == 0xae53722e && (pEvent->EventHeader.EventDescriptor.Opcode == 10 || pEvent->EventHeader.EventDescriptor.Opcode == 11 || pEvent->EventHeader.EventDescriptor.Opcode == 12 || pEvent->EventHeader.EventDescriptor.Opcode == 13 || pEvent->EventHeader.EventDescriptor.Opcode == 14 || pEvent->EventHeader.EventDescriptor.Opcode == 15 || pEvent->EventHeader.EventDescriptor.Opcode == 16 || pEvent->EventHeader.EventDescriptor.Opcode == 17 || pEvent->EventHeader.EventDescriptor.Opcode == 18 || pEvent->EventHeader.EventDescriptor.Opcode == 19 || pEvent->EventHeader.EventDescriptor.Opcode == 20 || pEvent->EventHeader.EventDescriptor.Opcode == 21 || pEvent->EventHeader.EventDescriptor.Opcode == 22 || pEvent->EventHeader.EventDescriptor.Opcode == 23 || pEvent->EventHeader.EventDescriptor.Opcode == 24 || pEvent->EventHeader.EventDescriptor.Opcode == 25 || pEvent->EventHeader.EventDescriptor.Opcode == 26 || pEvent->EventHeader.EventDescriptor.Opcode == 27))
				{
					//if (i == 0){
					//	CPID = pEvent->EventHeader.ProcessId;
					//	threadID = pEvent->EventHeader.ThreadId;
					//	if (CPID != ProcessIDOfRat){
					//		finishOp = TRUE;
					//		goto cleanup;
					//	}
					//}
					if (wcscmp(L"KeyHandle", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						)
					{
						keyhandle = *(DWORD*)(pUserData);
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}else
					if (wcscmp(L"KeyName", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						)
					{
						USES_CONVERSION;
						string ss(W2A((wchar_t*)pUserData));
						EventType = (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->TaskNameOffset)) + (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->OpcodeNameOffset));
						if (ss==""&&KeyNameMap.find(keyhandle) != KeyNameMap.end() ){
							parm =parm+"\""+ KeyNameMap[keyhandle]+"\" ";
						}else
						if (pEvent->EventHeader.EventDescriptor.Opcode == 22 || pEvent->EventHeader.EventDescriptor.Opcode == 10 || pEvent->EventHeader.EventDescriptor.Opcode == 11)
						{
							if (ss != "") KeyNameMap[keyhandle] = ss;
							parm = parm + "\"";
							parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
							parm += ": ";
							parm = parm + ss + "\" ";
						}
						else{
							if (ss != "") KeyNameMap[keyhandle] = ss;
							parm = parm + "\"";
							parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
							parm += ": ";
							parm = parm + ss + "\" ";
						}
						finishOp = TRUE;
						goto cleanup;
					}
					else{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
					pUserData += UserDataConsumed;
				}else


				if (pEvent->EventHeader.ProviderId.Data1 == 0x90cbdc39 && (pEvent->EventHeader.EventDescriptor.Opcode == 69 || pEvent->EventHeader.EventDescriptor.Opcode == 70 || pEvent->EventHeader.EventDescriptor.Opcode == 71 || pEvent->EventHeader.EventDescriptor.Opcode == 74 || pEvent->EventHeader.EventDescriptor.Opcode == 75))
				{
					if (wcscmp(L"TTID", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						)
					{
						threadID = PCharToDWORD(pFormattedData);
						if (ThreadIDtoPID_map.find(threadID) != ThreadIDtoPID_map.end())CPID = ThreadIDtoPID_map[threadID]; else CPID = GetPIDbyThreadID(threadID);
						if (CPID != ProcessIDOfRat){
							finishOp = TRUE;
							goto cleanup;
						}
					}
					else
					if (wcscmp(L"FileObject", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						)
					{
						USES_CONVERSION;
						fileObject = *(DWORD*)pUserData;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
					else
					if (wcscmp(L"FileKey", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						)
					{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
						filekey = *(DWORD*)pUserData;
					}
					else
					if (wcscmp(L"InfoClass", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						){
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
						EventType = (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->TaskNameOffset)) + (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->OpcodeNameOffset));
						if (fileNameMap.find(filekey) != fileNameMap.end()) parm += fileNameMap[filekey]; else{
							if (fileNameMap.find(fileObject) != fileNameMap.end())parm += fileNameMap[fileObject]; else parm += "\"\" ";
						}
						finishOp = TRUE;
						goto cleanup;
					}
					else{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
					pUserData += UserDataConsumed;
				}else


				if (pEvent->EventHeader.ProviderId.Data1 == 0x90cbdc39 && (pEvent->EventHeader.EventDescriptor.Opcode == 65 || pEvent->EventHeader.EventDescriptor.Opcode == 66 ||  pEvent->EventHeader.EventDescriptor.Opcode == 73))
				{
					if (wcscmp(L"TTID", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						)
					{
						threadID = PCharToDWORD(pFormattedData);
						if (ThreadIDtoPID_map.find(threadID) != ThreadIDtoPID_map.end())CPID = ThreadIDtoPID_map[threadID]; else CPID = GetPIDbyThreadID(threadID);
						if (CPID != ProcessIDOfRat){
							finishOp = TRUE;
							goto cleanup;
						}
					}
					else
					if (wcscmp(L"FileObject", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						)
					{
						USES_CONVERSION;
						fileObject = *(DWORD*)pUserData;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
					else
					if (wcscmp(L"FileKey", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						)
					{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
						filekey = *(DWORD*)pUserData;
						EventType = (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->TaskNameOffset)) + (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->OpcodeNameOffset));
						if (fileNameMap.find(filekey) != fileNameMap.end()) parm += fileNameMap[filekey]; else{
							if (fileNameMap.find(fileObject) != fileNameMap.end())parm += fileNameMap[fileObject]; else parm += "\"\" ";
						}
						finishOp = TRUE;
						goto cleanup;
					}
					else{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
					pUserData += UserDataConsumed;
				}


				else
				if (pEvent->EventHeader.ProviderId.Data1 == 1171836109 && (pEvent->EventHeader.EventDescriptor.Opcode == 35 || pEvent->EventHeader.EventDescriptor.Opcode == 36 || pEvent->EventHeader.EventDescriptor.Opcode == 37))
				{
					if (i == 0){
						CPID = pEvent->EventHeader.ProcessId;
						threadID = pEvent->EventHeader.ThreadId;
						if (CPID != ProcessIDOfRat){
							finishOp = TRUE;
							goto cleanup;
						}
					}
					if (i == pInfo->TopLevelPropertyCount - 1){
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						EventType = (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->TaskNameOffset)) + (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->OpcodeNameOffset));
						parm += "\" ";
						finishOp = true;
						goto cleanup;
					}
					else{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
					pUserData += UserDataConsumed;
				}
				else


				if (pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d4 && (pEvent->EventHeader.EventDescriptor.Opcode == 10 || pEvent->EventHeader.EventDescriptor.Opcode == 11 ))
				{
					if (wcscmp(L"Irp", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						)
					{
						USES_CONVERSION;
						Irp = *(DWORD*)pUserData;
						if (IrpToProcessID.find(Irp) != IrpToProcessID.end()){
							CPID = IrpToProcessID[Irp].processID;
							threadID = IrpToProcessID[Irp].threadID;
						}
						else{
							CPID = pEvent->EventHeader.ProcessId;
							threadID = pEvent->EventHeader.ThreadId;
							IrpToProcessID[Irp].processID = CPID;
							IrpToProcessID[Irp].threadID = threadID;
						}
						if (CPID != ProcessIDOfRat){
							finishOp = TRUE;
							goto cleanup;
						}
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
					else
					if (i==pInfo->TopLevelPropertyCount-1)
					{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\" ";
						EventType = (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->TaskNameOffset)) + (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->OpcodeNameOffset));
						finishOp = true;
						goto cleanup;
					}
					else{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
					pUserData += UserDataConsumed;
				}else


				if (pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d4 && (pEvent->EventHeader.EventDescriptor.Opcode == 12 || pEvent->EventHeader.EventDescriptor.Opcode == 13 || pEvent->EventHeader.EventDescriptor.Opcode == 15))
				{
					if (wcscmp(L"Irp", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						)
					{
						USES_CONVERSION;
						Irp = *(DWORD*)pUserData;
						CPID = pEvent->EventHeader.ProcessId;
						threadID = pEvent->EventHeader.ThreadId;
						IrpToProcessID[Irp].processID = CPID;
						IrpToProcessID[Irp].threadID = threadID;
						if (CPID != ProcessIDOfRat){
							finishOp = TRUE;
							goto cleanup;
						}
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\" ";
						EventType = (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->TaskNameOffset)) + (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->OpcodeNameOffset));
						finishOp = true;
						goto cleanup;
					}
					pUserData += UserDataConsumed;
				}
				else


				if (pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d4 && pEvent->EventHeader.EventDescriptor.Opcode == 14)
				{
					if (wcscmp(L"Irp", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						)
					{
						USES_CONVERSION;
						Irp = *(DWORD*)pUserData;
						if (IrpToProcessID.find(Irp) != IrpToProcessID.end()){
							CPID = IrpToProcessID[Irp].processID;
							threadID = IrpToProcessID[Irp].threadID;
						}
						else{
							CPID = pEvent->EventHeader.ProcessId;
							threadID = pEvent->EventHeader.ThreadId;
							IrpToProcessID[Irp].processID = CPID;
							IrpToProcessID[Irp].threadID = threadID;
						}
						if (CPID != ProcessIDOfRat){
							finishOp = TRUE;
							goto cleanup;
						}
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\" ";
						EventType = (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->TaskNameOffset)) + (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->OpcodeNameOffset));
						finishOp = true;
						goto cleanup;
					}
					else{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
					pUserData += UserDataConsumed;
				}
				else


				if (pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d4 && (pEvent->EventHeader.EventDescriptor.Opcode == 52))
				{
					if (wcscmp(L"Irp", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						)
					{
						USES_CONVERSION;
						Irp = *(DWORD*)pUserData;
						if (IrpToProcessID.find(Irp) != IrpToProcessID.end()){
							CPID = IrpToProcessID[Irp].processID;
							threadID = IrpToProcessID[Irp].threadID;
						}
						else{
							CPID = pEvent->EventHeader.ProcessId;
							threadID = pEvent->EventHeader.ThreadId;
						}
						if (CPID != ProcessIDOfRat){
							finishOp = TRUE;
							goto cleanup;
						}
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
					else
					if (i == pInfo->TopLevelPropertyCount - 1)
					{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\" ";
						EventType = (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->TaskNameOffset)) + (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->OpcodeNameOffset));
						finishOp = true;
						goto cleanup;
					}
					else{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
					pUserData += UserDataConsumed;
				}
				else


				if (pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d4 && (pEvent->EventHeader.EventDescriptor.Opcode == 53))
				{
					if (wcscmp(L"Irp", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						)
					{
						USES_CONVERSION;
						Irp = *(DWORD*)pUserData;
						if (IrpToProcessID.find(Irp) != IrpToProcessID.end()){
							CPID = IrpToProcessID[Irp].processID;
							threadID = IrpToProcessID[Irp].threadID;
						}
						else{
							CPID = pEvent->EventHeader.ProcessId;
							threadID = pEvent->EventHeader.ThreadId;
						}
						if (CPID != ProcessIDOfRat){
							finishOp = TRUE;
							goto cleanup;
						}
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
					else
					if (i == pInfo->TopLevelPropertyCount - 1)
					{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\" ";
						EventType = (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->TaskNameOffset)) + (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->OpcodeNameOffset));
						finishOp = true;
						goto cleanup;
					}
					pUserData += UserDataConsumed;
				}
				else


				if (pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d4 && (pEvent->EventHeader.EventDescriptor.Opcode == 37))
				{
					if (wcscmp(L"IrpPtr", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						)
					{
						USES_CONVERSION;
						Irp = *(DWORD*)pUserData;
						if (IrpToProcessID.find(Irp) != IrpToProcessID.end()){
							CPID = IrpToProcessID[Irp].processID;
							threadID = IrpToProcessID[Irp].threadID;
						}
						else{
							CPID = pEvent->EventHeader.ProcessId;
							threadID = pEvent->EventHeader.ThreadId;
						}
						if (CPID != ProcessIDOfRat){
							finishOp = TRUE;
							goto cleanup;
						}
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
					else
					if (i == pInfo->TopLevelPropertyCount - 1)
					{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\" ";
						EventType = (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->TaskNameOffset)) + (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->OpcodeNameOffset));
						finishOp = true;
						goto cleanup;
					}
					else{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
					pUserData += UserDataConsumed;
				}
				else


				if (pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d4 && (pEvent->EventHeader.EventDescriptor.Opcode == 34))
				{
					if (wcscmp(L"Irp", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						)
					{
						USES_CONVERSION;
						Irp = *(DWORD*)pUserData;
						if (IrpToProcessID.find(Irp) != IrpToProcessID.end()){
							CPID = IrpToProcessID[Irp].processID;
							threadID = IrpToProcessID[Irp].threadID;
						}
						else{
							CPID = pEvent->EventHeader.ProcessId;
							threadID = pEvent->EventHeader.ThreadId;
						}
						if (CPID != ProcessIDOfRat){
							finishOp = TRUE;
							goto cleanup;
						}
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
					else
					if (i == pInfo->TopLevelPropertyCount - 1)
					{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\" ";
						EventType = (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->TaskNameOffset)) + (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->OpcodeNameOffset));
						finishOp = true;
						goto cleanup;
					}
					else{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
					pUserData += UserDataConsumed;
				}
				else


				if (pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d4 && (pEvent->EventHeader.EventDescriptor.Opcode == 35))
				{
					if (i == 0){
						CPID = pEvent->EventHeader.ProcessId;
						threadID = pEvent->EventHeader.ThreadId;
						if (CPID != ProcessIDOfRat){
							finishOp = TRUE; 
							goto cleanup;
						}
					}
					if (wcscmp(L"Irp", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						)
					{
						USES_CONVERSION;
						Irp = *(DWORD*)pUserData;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
					else
					if (i == pInfo->TopLevelPropertyCount - 1)
					{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\" ";
						EventType = (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->TaskNameOffset)) + (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->OpcodeNameOffset));
						finishOp = true;
						goto cleanup;
					}
					pUserData += UserDataConsumed;
				}
				else


				//if (pEvent->EventHeader.ProviderId.Data1 == 0xce1dbfb4 && (pEvent->EventHeader.EventDescriptor.Opcode == 66 || pEvent->EventHeader.EventDescriptor.Opcode == 68 || pEvent->EventHeader.EventDescriptor.Opcode == 69))
				//{
				//	if (i == pInfo->TopLevelPropertyCount - 1)
				//	{
				//		USES_CONVERSION;
				//		CPID = pEvent->EventHeader.ProcessId;
				//		threadID = pEvent->EventHeader.ThreadId;
				//		parm += "\"";
				//		parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
				//		parm += ": ";
				//		parm += to_string(*(DWORD*)pUserData);
				//		parm += "\" ";
				//		EventType = (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->TaskNameOffset)) + (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->OpcodeNameOffset));
				//		finishOp = true;
				//		goto cleanup;
				//	}
				//	else{
				//		USES_CONVERSION;
				//		parm += "\"";
				//		parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
				//		parm += ": ";
				//		parm += to_string(*(DWORD*)pUserData);
				//		parm += "\", ";
				//	}
				//	pUserData += UserDataConsumed;
				//}
				//else


				//if (pEvent->EventHeader.ProviderId.Data1 == 0xce1dbfb4 && (pEvent->EventHeader.EventDescriptor.Opcode == 52))
				//{
				//	if (SystemFlag){
				//		USES_CONVERSION;
				//		SystemFlag = false;
				//		CPID = nextsystemcallexit.processID;
				//		threadID = nextsystemcallexit.threadID;
				//		parm = systemcallexit;
				//		parm += ", \"";
				//		parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
				//		parm += ": ";
				//		parm += string(W2A(pFormattedData));
				//		parm += "\" ";
				//		EventType = (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->TaskNameOffset)) + "SystemCall";
				//	}
				//	finishOp = true;
				//	goto cleanup;
				//	pUserData += UserDataConsumed;
				//}
				//else


				if (pEvent->EventHeader.ProviderId.Data1 == 0xce1dbfb4 && (pEvent->EventHeader.EventDescriptor.Opcode == 67))
				{
					if (i == 0){
						threadID = curPID[pEvent->BufferContext.ProcessorNumber];
						CPID = ThreadIDtoPID_map[threadID];
						if (CPID != ProcessIDOfRat){
							finishOp = TRUE;
							goto cleanup;
						}
					}
					if (i == pInfo->TopLevelPropertyCount - 1)
					{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\" ";
						EventType = (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->TaskNameOffset)) + (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->OpcodeNameOffset));
						finishOp = true;
						goto cleanup;
					}
					else{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
					pUserData += UserDataConsumed;
				}
				else


				if (pEvent->EventHeader.ProviderId.Data1 == 0x2cb15d1d && (pEvent->EventHeader.EventDescriptor.Opcode == 10 || pEvent->EventHeader.EventDescriptor.Opcode == 2 || pEvent->EventHeader.EventDescriptor.Opcode == 3 || pEvent->EventHeader.EventDescriptor.Opcode == 4))
				{
					if (wcscmp(L"ProcessId", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						)
					{
						USES_CONVERSION;
						CPID = *(DWORD*)pUserData;
						if (CPID != ProcessIDOfRat){
							finishOp = TRUE;
							goto cleanup;
						}
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
					if (wcscmp(L"FileName", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						)
					{
						USES_CONVERSION;
						threadID = curPID[pEvent->BufferContext.ProcessorNumber];
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\" ";
						EventType = (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->TaskNameOffset)) + (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->OpcodeNameOffset));
						finishOp = true;
						goto cleanup;
					}
					else{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
					pUserData += UserDataConsumed;
				}
				else


				if (pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d1 && (pEvent->EventHeader.EventDescriptor.Opcode == 2 || pEvent->EventHeader.EventDescriptor.Opcode == 1 || pEvent->EventHeader.EventDescriptor.Opcode == 3 || pEvent->EventHeader.EventDescriptor.Opcode == 4))
				{
					if (wcscmp(L"ProcessId", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						)
					{
						USES_CONVERSION;
						CPID = *(DWORD*)pUserData;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}else
					if (wcscmp(L"TThreadId", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						)
					{
						USES_CONVERSION;
						threadID = *(DWORD*)pUserData;
						if (pEvent->EventHeader.EventDescriptor.Opcode == 2 || pEvent->EventHeader.EventDescriptor.Opcode == 4){
							ThreadIDtoPID_map.erase(ThreadIDtoPID_map.find(threadID));
						}
						if (pEvent->EventHeader.EventDescriptor.Opcode == 1 || pEvent->EventHeader.EventDescriptor.Opcode == 3){
							ThreadIDtoPID_map[threadID] = CPID;
						}
						if (CPID != ProcessIDOfRat){
							finishOp = TRUE;
							goto cleanup;
						}
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}	else				
					if (i == pInfo->TopLevelPropertyCount - 1)
					{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\" ";
						EventType = (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->TaskNameOffset)) + (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->OpcodeNameOffset));
						finishOp = true;
						goto cleanup;
					}
					else{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
					pUserData += UserDataConsumed;
				}
				else


				if (pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d0 && (pEvent->EventHeader.EventDescriptor.Opcode == 2 || pEvent->EventHeader.EventDescriptor.Opcode == 1 || pEvent->EventHeader.EventDescriptor.Opcode == 3 || pEvent->EventHeader.EventDescriptor.Opcode == 4 || pEvent->EventHeader.EventDescriptor.Opcode == 39))
				{
					if (wcscmp(L"ProcessId", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						)
					{
						USES_CONVERSION;
						CPID = *(DWORD*)pUserData;
						if (CPID == ProcessIDOfRat&&pEvent->EventHeader.EventDescriptor.Opcode == 2){
							cout << "END." << endl;
							system("PAUSE");
							exit(0);
						}
						startPID = CPID;
						threadID = pEvent->EventHeader.ThreadId;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
					else
					if (wcscmp(L"ParentId", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						)
					{
						USES_CONVERSION;
						threadID = 0;
						int PID = PCharToDWORD(pFormattedData);
						if (PID == ProcessIDOfRat) {
							parm += "\"";
							parm += "KidPID";
							parm += ": ";
							parm += CPID;
							parm += "\", ";
							CPID = PID;
						}
						else{
							parm += "\"";
							parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
							parm += ": ";
							parm += string(W2A(pFormattedData));
							parm += "\", ";
							parm += "\"";
							parm += "ParentProcessName";
							parm += ": ";
							parm += ProcessName_map[PID];
							parm += "\", ";
						}
					}
					else
					if (i == 5)
					{
						USES_CONVERSION;
						if (pEvent->EventHeader.EventDescriptor.Opcode == 2 || pEvent->EventHeader.EventDescriptor.Opcode == 4){
							if (ProcessName_map.find(startPID) != ProcessName_map.end()) ProcessName_map.erase(ProcessName_map.find(startPID));
						}
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
						pUserData += 8;
						EventType = (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->TaskNameOffset)) + (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->OpcodeNameOffset));
						LPWSTR* chSID = new LPWSTR;
						pUserData += 16;
						int ret=ConvertSidToStringSid((PVOID)(pUserData), chSID);
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i+1].NameOffset));
						parm += ": ";
						if (ret) parm += string(W2A(*chSID)); else parm += to_string(ret);
						parm += "\", ";
						pUserData+=GetLengthSid((PVOID)(pUserData));
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i + 2].NameOffset));
						parm += ": ";
						string ss = string((char*)(pUserData));
						if (pEvent->EventHeader.EventDescriptor.Opcode == 1 || pEvent->EventHeader.EventDescriptor.Opcode == 3){
							ProcessName_map[startPID]=ss;
						}
						pUserData += (ss.size()+1);
						parm += ss;
						parm += "\", ";
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i + 3].NameOffset));
						parm += ": ";
						parm += string(W2A((wchar_t*)(pUserData)));
						parm += "\" ";
						finishOp = true;
						goto cleanup;
					}				
					else{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
					pUserData += UserDataConsumed;
				}
				else


				if (pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d0 && (pEvent->EventHeader.EventDescriptor.Opcode == 33 || pEvent->EventHeader.EventDescriptor.Opcode == 32))
				{
					if (wcscmp(L"ProcessId", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						)
					{
						USES_CONVERSION;
						CPID = *(DWORD*)pUserData;
						threadID = pEvent->EventHeader.ThreadId;
						if (CPID != ProcessIDOfRat){
							finishOp = TRUE;
							goto cleanup;
						}
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
					else
					if (i == pInfo->TopLevelPropertyCount - 1)
					{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\" ";
						EventType = (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->TaskNameOffset)) + (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->OpcodeNameOffset));
						finishOp = true;
						goto cleanup;
					}

					else{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
					pUserData += UserDataConsumed;
				}
				else


				if (pEvent->EventHeader.EventDescriptor.Opcode == 46 && pEvent->EventHeader.ProviderId.Data1 == 0xce1dbfb4){
					if (wcscmp(L"ThreadId", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						)
					{
						USES_CONVERSION;
						threadID = *(DWORD*)pUserData;
						CPID = ThreadIDtoPID_map[threadID];
						if (CPID != ProcessIDOfRat){
							finishOp = TRUE;
							goto cleanup;
						}
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
					else
					if (i == pInfo->TopLevelPropertyCount - 1)
					{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\" ";
						EventType = (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->TaskNameOffset)) + (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->OpcodeNameOffset));
						finishOp = true;
						goto cleanup;
					}
					else{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
					pUserData += UserDataConsumed;
				}else


				if ((pEvent->EventHeader.EventDescriptor.Opcode == 32) && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d3){
					if (wcscmp(L"TThreadId", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						)
					{
						USES_CONVERSION;
						threadID = *(DWORD*)pUserData;
						CPID = ThreadIDtoPID_map[threadID];
						if (CPID != ProcessIDOfRat){
							finishOp = TRUE;
							goto cleanup;
						}
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}else
					if (wcscmp(L"FileObject", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						)
					{
						USES_CONVERSION;
						fileObject = *(DWORD*)pUserData;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
					else
					if (i == pInfo->TopLevelPropertyCount - 1)
					{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\"";
						if (fileNameMap.find(fileObject) != fileNameMap.end()) parm += (", " + fileNameMap[fileObject]); else parm += ", FileName: \"\"";
						EventType = (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->TaskNameOffset)) + (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->OpcodeNameOffset));
						finishOp = true;
						goto cleanup;
					}
					else{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
					pUserData += UserDataConsumed;
				}else


				if ((pEvent->EventHeader.EventDescriptor.Opcode == 105) && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d3){
					if (i == 0){
						threadID = pEvent->EventHeader.ThreadId;
						CPID = pEvent->EventHeader.ProcessId;
						if (CPID != ProcessIDOfRat){
							finishOp = TRUE;
							goto cleanup;
						}
					}
					if (wcscmp(L"FileObject", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						)
					{
						USES_CONVERSION;
						fileObject = *(DWORD*)pUserData;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
					else
					if (i == pInfo->TopLevelPropertyCount - 1)
					{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\"";
						if (fileNameMap.find(fileObject) != fileNameMap.end()) parm += (", " + fileNameMap[fileObject]); else parm += ", FileName: \"\"";
						EventType = (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->TaskNameOffset)) + (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->OpcodeNameOffset));
						finishOp = true;
						goto cleanup;
					}
					else{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
					pUserData += UserDataConsumed;
				}
				else


				if ((pEvent->EventHeader.EventDescriptor.Opcode == 98 || pEvent->EventHeader.EventDescriptor.Opcode == 99) && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d3){
					if (wcscmp(L"ProcessId", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
						)
					{
						USES_CONVERSION;
						CPID = *(DWORD*)pUserData;
						if (CPID != ProcessIDOfRat){
							finishOp = TRUE;
							goto cleanup;
						}
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
					else
					if (i == pInfo->TopLevelPropertyCount - 1)
					{
						USES_CONVERSION;
						threadID = pEvent->EventHeader.ThreadId;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\" ";
						EventType = (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->TaskNameOffset)) + (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->OpcodeNameOffset));
						finishOp = true;
						goto cleanup;
					}
					else{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
					pUserData += UserDataConsumed;
				}
				else


				if ((pEvent->EventHeader.EventDescriptor.Opcode == 10 || pEvent->EventHeader.EventDescriptor.Opcode == 11 || pEvent->EventHeader.EventDescriptor.Opcode == 12 || pEvent->EventHeader.EventDescriptor.Opcode == 13 || pEvent->EventHeader.EventDescriptor.Opcode == 14 || pEvent->EventHeader.EventDescriptor.Opcode == 15) && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d3){
					if (i == 0){
						CPID = pEvent->EventHeader.ProcessId;
						threadID = pEvent->EventHeader.ThreadId;
						if (CPID != ProcessIDOfRat){
							finishOp = TRUE;
							goto cleanup;
						}
					}
					if (i == pInfo->TopLevelPropertyCount - 1)
					{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\" ";
						EventType = (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->TaskNameOffset)) + (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->OpcodeNameOffset));
						finishOp = true;
						goto cleanup;
					}
					else{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
					pUserData += UserDataConsumed;
				}
				else


				if ((pEvent->EventHeader.EventDescriptor.Opcode == 32) && pEvent->EventHeader.ProviderId.Data1 == 0xd837ca92){
					if (i == 0){
						CPID = pEvent->EventHeader.ProcessId;
						threadID = pEvent->EventHeader.ThreadId;
						if (CPID != ProcessIDOfRat){
							finishOp = TRUE;
							goto cleanup;
						}
					}
					if (i == pInfo->TopLevelPropertyCount - 1)
					{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\" ";
						EventType = (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->TaskNameOffset)) + (string)W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->OpcodeNameOffset));
						finishOp = true;
						goto cleanup;
					}
					else{
						USES_CONVERSION;
						parm += "\"";
						parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
						parm += ": ";
						parm += string(W2A(pFormattedData));
						parm += "\", ";
					}
					pUserData += UserDataConsumed;
				}
				else


				switch (OPcode)
				{

				case 1:{
						   if (wcscmp(L"ProcessId", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
							   && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d1)
						   {
							   CPID = *(DWORD*)pUserData;
						   }
						   if (wcscmp(L"TThreadId", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
							   && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d1)
						   {
							   EventType = "ThreadStart";
							   threadID = PCharToDWORD(pFormattedData);
							   ThreadIDtoPID_map[threadID] = CPID;
							   finishOp = TRUE;
							   parm = "";
							   goto cleanup;
						   }
						   pUserData += UserDataConsumed;
						   break;
				}

				case 3:{
						   if (wcscmp(L"ProcessId", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
							   )
						   {
							   CPID = PCharToDWORD(pFormattedData);
						   }
						   if (wcscmp(L"TThreadId", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
							   )
						   {
							   EventType = "ThreadDCStart";
							   threadID = PCharToDWORD(pFormattedData);
							   ThreadIDtoPID_map[threadID] = CPID;
							   finishOp = TRUE;
							   parm = "";
							   goto cleanup;
						   }
						   pUserData += UserDataConsumed;
						   break;
				}
				//case 14:{
				//			if (wcscmp(L"KeyHandle", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
				//				)
				//			{
				//				keyhandle = PCharToDWORD(pFormattedData);
				//			}
				//			if (wcscmp(L"KeyName", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
				//				)
				//			{
				//				EventType = "RegistrySetValue";
				//				USES_CONVERSION;
				//				parm = KeyNameMap[keyhandle];
				//				CPID = pEvent->EventHeader.ProcessId;
				//				finishOp = TRUE;
				//				goto cleanup;
				//			}
				//			pUserData += UserDataConsumed;
				//			break;
				//}

				case 2:{
						   if (wcscmp(L"ProcessId", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
							   && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d0)
						   {
							   CPID = PCharToDWORD(pFormattedData);
							   if (CPID == ProcessIDOfRat){
								   for (unordered_map<int, ofstream*>::iterator ix = OutFile_Map.begin(); ix != OutFile_Map.end(); ix++){
									   delete ix->second;
									   ix->second = 0;
									   EndFlag = true;
									   exit(0);
								   }
							   }
						   }
						   else
						   if (wcscmp(L"ProcessId", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
							   && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d1)
						   {
							   CPID = PCharToDWORD(pFormattedData);
						   }
						   if (wcscmp(L"TThreadId", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
							   && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d1)
						   {
							   threadID = PCharToDWORD(pFormattedData);
							   if (CPID == ProcessIDOfRat){
								   //delete OutFile_Map.find(threadID)->second;
								   //OutFile_Map.find(threadID)->second = 0;
							   }
							   goto cleanup;
						   }
						   pUserData += UserDataConsumed;
						   break;

				}

				case 33:
				{
						   if (wcscmp(L"MessageID", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0){
							   DWORD messageID = *(DWORD*)(pUserData);
							   CPID = pEvent->EventHeader.ProcessId;
							   messageID_Map[messageID] = pEvent->EventHeader.ProcessId;
							   messageID2ThreadID[messageID]=pEvent->EventHeader.ThreadId;
							   CPID = -1;
							   finishOp = TRUE;
							   goto cleanup;
						   }
						   break;

				}

				case 34:
				{
						   if (wcscmp(L"MessageID", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0){
							   USES_CONVERSION;
							   parm += "\"";
							   parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
							   parm += ": ";
							   parm += to_string(*(DWORD*)pUserData);
							   parm += "\", ";
							   CPID = pEvent->EventHeader.ProcessId;
							   DWORD messageID = *(DWORD*)(pUserData);
							   if (messageID_Map.find(messageID) != messageID_Map.end() && CPID == ProcessIDOfRat){
								   parm = "\"REC:" + to_string(messageID_Map[messageID]) + "\", " + "\"ProcessName:" + ProcessName_map[messageID_Map[messageID]] + '\"';
								   EventType = "ALPC_REC";
								   messageID_Map.erase(messageID_Map.find(messageID));
								   finishOp = TRUE;
								   goto cleanup;
							   } else
							   if (messageID_Map[messageID] == ProcessIDOfRat){
								   threadID = messageID2ThreadID[messageID];
								   parm = "\"SEN:" + to_string(CPID) + "\", " + "\"ProcessName:" + ProcessName_map[CPID] + '\"';
								   EventType = "ALPC_SEN";
								   finishOp = TRUE;
								   goto cleanup;
							   }
						   }
						   break;

				}

				case 12:
				{
						   if (wcscmp(L"PID", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0){
							   CPID = *(DWORD*)pUserData;
						   }
						   else
						   if (wcscmp(L"daddr", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0){
							   USES_CONVERSION;
							   parm = parm + "\"daddr:" + string(W2A(pFormattedData)) + "\", ";
						   }
						   else
						   if (wcscmp(L"saddr", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0){
							   USES_CONVERSION;
							   parm = parm + "\"saddr:" + string(W2A(pFormattedData)) + "\" ";
							   finishOp = TRUE;
							   EventType = "TCP_Connect";
							   goto cleanup;
						   }
						   else
						   if (wcscmp(L"size", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0){
							   USES_CONVERSION;
							   parm = parm + "\"size:" + string(W2A(pFormattedData)) + "\", ";
						   }
						   //if (wcscmp(L"KeyHandle", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
							  // )
						   //{
							  // keyhandle = PCharToDWORD(pFormattedData);
						   //}
						   //if (wcscmp(L"KeyName", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
							  // )
						   //{
							  // parm = KeyNameMap[keyhandle];
							  // CPID = pEvent->EventHeader.ProcessId;
							  // finishOp = TRUE;
							  // EventType = "RegistryDeleteKey";
							  // goto cleanup;
						   //}
						   pUserData += UserDataConsumed;
						   break;
				}


				case 13:{
							if (wcscmp(L"PID", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0){
								CPID = *(DWORD*)pUserData;
							}
							else
							if (wcscmp(L"daddr", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0){
								USES_CONVERSION;
								parm = parm + "\"daddr:" + string(W2A(pFormattedData)) + "\", ";
							}
							else
							if (wcscmp(L"saddr", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0){
								USES_CONVERSION;
								parm = parm + "\"saddr:" + string(W2A(pFormattedData)) + "\" ";
								finishOp = TRUE;
								EventType = "TCP_Disconnect";
								goto cleanup;
							}
							else
							if (wcscmp(L"size", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0){
								USES_CONVERSION;
								parm = parm + "\"size:" + string(W2A(pFormattedData)) + "\", ";
							}
							//if (wcscmp(L"KeyHandle", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
							//	)
							//{
							//	keyhandle = PCharToDWORD(pFormattedData);
							//}
							//if (wcscmp(L"KeyName", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
							//	)
							//{
							//	USES_CONVERSION;
							//	parm = KeyNameMap[keyhandle];
							//	CPID = pEvent->EventHeader.ProcessId;
							//	finishOp = TRUE;
							//	EventType = "RegistryQueryKey";
							//	goto cleanup;
							//}
							pUserData += UserDataConsumed;
							break;
				}
				case 15:{
							if (wcscmp(L"PID", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0){
								CPID = *(DWORD*)pUserData;
							}
							else
							if (wcscmp(L"daddr", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0){
								USES_CONVERSION;
								parm = parm + "\"daddr:" + string(W2A(pFormattedData)) + "\", ";
							}
							else
							if (wcscmp(L"saddr", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0){
								USES_CONVERSION;
								parm = parm + "\"saddr:" + string(W2A(pFormattedData)) + "\" ";
								finishOp = TRUE;
								EventType = "TCP_Accept";
								goto cleanup;
							}
							else
							if (wcscmp(L"size", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0){
								USES_CONVERSION;
								parm = parm + "\"size:" + string(W2A(pFormattedData)) + "\", ";
							}
							//if (wcscmp(L"KeyHandle", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
							//	)
							//{
							//	keyhandle = PCharToDWORD(pFormattedData);
							//}
							//if (wcscmp(L"KeyName", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
							//	)
							//{
							//	parm = KeyNameMap[keyhandle];
							//	CPID = pEvent->EventHeader.ProcessId;
							//	finishOp = TRUE;
							//	EventType = "RegistryDeleteValue";
							//	goto cleanup;
							//}
							pUserData += UserDataConsumed;
							break;
				}
				case 36:
				{
						   if (true														//CSwitch
							   && wcscmp(L"NewThreadId", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0 //NewTreadID
							   && wcscmp(L"0x0", pFormattedData) != 0																// new threadID is not 0
							   )
						   {

							   threadID = PCharToDWORD(pFormattedData);
							   int processorID = pEvent->BufferContext.ProcessorNumber;
							   curPID[processorID] = threadID;
							   CPID = ThreadIDtoPID_map[threadID];
							   threadID_list[pEvent->BufferContext.ProcessorNumber] = threadID;
							   finishOp = TRUE;
						   }
						   goto cleanup;
				}

				case 11:
				{
						   if (wcscmp(L"PID", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0){
							   CPID = *(DWORD*)pUserData;
						   }
						   else
						   if (wcscmp(L"daddr", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0){
							   USES_CONVERSION;
							   parm = parm + "\"daddr:" + string(W2A(pFormattedData)) + "\", ";
						   }
						   else
						   if (wcscmp(L"saddr", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0){
							   USES_CONVERSION;
							   parm = parm + "\"saddr:" + string(W2A(pFormattedData)) + "\" ";
							   finishOp = TRUE;
							   EventType = "TCP_Rec";
							   goto cleanup;
						   }
						   else
						   if (wcscmp(L"size", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0){
							   USES_CONVERSION;
							   parm = parm + "\"size:" + string(W2A(pFormattedData)) + "\", ";
						   }
						   //if (wcscmp(L"KeyHandle", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
							  // )
						   //{
							  // keyhandle = PCharToDWORD(pFormattedData);
						   //}
						   //if (wcscmp(L"KeyName", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
							  // )
						   //{
							  // USES_CONVERSION;
							  // parm = parm + " \"KeyName:" + string(W2A(pFormattedData)) + '\"';
							  // KeyNameMap[keyhandle] = parm;
							  // CPID = pEvent->EventHeader.ProcessId;
							  // finishOp = TRUE;
							  // EventType = "RegistryOpenKey";
							  // goto cleanup;
						   //}
						   pUserData += UserDataConsumed;
						   break;
				}

				//case 67:{
				//			if (wcscmp(L"TTID", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
				//				)
				//			{
				//				threadID = PCharToDWORD(pFormattedData);
				//				if (ThreadIDtoPID_map.find(threadID) != ThreadIDtoPID_map.end())CPID = ThreadIDtoPID_map[threadID]; else CPID=GetPIDbyThreadID(threadID);
				//			}
				//			else
				//			if (wcscmp(L"FileKey", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
				//				)
				//			{
				//				filekey = *(DWORD*)pUserData;
				//				USES_CONVERSION;
				//				parm += "\"";
				//				parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
				//				parm += ": ";
				//				parm += to_string(*(DWORD*)pUserData);
				//				parm += "\", ";
				//			}else
				//			if (wcscmp(L"FileObject", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
				//				)
				//			{
				//				fileObject = *(DWORD*)pUserData;
				//				USES_CONVERSION;
				//				parm += "\"";
				//				parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
				//				parm += ": ";
				//				parm += to_string(*(DWORD*)pUserData);
				//				parm += "\", ";
				//				EventType = "FileIoRead";
				//				if (fileNameMap.find(filekey) != fileNameMap.end()) parm += fileNameMap[filekey]; else{
				//					if (fileNameMap.find(fileObject) != fileNameMap.end())parm += fileNameMap[fileObject];
				//				}
				//				finishOp = TRUE;
				//				goto cleanup;
				//			}
				//			pUserData += UserDataConsumed;
				//			break;
				//}

				//case 68:{
				//			if (wcscmp(L"TTID", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
				//				)
				//			{
				//				threadID = PCharToDWORD(pFormattedData);
				//				if (ThreadIDtoPID_map.find(threadID) != ThreadIDtoPID_map.end())CPID = ThreadIDtoPID_map[threadID]; else CPID = GetPIDbyThreadID(threadID);
				//			}
				//			else
				//			if (wcscmp(L"FileKey", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
				//				)
				//			{
				//				filekey = *(DWORD*)pUserData;
				//				USES_CONVERSION;
				//				parm += "\"";
				//				parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
				//				parm += ": ";
				//				parm += to_string(*(DWORD*)pUserData);
				//				parm += "\", ";
				//			}
				//			else
				//			if (wcscmp(L"FileObject", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
				//				)
				//			{
				//				fileObject = *(DWORD*)pUserData;
				//				USES_CONVERSION;
				//				parm += "\"";
				//				parm += W2A((PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset));
				//				parm += ": ";
				//				parm += to_string(*(DWORD*)pUserData);
				//				parm += "\", ";
				//				EventType = "FileIoWrite";
				//				if (fileNameMap.find(filekey) != fileNameMap.end()) parm += fileNameMap[filekey]; else{
				//					if (fileNameMap.find(fileObject) != fileNameMap.end())parm += fileNameMap[fileObject];
				//				}
				//				finishOp = TRUE;
				//				goto cleanup;
				//			}
				//			pUserData += UserDataConsumed;
				//			break;
				//}

				//case 23:{
				//			if (wcscmp(L"KeyName", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
				//				)
				//			{
				//				USES_CONVERSION;
				//				parm = "\"KeyName:" + string(W2A(pFormattedData)) + '\"';
				//				CPID = pEvent->EventHeader.ProcessId;
				//				finishOp = TRUE;
				//				EventType = "RegistryDeleteKeyEvent";
				//				goto cleanup;
				//			}
				//			pUserData += UserDataConsumed;
				//			break;
				//}

				//case 22:{
				//			if (wcscmp(L"KeyName", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
				//				)
				//			{
				//				USES_CONVERSION;
				//				parm = "\"KeyName:" + string(W2A(pFormattedData)) + '\"';
				//				CPID = pEvent->EventHeader.ProcessId;
				//				finishOp = TRUE;
				//				EventType = "RegistryCreateKeyEvent";
				//				goto cleanup;
				//			}
				//			pUserData += UserDataConsumed;
				//			break;
				//}

				//case 16:
				//{
				//		   if (wcscmp(L"KeyHandle", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
				//			   )
				//		   {
				//			   keyhandle = PCharToDWORD(pFormattedData);
				//		   }
				//		   if (wcscmp(L"KeyName", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
				//			   )
				//		   {
				//			   USES_CONVERSION;
				//			   parm = KeyNameMap[keyhandle];
				//			   CPID = pEvent->EventHeader.ProcessId;
				//			   finishOp = TRUE;
				//			   EventType = "RegistryQueryValue";
				//			   goto cleanup;
				//		   }
				//		   pUserData += UserDataConsumed;
				//		   break;
				//}

					//QueryDirectoryFile
				//case 72:
				//{
				//		   if (wcscmp(L"TTID", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
				//			   )
				//		   {
				//			   threadID = PCharToDWORD(pFormattedData);
				//			   CPID = GetPIDbyThreadID(threadID);
				//		   }
				//		   else
				//		   if (wcscmp(L"FileObject", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
				//			   )
				//		   {
				//			   fileObject = *(DWORD*)pUserData;
				//		   }
				//		   else
				//		   if (wcscmp(L"FileName", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
				//			   )
				//		   {
				//			   parm = fileNameMap[fileObject];
				//			   finishOp = TRUE;
				//			   EventType = "FileIoDirEnum";
				//			   goto cleanup;
				//		   }
				//		   pUserData += UserDataConsumed;
				//		   break;
				//}

				//case 17:{
				//			if (wcscmp(L"KeyHandle", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
				//				)
				//			{
				//				keyhandle = PCharToDWORD(pFormattedData);
				//			}
				//			if (wcscmp(L"KeyName", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
				//				)
				//			{
				//				USES_CONVERSION;
				//				parm = KeyNameMap[keyhandle];
				//				CPID = pEvent->EventHeader.ProcessId;
				//				finishOp = TRUE;
				//				EventType = "RegistryEnumerateKey";
				//				goto cleanup;
				//			}
				//			pUserData += UserDataConsumed;
				//			break;
				//}

				//case 18:{
				//			if (wcscmp(L"KeyHandle", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
				//				)
				//			{
				//				keyhandle = PCharToDWORD(pFormattedData);
				//			}
				//			if (wcscmp(L"KeyName", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
				//				)
				//			{
				//				USES_CONVERSION;
				//				parm = KeyNameMap[keyhandle];
				//				CPID = pEvent->EventHeader.ProcessId;
				//				finishOp = TRUE;
				//				EventType = "RegistryEnumerateValueKey";
				//				goto cleanup;
				//			}
				//			pUserData += UserDataConsumed;
				//			break;
				//}
					//CreateFile & FileName
				//case 32:
				//{
				//		   if (wcscmp(L"FileObject", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
				//			   )
				//		   {
				//			   fileObject = *(DWORD*)pUserData;
				//		   }
				//		   else
				//		   if (wcscmp(L"FileName", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
				//			   )
				//		   {
				//			   USES_CONVERSION;
				//			   CPID = pEvent->EventHeader.ProcessId;
				//			   parm = "\"FileName:" + string(W2A(pFormattedData)) + '\"';
				//			   fileNameMap[fileObject] = parm;
				//			   finishOp = TRUE;
				//			   EventType = "FileIoCreateFile";
				//			   goto cleanup;
				//		   }
				//		   pUserData += UserDataConsumed;
				//		   break;
				//}
				//case 64: // create file
				//{
				//			 if (wcscmp(L"TTID", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
				//				 )
				//			 {
				//				 threadID = PCharToDWORD(pFormattedData);
				//				 CPID = GetPIDbyThreadID(threadID);
				//			 }
				//			 else
				//			 if (wcscmp(L"FileObject", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
				//				 )
				//			 {
				//				 fileObject = *(DWORD*)pUserData;
				//			 }
				//			 else
				//			 if (wcscmp(L"OpenPath", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
				//				 )
				//			 {
				//				 USES_CONVERSION;
				//				 parm = "\"OpenPath:" + string(W2A(pFormattedData)) + '\"';
				//				 fileNameMap[fileObject] = parm;
				//				 finishOp = TRUE;
				//				 EventType = "FileIoCreateFile";
				//				 goto cleanup;
				//			 }
				//			 pUserData += UserDataConsumed;
				//			 break;
				//}

					//QueryAttributesFile
				case 74:
				{
						   if (wcscmp(L"TTID", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
							   )
						   {
							   threadID = PCharToDWORD(pFormattedData);
							   CPID = GetPIDbyThreadID(threadID);
						   }
						   else
						   if (wcscmp(L"FileObject", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
							   )
						   {
							   fileObject = *(DWORD*)pUserData;
						   }
						   else
						   if (wcscmp(L"FileName", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
							   )
						   {
							   parm = fileNameMap[fileObject];
							   finishOp = TRUE;
							   EventType = "FileIoQueryInfo";
							   goto cleanup;
						   }
						   pUserData += UserDataConsumed;
						   break;
				}

				case 10:                   //Load
				{
											   if (wcscmp(L"ProcessID", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
												   )
											   {
												   CPID = int(PCharToDWORD(pFormattedData));
											   }
											   else
											   if (wcscmp(L"FileName", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
												   )
											   {
												   USES_CONVERSION;
												   parm = "\"FileName:" + string(W2A(pFormattedData)) + '\"';
												   finishOp = TRUE;
												   EventType = "ImageLoad";
												   goto cleanup;
											   }
											   else
											   //if (wcscmp(L"KeyHandle", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
												  // )
											   //{
												  // keyhandle = PCharToDWORD(pFormattedData);
											   //}
											   //else
											   //if (wcscmp(L"KeyName", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0
												  // )
											   //{
												  // USES_CONVERSION;
												  // parm = "\"Keyname: " + string(W2A(pFormattedData)) + '\"';
												  // KeyNameMap[keyhandle] = parm;
												  // CPID = pEvent->EventHeader.ProcessId;
												  // finishOp = TRUE;
												  // EventType = "RegistryCreateKey";
												  // goto cleanup;
											   //}
											   if (wcscmp(L"PID", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0){
												   CPID = *(DWORD*)pUserData;
											   }
											   if (wcscmp(L"daddr", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0){
												   USES_CONVERSION;
												   parm = parm + "\"daddr:" + string(W2A(pFormattedData)) + "\", ";
											   }
											   if (wcscmp(L"saddr", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0){
												   USES_CONVERSION;
												   parm = parm + "\"saddr:" + string(W2A(pFormattedData)) + "\" ";
												   finishOp = TRUE;
												   EventType = "TCP_Send";
												   goto cleanup;
											   }
											   if (wcscmp(L"size", (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset)) == 0){
												   USES_CONVERSION;
												   parm = parm + "\"size:" + string(W2A(pFormattedData)) + "\", ";
											   }
											   pUserData += UserDataConsumed;
											   break;
				}

				default:
					finishOp = TRUE;
				}
			}

		}
	}

cleanup:
	if (CPID != 0 && finishOp)
	{
		if (!pidInWhitelist(CPID) && CPID == ProcessIDOfRat&&OPcode != 36 && (!(OPcode == 51 && parm == "")) || (OPcode == 34 && EventType != ""&& pEvent->EventHeader.ProviderId.Data1 == 1171836109))
		{
			if (parm.find("\\") != string::npos)
			{
				parm = changeSeparator(parm);
				//				cout << parm << endl;
			}
			ft.dwHighDateTime = pEvent->EventHeader.TimeStamp.HighPart;
			ft.dwLowDateTime = pEvent->EventHeader.TimeStamp.LowPart;

			FileTimeToSystemTime(&ft, &st);
			SystemTimeToTzSpecificLocalTime(NULL, &st, &stLocal);

			TimeStamp = pEvent->EventHeader.TimeStamp.QuadPart;
			//		wcout<<"Timestamp :"<<TimeStamp<<endl;
			Nanoseconds = (TimeStamp % 10000000) * 100;

			if (threadID == 0 && pEvent->EventHeader.ThreadId != -1) threadID = pEvent->EventHeader.ThreadId;
			string ProcessName = GetProcessName(CPID);
			stringstream ss;
			long long TimeStamp = pEvent->EventHeader.TimeStamp.QuadPart;
			ss << " { ";
			ss << " \"Time\": \"";
			ss << stLocal.wMonth;
			ss << "-";
			ss << stLocal.wDay;
			ss << "-";
			ss << stLocal.wYear;
			ss << " ";
			ss << stLocal.wHour;
			ss << ":";
			ss << stLocal.wMinute;
			ss << ":";
			ss << stLocal.wSecond;
			ss << ".";
			ss << Nanoseconds;
			ss << "\", \"EventType\": \"";
			ss << EventType;
			ss << "\",\"ThreadID\": \"";
			ss << threadID;
			ss << "\",\"";
			ss << "pid\" : \"";
			ss << ProcessIDOfRat;

			if (parm != "") ss << "\",\"parameter\" : "; else  ss << "\",\"parameter\" : \"\"";
			ss << parm;
			ss << " }";
			string messageBody = ss.str();
			MessageCount++;
			if (OutFile_Map.find(threadID) != OutFile_Map.end()) {
				*OutFile_Map[threadID] << messageBody << endl;
			}
			else{
				string FileName = ".\\DATA\\ThreadId" + to_string(threadID) + ".output";
				OutFile_Map[threadID] = new ofstream(FileName.c_str());
				*OutFile_Map[threadID] << messageBody << endl;
			}

			if (MessageCount % 10000 == 0)
			{
				wcout << L"published " << MessageCount << L" messages!" << endl;
			}
		}

	}
	if (i==pInfo->TopLevelPropertyCount-1||finishOp){
		CPID = 0;
		threadID = 0;
		filekey = 0;
		fileObject = 0;
		Irp = 0;
		strName = "";
		parm = "";
		EventType = "";
	}
	if (pFormattedData){
		free(pFormattedData);
		pFormattedData = NULL;
	}

	if (pMapInfo)
	{
		free(pMapInfo);
		pMapInfo = NULL;
	}

	return pUserData;
}


// Get the length of the property data. For MOF-based events, the size is inferred from the data type
// of the property. For manifest-based events, the property can specify the size of the property value
// using the length attribute. The length attribue can specify the size directly or specify the name 
// of another property in the event data that contains the size. If the property does not include the 
// length attribute, the size is inferred from the data type. The length will be zero for variable
// length, null-terminated strings and structures.


DWORD GetPropertyLength(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT PropertyLength,DWORD puserdata)
{
	DWORD status = ERROR_SUCCESS;
	PROPERTY_DATA_DESCRIPTOR DataDescriptor;
	DWORD PropertySize = 0;

	// If the property is a binary blob and is defined in a manifest, the property can 
	// specify the blob's size or it can point to another property that defines the 
	// blob's size. The PropertyParamLength flag tells you where the blob's size is defined.

	if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyParamLength) == PropertyParamLength)
	{
		DWORD Length = 0;  // Expects the length to be defined by a UINT16 or UINT32
		DWORD j = pInfo->EventPropertyInfoArray[i].lengthPropertyIndex;
		ZeroMemory(&DataDescriptor, sizeof(PROPERTY_DATA_DESCRIPTOR));
		DataDescriptor.PropertyName = (ULONGLONG)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[j].NameOffset);
		DataDescriptor.ArrayIndex = ULONG_MAX;
		status = TdhGetPropertySize(pEvent, 0, NULL, 1, &DataDescriptor, &PropertySize);
		status = TdhGetProperty(pEvent, 0, NULL, 1, &DataDescriptor, PropertySize, (PBYTE)&Length);
		*PropertyLength = (USHORT)Length;
	}
	else
	{
		if (pInfo->EventPropertyInfoArray[i].length > 0)
		{
			*PropertyLength = pInfo->EventPropertyInfoArray[i].length;
		}
		else
		{
			// If the property is a binary blob and is defined in a MOF class, the extension
			// qualifier is used to determine the size of the blob. However, if the extension 
			// is IPAddrV6, you must set the PropertyLength variable yourself because the 
			// EVENT_PROPERTY_INFO.length field will be zero.

			if (TDH_INTYPE_BINARY == pInfo->EventPropertyInfoArray[i].nonStructType.InType &&
				TDH_OUTTYPE_IPV6 == pInfo->EventPropertyInfoArray[i].nonStructType.OutType)
			{
				*PropertyLength = (USHORT)sizeof(IN6_ADDR);
			}
			else if (TDH_INTYPE_UNICODESTRING == pInfo->EventPropertyInfoArray[i].nonStructType.InType ||
				TDH_INTYPE_ANSISTRING == pInfo->EventPropertyInfoArray[i].nonStructType.InType ||
				(pInfo->EventPropertyInfoArray[i].Flags & PropertyStruct) == PropertyStruct)
			{
				*PropertyLength = pInfo->EventPropertyInfoArray[i].length;
			}
			else if (pInfo->EventPropertyInfoArray[i].nonStructType.InType==0){
				int forepuserdata = puserdata;
				while (*(short*)puserdata!=0){
					puserdata += 2;
				}
				*PropertyLength = (puserdata-forepuserdata+2);
			}else
			{
				wprintf(L"Unexpected length of 0 for intype %d and outtype %d\n",
					pInfo->EventPropertyInfoArray[i].nonStructType.InType,
					pInfo->EventPropertyInfoArray[i].nonStructType.OutType);

				status = ERROR_EVT_INVALID_EVENT_DATA;
				goto cleanup;
			}
		}
	}

cleanup:

	return status;
}


// Get the size of the array. For MOF-based events, the size is specified in the declaration or using 
// the MAX qualifier. For manifest-based events, the property can specify the size of the array
// using the count attribute. The count attribue can specify the size directly or specify the name 
// of another property in the event data that contains the size.


DWORD GetArraySize(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT ArraySize)
{
	DWORD status = ERROR_SUCCESS;
	PROPERTY_DATA_DESCRIPTOR DataDescriptor;
	DWORD PropertySize = 0;

	if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyParamCount) == PropertyParamCount)
	{
		DWORD Count = 0;  // Expects the count to be defined by a UINT16 or UINT32
		DWORD j = pInfo->EventPropertyInfoArray[i].countPropertyIndex;
		ZeroMemory(&DataDescriptor, sizeof(PROPERTY_DATA_DESCRIPTOR));
		DataDescriptor.PropertyName = (ULONGLONG)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[j].NameOffset);
		DataDescriptor.ArrayIndex = ULONG_MAX;
		status = TdhGetPropertySize(pEvent, 0, NULL, 1, &DataDescriptor, &PropertySize);
		status = TdhGetProperty(pEvent, 0, NULL, 1, &DataDescriptor, PropertySize, (PBYTE)&Count);
		*ArraySize = (USHORT)Count;
	}
	else
	{
		*ArraySize = pInfo->EventPropertyInfoArray[i].count;
	}

	return status;
}


// Both MOF-based events and manifest-based events can specify name/value maps. The
// map values can be integer values or bit values. If the property specifies a value
// map, get the map.


DWORD GetMapInfo(PEVENT_RECORD pEvent, LPWSTR pMapName, DWORD DecodingSource, PEVENT_MAP_INFO & pMapInfo)
{
	DWORD status = ERROR_SUCCESS;
	DWORD MapSize = 0;

	// Retrieve the required buffer size for the map info.

	status = TdhGetEventMapInformation(pEvent, pMapName, pMapInfo, &MapSize);

	if (ERROR_INSUFFICIENT_BUFFER == status)
	{
		pMapInfo = (PEVENT_MAP_INFO)malloc(MapSize);
		if (pMapInfo == NULL)
		{
			wprintf(L"Failed to allocate memory for map info (size=%lu).\n", MapSize);
			status = ERROR_OUTOFMEMORY;
			goto cleanup;
		}

		// Retrieve the map info.

		status = TdhGetEventMapInformation(pEvent, pMapName, pMapInfo, &MapSize);
	}

	if (ERROR_SUCCESS == status)
	{
		if (DecodingSourceXMLFile == DecodingSource)
		{
			RemoveTrailingSpace(pMapInfo);
		}
	}
	else
	{
		if (ERROR_NOT_FOUND == status)
		{
			status = ERROR_SUCCESS; // This case is okay.
		}
		else
		{
			wprintf(L"TdhGetEventMapInformation failed with 0x%x.\n", status);
		}
	}

cleanup:

	return status;
}


// The mapped string values defined in a manifest will contain a trailing space
// in the EVENT_MAP_ENTRY structure. Replace the trailing space with a null-
// terminating character, so that the bit mapped strings are correctly formatted.


void RemoveTrailingSpace(PEVENT_MAP_INFO pMapInfo)
{
	DWORD ByteLength = 0;

	for (DWORD i = 0; i < pMapInfo->EntryCount; i++)
	{
		ByteLength = (wcslen((LPWSTR)((PBYTE)pMapInfo + pMapInfo->MapEntryArray[i].OutputOffset)) - 1) * 2;
		*((LPWSTR)((PBYTE)pMapInfo + (pMapInfo->MapEntryArray[i].OutputOffset + ByteLength))) = L'\0';
	}
}


// Get the metadata for the event.


DWORD GetEventInformation(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO & pInfo)
{
	DWORD status = ERROR_SUCCESS;
	DWORD BufferSize = 0;

	// Retrieve the required buffer size for the event metadata.

	status = TdhGetEventInformation(pEvent, 0, NULL, pInfo, &BufferSize);

	if (ERROR_INSUFFICIENT_BUFFER == status)
	{
		pInfo = (TRACE_EVENT_INFO*)malloc(BufferSize);
		if (pInfo == NULL)
		{
			wprintf(L"Failed to allocate memory for event info (size=%lu).\n", BufferSize);
			status = ERROR_OUTOFMEMORY;
			goto cleanup;
		}

		// Retrieve the event metadata.

		status = TdhGetEventInformation(pEvent, 0, NULL, pInfo, &BufferSize);
	}

	if (ERROR_SUCCESS != status)
	{
		wprintf(L"TdhGetEventInformation failed with 0x%x.\n", status);
	}

cleanup:

	return status;
}



//tranverse the LPWSTR format data to DWORD
DWORD PCharToDWORD(LPWSTR pFormattedData)
{
	wchar_t* WStr = (wchar_t *)pFormattedData;
	size_t len = wcslen(WStr) + 1;
	size_t converted = 0;
	char *CStr;
	CStr = (char*)malloc(len*sizeof(char));
	wcstombs_s(&converted, CStr, len, WStr, _TRUNCATE);

	std::stringstream ss;
	ss << CStr + 2;
	DWORD dd;
	ss >> hex >> dd; // !!!dd is BINARY.
	free(CStr);
	//	wcout << pFormattedData << endl;
	//	cout << "dd = " << hex << dd << endl;;
	return dd;
}


DWORD GetPIDbyThreadID(DWORD threadID)
{

	HANDLE thread = OpenThread(THREAD_QUERY_INFORMATION, false, threadID);

	return GetProcessIdOfThread(thread);
}


string GetPathbyPID(DWORD pid)
{
	LPTSTR lpFilename;

	HANDLE process = OpenProcess(THREAD_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);


	return "";
}
LPWSTR addressTosyscall(DWORD address)
{
	address &= 0xFFFFFFF;
	if (g.addressToName.find(address) == g.addressToName.end())
		return NULL;
	else
		return LPWSTR(g.addressToName[address]);
}


DWORD string16ToDword(string s)
{
	DWORD address = 0;
	DWORD index = 1;
	for (int i = s.length() - 1; i >= 0; i--)
	{
		if (s[i] >= 'A' && s[i] <= 'F')
		{
			address += ((s[i] - 'A') + 10)*index;
		}
		else
		{
			address += (s[i] - '0')*index;
		}
		index *= 16;

	}
	return address;
}


BOOL pidInWhitelist(DWORD pid){
	string a;

	set<DWORD>::iterator i = whiteListPID.find(pid);
	if (i != whiteListPID.end())
		return true;
	else
		return false;
}


string changeSeparator(string ss){

	for (size_t i = 0; i<ss.size(); i++) {
		if (ss[i] == '\\') {
			ss.insert(i, string("\\"));
			i++;
			//			i += 2;
		}
	}
	return ss;
}


string GetProcessName(int PID){
	HANDLE   hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32   procentry;
	procentry.dwSize = sizeof(PROCESSENTRY32);
	BOOL   bFlag = Process32First(hSnapShot, &procentry);
	while (bFlag)
	{
		if (procentry.th32ProcessID == PID){
			USES_CONVERSION;
			return (string)W2A(procentry.szExeFile);
		}//找到 
		bFlag = Process32Next(hSnapShot, &procentry);
	}
	return "Null";
}


int GetProcessID(string ProcessNameOfRat){
	HANDLE   hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32   procentry;
	procentry.dwSize = sizeof(PROCESSENTRY32);
	BOOL   bFlag = Process32First(hSnapShot, &procentry);
	while (bFlag)
	{
		USES_CONVERSION;
		if (stricmp(W2A(procentry.szExeFile), ProcessNameOfRat.c_str()) == 0){
			return procentry.th32ProcessID;
		}//找到 
		bFlag = Process32Next(hSnapShot, &procentry);
	}
	return 0;
}


VOID getallprocess()
{
	HANDLE   hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32   procentry;
	procentry.dwSize = sizeof(PROCESSENTRY32);
	BOOL   bFlag = Process32First(hSnapShot, &procentry);
	while (bFlag)
	{
		USES_CONVERSION;
		ProcessName_map[procentry.th32ProcessID] = (string)W2A(procentry.szExeFile);
		bFlag = Process32Next(hSnapShot, &procentry);
	}
}


VOID getallthread()
{

	HANDLE   hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	THREADENTRY32   thrcentry;
	thrcentry.dwSize = sizeof(THREADENTRY32);
	BOOL   bFlag = Thread32First(hSnapShot, &thrcentry);
	while (bFlag)
	{
		USES_CONVERSION;
		ThreadIDtoPID_map[thrcentry.th32ThreadID] = thrcentry.th32OwnerProcessID;
		bFlag = Thread32Next(hSnapShot, &thrcentry);
	}
}