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
#include <tlhelp32.h>
#include <stdlib.h>
#include <sddl.h>
#include <thread>
#include <memory>
#include <unordered_map>

#include <activemq/util/Config.h>
#include <decaf/lang/System.h>
#include <decaf/lang/Runnable.h>
#include <decaf/lang/Integer.h>
#include <activemq/core/ActiveMQConnectionFactory.h>
#include <activemq/library/ActiveMQCPP.h>
#include <cms/Connection.h>
#include <cms/Session.h>
#include <cms/Destination.h>
#include <cms/MessageProducer.h>
#include <cms/BytesMessage.h>
#include <cms/CMSException.h>

#include "getAddress.h"
#include "syscallParaList.h"
#include "consumer.h"
#include "messageQueue.h"


#pragma comment(lib, "tdh.lib")
#pragma warning(disable:4996)


using namespace cms;
using namespace activemq;
using namespace activemq::core;
using namespace decaf;
using namespace decaf::lang;

using namespace std;


ULONG g_TimerResolution = 0;
BOOL g_bUserMode = FALSE;
TRACEHANDLE g_hTrace = 0;
BOOL finishOP;
SOCKET sockClient;

//global values
wofstream outFile;
DWORD  MessageCount;
DWORD curPID[4] = { 0L };
BYTE data[MaxSendNum * 6 + 1];
getAddress g;
string path = "";
DWORD EventType;
wchar_t* parm;
set<DWORD> whiteListPID = { 0, 4 };
set<wstring> whiteListPName = {
	L"conhost.exe",
	L"winlogon.exe",
	L"csrss.exe",
	L"explorer.exe",
	L"smss.exe",
	L"wininit.exe",
	L"services.exe",
	L"lsass.exe",
	L"lsm.exe",
	L"svchost.exe",
	L"vmacthlp.exe",
	L"dllhost.exe",
	L"spoolsv.exe",
	L"sqlwriter.exe",
	L"VGAuthService.exe",
	L"vmtoolsd.exe",
	L"SearchIndexer.exe",
	L"WmiPrvSE.exe",
	L"sppsvc.exe",
	L"msdtc.exe",
	L"devenv.exe",
	L"perfmon.exe",
	L"taskmgr.exe",
	L"audiodg.exe",
	L"DarkComet.exe",
	L"taskmgr.exe"
};
int CPID;
int parmnum = 255;
UCHAR OPcode;

//MessageQueue mq;

// hash map for file name
DWORD fileObject;
unordered_map<DWORD, DWORD> keyhandleMap;
unordered_map<DWORD, short> ParmToNum;
unordered_map<DWORD, wchar_t*> ProcessName_map;

unordered_map<DWORD, DWORD> ThreadIDtoPID_map;
unordered_map<DWORD, DWORD> keyname_map;
unordered_map<DWORD, DWORD> messageID_Map;
unordered_map<DWORD, DWORD> couteachprocesseventnumber;

struct hash_func
{
	//BKDR hash algorithm，有关字符串hash函数，可以去找找资料看看
	int operator()(const wchar_t * str)const
	{
		int seed = 131;//31  131 1313 13131131313 etc//
		int hash = 0;
		while (*str)
		{
			hash = (hash * seed) + (*str);
			str++;
		}

		return hash & (0x7FFFFFFF);
	}
};
struct cmp
{
	bool operator()(const wchar_t *str1, const wchar_t * str2)const
	{
		return wcscmp(str1, str2) == 0;
	}
};
unordered_map<const wchar_t*, int, hash_func, cmp> ParaList;

//global values for activeMQ
std::auto_ptr<MessageProducer> producer;
std::auto_ptr<BytesMessage> message;
std::auto_ptr<Session> session;
auto_ptr<Connection> connection;


void wmain(int argc, char* argv[])
{
	_beginthread(killProcessByPID, 0, NULL);

	getallprocess();
	getallthread();

	whiteListPID.insert(GetCurrentProcessId());
	for (int i = 0; i != 83; i++){
		ParaList[SysParaList[i]] = i;
	}
	for (unordered_map<DWORD, wchar_t*>::iterator ix = g.addressToName.begin(); ix != g.addressToName.end(); ix++){
		ParmToNum[ix->first] = ParaList[ix->second];
	}

	activemq::library::ActiveMQCPP::initializeLibrary();

	cout << "=====================================================\n";
	cout << "Starting the Publisher :" << std::endl;
	cout << "-----------------------------------------------------\n";

	string user = getEnv("ACTIVEMQ_USER", "admin");
	string password = getEnv("ACTIVEMQ_PASSWORD", "admin");
	string host = getEnv("ACTIVEMQ_HOST", "10.214.148.122");
	int port = Integer::parseInt(getEnv("ACTIVEMQ_PORT", "61616"));
	string destination = getArg(argv, argc, 1, "new");

	ActiveMQConnectionFactory factory;
	factory.setBrokerURI(std::string("tcp://") + host + ":" + Integer::toString(port));

	auto_ptr<Connection>  connection_(factory.createConnection(user, password));
	connection = connection_;
	connection->start();
	auto_ptr<Session> ss(connection->createSession());
	session = ss;
	auto_ptr<Destination> dest(session->createTopic(destination));
	auto_ptr<MessageProducer> pp(session->createProducer(dest.get()));
	producer = pp;

	producer->setDeliveryMode(DeliveryMode::NON_PERSISTENT);
	cout << "Initialized." << endl;
	MessageCount = 0L;

begin:
	TDHSTATUS status = ERROR_SUCCESS;
	EVENT_TRACE_LOGFILE trace;
	TRACE_LOGFILE_HEADER* pHeader = &trace.LogfileHeader;

	// Identify the log file from which you want to consume events
	// and the callbacks used to process the events and buffers.

	ZeroMemory(&trace, sizeof(EVENT_TRACE_LOGFILE));
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

	// wprintf(L"Number of buffers lost: %lu\n\n", pHeader->BuffersLost);


	status = ProcessTrace(&g_hTrace, 1, 0, 0);
	if (status != ERROR_SUCCESS && status != ERROR_CANCELLED)
	{
		wprintf(L"ProcessTrace failed with %lu\n", status);
		goto cleanup;
	}


cleanup:

	//	wprintf(L"The process is ended with %lu\n", status);
	if (INVALID_PROCESSTRACE_HANDLE != g_hTrace)
	{
		status = CloseTrace(g_hTrace);
	}
	outFile.clear();
	//WSACleanup();
	goto begin;

}


VOID WINAPI ProcessEvent(PEVENT_RECORD pEvent)
{
	DWORD status = ERROR_SUCCESS;
	DWORD pUserData;
	DWORD PointerSize = 0;
	ULONGLONG TimeStamp = 0;
	ULONGLONG Nanoseconds = 0;
	finishOP = false;
	CPID = 0;
	OPcode = pEvent->EventHeader.EventDescriptor.Opcode;
	if (IsEqualGUID(pEvent->EventHeader.ProviderId, EventTraceGuid) &&
		(!OPcode))
	{
		wprintf(L"A Event is being skipped\n");
		; // Skip this event.
	}
	// Skips the event if it is not SysClEnter(51) or CSwitch(36).
	else
	if (
		(OPcode == 10 && pEvent->EventHeader.ProviderId.Data1 == 0xae53722e)
		|| (OPcode == 11 && pEvent->EventHeader.ProviderId.Data1 == 0xae53722e)
		|| (OPcode == 13 && pEvent->EventHeader.ProviderId.Data1 == 0xae53722e)
		|| (OPcode == 16 && pEvent->EventHeader.ProviderId.Data1 == 0xae53722e)
		|| (OPcode == 51)
		|| (OPcode == 10 && pEvent->EventHeader.ProviderId.Data1 == 0x2cb15d1d)
		|| (OPcode == 32 && pEvent->EventHeader.ProviderId.Data1 == 0x90cbdc39)
		|| (OPcode == 64 && pEvent->EventHeader.ProviderId.Data1 == 0x90cbdc39)
		|| (OPcode == 33 && pEvent->EventHeader.ProviderId.Data1 == 0x45d8cccd)
		|| (OPcode == 34 && pEvent->EventHeader.ProviderId.Data1 == 0x45d8cccd)
		|| (OPcode == 1 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d1)
		|| (OPcode == 36 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d1)
		|| (OPcode == 1 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d0)

		)
	{
		pUserData = (DWORD)pEvent->UserData;
		if (OPcode == 51){
			DWORD address = (*(DWORD *)pUserData) & 0xFFFFFFF;
			if (g.addressToName.find(address) != g.addressToName.end())
				parmnum = ParmToNum[address];
			else goto cleanup;
			EventType = 46;
			CPID = curPID[pEvent->BufferContext.ProcessorNumber];
			finishOP = true;
			goto cleanup;
		}
		else
		if ((OPcode == 33 && pEvent->EventHeader.ProviderId.Data1 == 0x45d8cccd)
			|| (OPcode == 34 && pEvent->EventHeader.ProviderId.Data1 == 0x45d8cccd)){
			if (OPcode == 33)
			{
				DWORD messageID = *(DWORD*)(pUserData);
				CPID = pEvent->EventHeader.ProcessId;
				messageID_Map[messageID] = CPID;
				goto cleanup;
			}
			else
			{
				CPID = pEvent->EventHeader.ProcessId;
				DWORD messageID = *(DWORD*)(pUserData);
				if (messageID_Map.find(messageID) != messageID_Map.end() && ProcessName_map.find(messageID_Map[messageID]) != ProcessName_map.end() && ParaList.find(ProcessName_map[messageID_Map[messageID]]) != ParaList.end()){
					EventType = 38;
					finishOP = true;
					parmnum = ParaList[ProcessName_map[messageID_Map[messageID]]];
				}
				if (ProcessName_map.find(CPID) != ProcessName_map.end() && ParaList.find(ProcessName_map[CPID]) != ParaList.end()){
					EventType = 39;
					finishOP = true;
					parmnum = ParaList[ProcessName_map[CPID]];
					CPID = messageID_Map[messageID];
				}
				goto cleanup;
			}
		}
		else
		if (OPcode == 1 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d0){
			pUserData += 8;
			CPID = *(DWORD*)pUserData;
			pUserData += 40;
			pUserData += GetLengthSid((PVOID)(pUserData));
			int len = strlen((char *)pUserData);
			if (pEvent->EventHeader.EventDescriptor.Opcode == 1 || pEvent->EventHeader.EventDescriptor.Opcode == 3){
				/*wstring oname = ProcessName_map[CPID];
				if (whiteListPName.find(oname) != whiteListPName.end())
				{
					if (whiteListPID.find(CPID) != whiteListPID.end())
						whiteListPID.erase(CPID);
				}*/

				ProcessName_map[CPID] = (wchar_t*)malloc((len + 1)*sizeof(wchar_t));
				int i = 0;
				wchar_t* st = ProcessName_map[CPID];
				wchar_t* stemp = st;
				char* ch = (char *)pUserData;
				while ((*ch) != 0){
					*st = (wchar_t)(*ch);
					st += 1;
					ch += 1;
					i += 1;
				}
				*st = 0;

				wstring temp = wstring(stemp);
				if (whiteListPName.find(temp) != whiteListPName.end())
					whiteListPID.insert(CPID);
			}
			goto cleanup;
		}
		else
		if (OPcode == 1 && pEvent->EventHeader.ProviderId.Data1 == 0x3d6fa8d1){
			CPID = *(DWORD*)pUserData;
			pUserData += 4;
			DWORD threadid = *(DWORD*)pUserData;
			ThreadIDtoPID_map[threadid] = CPID;
			goto cleanup;
		}
		else
		if ((OPcode == 10 || OPcode == 13 || OPcode == 16 || OPcode == 11) && pEvent->EventHeader.ProviderId.Data1 == 0xae53722e){
			pUserData += 16;
			DWORD keyhandle = *(DWORD*)pUserData;
			if (OPcode == 10 || OPcode == 11){
				pUserData += 8;
				DWORD last_backslash = pUserData;
				while (*(unsigned short*)pUserData != 0 && *(unsigned short*)pUserData != 0x7B){
					pUserData += 2;
				}
				*(unsigned short*)pUserData = 0;
				parm = (wchar_t*)last_backslash;
				if (ParaList.find(parm) == ParaList.end()) goto cleanup; else parmnum = ParaList[parm];
				keyname_map[keyhandle] = parmnum;
			}
			else{
				if (keyname_map.find(keyhandle) == keyname_map.end()) goto cleanup; else parmnum = keyname_map[keyhandle];
			}
			switch (OPcode)
			{
			case 10:{
						EventType = 42;
						break;
			}
			case 11:{
						EventType = 43;
						break;
			}
			case 13:{
						EventType = 44;
						break;
			}
			case 16:{
						EventType = 45;
						break;
			}
			}
			CPID = pEvent->EventHeader.ProcessId;
			finishOP = true;
			goto cleanup;
		}
		else
		if (OPcode == 32 && pUserData&& pEvent->EventHeader.ProviderId.Data1 == 0x90cbdc39){
			//fileObject = *(DWORD *)pUserData;
			pUserData += 8;
			//strName = "NtCreateFile";
			DWORD last_backslash = pUserData;
			while (*(unsigned short*)pUserData != 0 && *(unsigned short*)pUserData != 0x7B){
				pUserData += 2;
			}
			*(unsigned short*)pUserData = 0;
			parm = (wchar_t*)last_backslash;
			if (ParaList.find(parm) == ParaList.end()) goto cleanup; else parmnum = ParaList[parm];
			EventType = 40;
			CPID = curPID[pEvent->BufferContext.ProcessorNumber];
			finishOP = true;
			goto cleanup;
		}
		else
		if (OPcode == 36 && pEvent->EventHeader.ProviderId.Data1 == 1030727889){
			DWORD threadID = *(DWORD *)pUserData;
			int processorID = pEvent->BufferContext.ProcessorNumber;
			curPID[processorID] = GetProcessIdOfThread(OpenThread(THREAD_QUERY_INFORMATION, false, threadID));
			if (curPID[processorID] == 0) curPID[processorID] = ThreadIDtoPID_map[threadID];
			goto cleanup;
		}
		if (OPcode == 64 && pEvent->EventHeader.ProviderId.Data1 == 0x90cbdc39){
			pUserData += 8;
			DWORD threadID = *(DWORD *)pUserData;
			CPID = GetProcessIdOfThread(OpenThread(THREAD_QUERY_INFORMATION, false, threadID));
			if (!CPID) CPID = ThreadIDtoPID_map[threadID];
			pUserData += 8;
			fileObject = *(DWORD*)pUserData;
			pUserData += 20;
			//strName = "NtCreateFile";
			DWORD last_backslash = pUserData;
			while (*(unsigned short*)pUserData != 0 && *(unsigned short*)pUserData != 0x7B){
				pUserData += 2;
			}
			*(unsigned short*)pUserData = 0;
			parm = (wchar_t*)last_backslash;
			if (ParaList.find(parm) == ParaList.end()) goto cleanup; else parmnum = ParaList[parm];
			EventType = 40;
			finishOP = true;
			goto cleanup;
		}
		else
		if (OPcode == 10 && pEvent->EventHeader.ProviderId.Data1 == 0x2cb15d1d){
			pUserData += 16;
			CPID = *(DWORD*)pUserData;
			pUserData += 40;
			//strName = "NtOpenSection";
			DWORD last_backslash = pUserData;
			while (*(unsigned short*)pUserData != 0 && *(unsigned short*)pUserData != 0x7B){
				pUserData += 2;
			}
			*(unsigned short*)pUserData = 0;
			parm = (wchar_t*)last_backslash;
			if (ParaList.find(parm) == ParaList.end()) goto cleanup; else parmnum = ParaList[parm];
			EventType = 41;
			CPID = pEvent->EventHeader.ProcessId;
			finishOP = true;
			goto cleanup;
		}
	cleanup:
		if (!pidInWhitelist(CPID) && finishOP)
		{
			if (MessageCount % MaxSendNum == 0 && MessageCount != 0){
				try {
					message.reset(session->createBytesMessage(data, MaxSendNum * 6));
				}
				catch (CMSException e){
					cout << e.getMessage();
					auto_ptr<Session> ss(connection->createSession());
					session = ss;
				}

				producer->send(message.get());
			}
			if (couteachprocesseventnumber.find(CPID) != couteachprocesseventnumber.end()){
				couteachprocesseventnumber[CPID]++;
			}
			else{
				couteachprocesseventnumber[CPID] = 1;
			}
			data[(MessageCount%MaxSendNum) * 6] = couteachprocesseventnumber[CPID] % 255 + 1;
			data[(MessageCount%MaxSendNum) * 6 + 1] = (couteachprocesseventnumber[CPID] / 255) % 255 + 1;
			data[(MessageCount%MaxSendNum) * 6 + 2] = CPID % 255 + 1;
			data[(MessageCount%MaxSendNum) * 6 + 3] = (CPID / 255) % 255 + 1;
			data[(MessageCount%MaxSendNum) * 6 + 4] = parmnum + 1;
			data[(MessageCount%MaxSendNum) * 6 + 5] = EventType + 1;
			MessageCount++;
			//string messageBody = ss.str();
			//reset
			//message.reset(session->createTextMessage(boost::asio::buffer(data)));
			//			cout << data << endl;
			//send to activeMQ
			//output to local file
			//outFile << messageBody.c_str() << endl;
			//outFile << data << endl;
			//outFile << hex << (((strnum << 1) + parmnum / 256) << 24) + (parmnum % 256 << 16) + (CPID / 256 << 8) + CPID % 256 << ' ';
			//cout << messageBody.c_str() << endl;
			//int ret;
			//if ((ret = send(sockClient, (char*)&data, 4, 0)) < 0)
			//	{
			//		printf("errno: %d\n", WSAGetLastError());
			//	}
			if (MessageCount % 10000 == 0)
			{
				wcout << L"published " << MessageCount << L" messages!" << endl;
			}
		}
		parmnum = 255;
		EventType = 255;
		//CloseTrace(g_hTrace);
		if (ERROR_SUCCESS != status || NULL == pUserData)
		{
			CloseTrace(g_hTrace);
		}
	}
}


BOOL pidInWhitelist(DWORD pid){

	set<DWORD>::iterator i = whiteListPID.find(pid);
	if (i != whiteListPID.end())
	{
		return true;
	}
		
	else
		return false;
}


VOID getallprocess()
{
	HANDLE   hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32   procentry;
	procentry.dwSize = sizeof(PROCESSENTRY32);
	BOOL   bFlag = Process32First(hSnapShot, &procentry);
	while (bFlag)
	{
		int len = wcslen(procentry.szExeFile);
		ProcessName_map[procentry.th32ProcessID] = (wchar_t*)malloc((len + 1)*sizeof(wchar_t));
		int i = 0;
		wchar_t* st = ProcessName_map[procentry.th32ProcessID];

		//try to find out the PIDs for the processes in the whitelist
		wstring temp = wstring(procentry.szExeFile);
		if (whiteListPName.find(temp) != whiteListPName.end())
			whiteListPID.insert(procentry.th32ProcessID);

		while ((procentry.szExeFile[i]) != 0){
			*st = procentry.szExeFile[i];
			st += 1;
			i += 1;
		}
		*st = 0;
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
		ThreadIDtoPID_map[thrcentry.th32ThreadID] = thrcentry.th32OwnerProcessID;
		bFlag = Thread32Next(hSnapShot, &thrcentry);
	}
}

VOID __cdecl killProcessByPID(VOID*)
{
	//wprintf(L"new thread!!\n");

	//cout << "waitting for killing" << endl;

	DWORD processId = 1544;

	activemq::library::ActiveMQCPP::initializeLibrary();
	string user = getEnv("ACTIVEMQ_USER", "admin");
	string password = getEnv("ACTIVEMQ_PASSWORD", "admin");
	string host = getEnv("ACTIVEMQ_HOST", "10.214.148.122");
	int port = Integer::parseInt(getEnv("ACTIVEMQ_PORT", "61616"));
	string destination = getArg(NULL, 0, 1, "kill");



	{
		ActiveMQConnectionFactory factory;
		factory.setBrokerURI(std::string("tcp://") + host + ":" + Integer::toString(port));

		std::auto_ptr<Connection> connection(factory.createConnection(user, password));

		std::auto_ptr<Session> session(connection->createSession());
		std::auto_ptr<Destination> dest(session->createTopic(destination));
		std::auto_ptr<MessageConsumer> consumer(session->createConsumer(dest.get()));

		connection->start();

		long long start = System::currentTimeMillis();
		long long count = 0;

		//std::cout << "Waiting for messages..." << std::endl;
		
		while (true)
		{
			std::auto_ptr<Message> message(consumer->receive());

			const BytesMessage* bMessage = dynamic_cast<const BytesMessage*>(message.get());
			BYTE* bp = bMessage->getBodyBytes();
			processId = *(int*)bp;

			//if (ProcessName_map.find(processId) != ProcessName_map.end())
			//	std::wcout << L"killing process: " << ProcessName_map[processId] << endl;
			//else
			//	std::wcout << L"no such process: " << processId << endl;

			HANDLE   hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			PROCESSENTRY32   procentry;
			procentry.dwSize = sizeof(PROCESSENTRY32);
			BOOL   bFlag = Process32First(hSnapShot, &procentry);
			while (bFlag)
			{
				if (procentry.th32ProcessID == processId){
					wprintf(L"killing process:%s\n", procentry.szExeFile);
					break;
				}
				bFlag = Process32Next(hSnapShot, &procentry);
			}



			HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
			TerminateProcess(processHandle, 0);
		}
		

		connection->close();
	}


}
