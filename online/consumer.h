#define MaxSendNum 10000
#define BUFFERSIZE 100
#define LOGFILE_PATH L"C:\\Users\\admin\\Desktop\\online\\record.etl"


//global values
DWORD fileObject;
ULONG g_TimerResolution = 0;
BOOL g_bUserMode = FALSE;
TRACEHANDLE g_hTrace = 0;
BOOL finishOP;
SOCKET sockClient;
wofstream outFile;
DWORD  MessageCount;
DWORD curPID[4] = { 0L };
BYTE data[MaxSendNum * 6 + 1];
getAddress g;
string path = "";
DWORD EventType;
wchar_t* parm;
int CPID;
int parmnum = 255;
UCHAR OPcode;

// hash map for file name
unordered_map<DWORD, DWORD> keyhandleMap;
unordered_map<DWORD, short> ParmToNum;
unordered_map<DWORD, wchar_t*> ProcessName_map;
unordered_map<DWORD, DWORD> ThreadIDtoPID_map;
unordered_map<DWORD, DWORD> keyname_map;
unordered_map<DWORD, DWORD> messageID_Map;
unordered_map<DWORD, DWORD> couteachprocesseventnumber;

// for "producter and consumer" model
struct eventStruct{
	void* userData;
	int userDataSize;
};
eventStruct eventStructBuffer[BUFFERSIZE];
//PEVENT_RECORD pEventBuffer[BUFFERSIZE];
int pEventBufferSize = 0;
int producterPos = 0;
int consumerPos = 0;
condition_variable notFullCv;
condition_variable notEmptyCv;
mutex bufferMutex;
mutex ioMutex;


DWORD GetEventInformation(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO & pInfo);
PBYTE PrintProperties(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, DWORD PointerSize, USHORT i, PBYTE pUserData, PBYTE pEndOfUserData);
DWORD GetPropertyLength(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT PropertyLength);
void RemoveTrailingSpace(PEVENT_MAP_INFO pMapInfo);
string getEnv(const string& key, const string& defaultValue);
string getArg(char* argv[], int argc, int index, const string& defaultValue);
BOOL pidInWhitelist(DWORD pid);
VOID getallthread(VOID);
VOID getallprocess(VOID);

VOID __cdecl killProcessByPID(VOID*);
void WINAPI produceEvent(PEVENT_RECORD pEvent);
VOID __cdecl consumEvent(VOID*);
//VOID ProcessEvent(PEVENT_RECORD pEvent);
VOID WINAPI ProcessEvent(PEVENT_RECORD pEvent);