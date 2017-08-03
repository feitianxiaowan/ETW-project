#define MaxSendNum 10000
#define LOGFILE_PATH L"C:\\Users\\admin\\Desktop\\online\\record.etl"


void WINAPI ProcessEvent(PEVENT_RECORD pEvent);
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