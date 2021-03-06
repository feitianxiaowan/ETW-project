#define INITGUID  // Include this #define to use SystemTraceControlGuid in Evntrace.h.

#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <strsafe.h>
#include <wmistr.h>
#include <evntrace.h>

#define LOGFILE_PATH L"G:\\source\\ETW\\IMAGE_LOAD2.etl"

void wmain(void)
{
    ULONG status = ERROR_SUCCESS;
    TRACEHANDLE SessionHandle = 0;
    EVENT_TRACE_PROPERTIES* pSessionProperties = NULL;
    ULONG BufferSize = 0;

    // Allocate memory for the session properties. The memory must
    // be large enough to include the log file name and session name,
    // which get appended to the end of the session properties structure.
    
    BufferSize = sizeof(EVENT_TRACE_PROPERTIES) 
//		+ sizeof(LOGFILE_PATH)             // delete this in real time mode
		+ sizeof(KERNEL_LOGGER_NAME);
    pSessionProperties = (EVENT_TRACE_PROPERTIES*) malloc(BufferSize);    
    if (NULL == pSessionProperties)
    {
        wprintf(L"Unable to allocate %d bytes for properties structure.\n", BufferSize);
        goto cleanup;
    }
    
    // Set the session properties. You only append the log file name
    // to the properties structure; the StartTrace function appends
    // the session name for you.


    ZeroMemory(pSessionProperties, BufferSize);
    pSessionProperties->Wnode.BufferSize = BufferSize;
    pSessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    pSessionProperties->Wnode.ClientContext = 1; //QPC clock resolution
    pSessionProperties->Wnode.Guid = SystemTraceControlGuid; 
	pSessionProperties->EnableFlags = 0L
|EVENT_TRACE_FLAG_PROCESS            // process start & end
|EVENT_TRACE_FLAG_THREAD            // thread start & end
|EVENT_TRACE_FLAG_IMAGE_LOAD          // image load

|EVENT_TRACE_FLAG_DISK_IO             // physical disk IO
|EVENT_TRACE_FLAG_DISK_FILE_IO         // requires disk IO

|EVENT_TRACE_FLAG_MEMORY_PAGE_FAULTS   // all page faults
|EVENT_TRACE_FLAG_MEMORY_HARD_FAULTS   // hard faults only

|EVENT_TRACE_FLAG_NETWORK_TCPIP        // tcpip send & receive

|EVENT_TRACE_FLAG_REGISTRY             // registry calls
|EVENT_TRACE_FLAG_DBGPRINT             // DbgPrint(ex) Calls
|EVENT_TRACE_FLAG_PROCESS_COUNTERS     // process perf counters
|EVENT_TRACE_FLAG_CSWITCH              // context switches
|EVENT_TRACE_FLAG_DPC                  // deffered procedure calls
|EVENT_TRACE_FLAG_INTERRUPT            // interrupts
|EVENT_TRACE_FLAG_SYSTEMCALL           // system calls

|EVENT_TRACE_FLAG_DISK_IO_INIT         // physical disk IO initiation
|EVENT_TRACE_FLAG_ALPC                 // ALPC traces
|EVENT_TRACE_FLAG_SPLIT_IO             // split io traces (VolumeManager)

|EVENT_TRACE_FLAG_DRIVER               // driver delays
/*|EVENT_TRACE_FLAG_PROFILE*/              // sample based profiling
|EVENT_TRACE_FLAG_FILE_IO              // file IO
|EVENT_TRACE_FLAG_FILE_IO_INIT  // file IO initiation     
|EVENT_TRACE_FLAG_DISPATCHER	// scheduler (ReadyThread)
| EVENT_TRACE_FLAG_VIRTUAL_ALLOC		//VM operations
				/*| EVENT_TRACE_FLAG_PROFILE*/
		;
	/*
	pSessionProperties->LogFileMode = EVENT_TRACE_FILE_MODE_CIRCULAR;
	pSessionProperties->MaximumFileSize = 1;  //  MB
	*/
	
	pSessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
	pSessionProperties->MaximumBuffers = 1024;
	pSessionProperties->BufferSize = 1000;
	pSessionProperties->LogFileNameOffset = 0;
	

	/*
    pSessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    pSessionProperties->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(KERNEL_LOGGER_NAME); 
    StringCbCopy((LPWSTR)((char*)pSessionProperties + pSessionProperties->LogFileNameOffset), sizeof(LOGFILE_PATH), LOGFILE_PATH);
	*/
    // Create the trace session.

    status = StartTrace((PTRACEHANDLE)&SessionHandle, KERNEL_LOGGER_NAME, pSessionProperties);

    if (ERROR_SUCCESS != status)
    {
        if (ERROR_ALREADY_EXISTS == status)
        {
            wprintf(L"The NT Kernel Logger session is already in use.\n");
        }
        else
        {
            wprintf(L"EnableTrace() failed with %lu\n", status);
        }

        goto cleanup;
    }

    wprintf(L"Press any key to end trace session ");
    _getch();

cleanup:

    if (SessionHandle)
    {
        status = ControlTrace(SessionHandle, KERNEL_LOGGER_NAME, pSessionProperties, EVENT_TRACE_CONTROL_STOP);

        if (ERROR_SUCCESS != status)
        {
            wprintf(L"ControlTrace(stop) failed with %lu\n", status);
        }
    }

    if (pSessionProperties)
        free(pSessionProperties);

	_getch();
}