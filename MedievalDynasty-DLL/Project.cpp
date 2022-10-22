#include "Project.h"
#include "DllMain.h"
#include "Test.h"
#include "Unloader.h"
#include "Console.h"
#include "ScanData.h"

#include <atlstr.h>
#include <fstream>
#include <iomanip>
#include <process.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <time.h>
#include <vector>
#include <wchar.h>
#include <WinBase.h>
#include <Windows.h>
#include <windowsx.h>
#include <tlhelp32.h>


#include <thread>
#include <chrono>



using namespace std;

DLLEXPORT void Initialize();
DLLEXPORT void Run();
DLLEXPORT void Cleanup();
DLLEXPORT void __cdecl  hotkeyThread(void*);

BOOL WINAPI OnConsoleSignal(DWORD dwCtrlType);

HANDLE hHotkeyThread;

bool bRunning = false;

typedef PDWORD64(WINAPI* tStaticFindObject)(DWORD64 cls, DWORD64 inout, wchar_t* obj, bool flag);
PDWORD64 WINAPI hStaticFindObject(DWORD64 cls, DWORD64 input, wchar_t* obj, bool flag);
tStaticFindObject StaticFindObject = NULL;


struct sMDGameFunctions
{
	DWORD64 StaticFindObject;
};
sMDGameFunctions MDGameFunctions;

struct UFunction
{
	char misc[0xd8];
	DWORD64 fptr;
};


void initInGameFunctions()
{

}

DWORD ModuleCheckingThread()
{
	return 0;
}

DLLEXPORT void __cdecl Start(void*)
{
	Unloader::Initialize(hDll);

	Console::Create("MedievalDynasty-DLL");

	if (!SetConsoleCtrlHandler(OnConsoleSignal, TRUE)) {
		printf("\nERROR: Could not set control handler\n");
		return;
	}

	printf("Initializing\n");
	Initialize();
	Run();
	Cleanup();

	SetConsoleCtrlHandler(OnConsoleSignal, FALSE);
	Console::Free();
	Unloader::UnloadSelf(true);		// Unloading on a new thread fixes an unload issue
}

uintptr_t bruteForce(const ScanData& signature, const ScanData& data) {
	//Bruteforce function copied from Broihon at GuidedHacking.net
	for (size_t currentIndex = 0; currentIndex < data.size - signature.size; currentIndex++) {
		for (size_t sigIndex = 0; sigIndex < signature.size; sigIndex++) {
			if (data.data[currentIndex + sigIndex] != signature.data[sigIndex] && signature.data[sigIndex] != '?') {
				break;
			}
			else if (sigIndex == signature.size - 1) {
				return currentIndex;
			}
		}
	}
	return 0;
}

LPCSTR GetProcessName(DWORD PID)
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 process;
	ZeroMemory(&process, sizeof(process));
	process.dwSize = sizeof(process);

	if (Process32First(snapshot, &process))
	{
		do
		{
			if (process.th32ProcessID == PID)
			{
				CloseHandle(snapshot);

				return CStringA(process.szExeFile);
			}
		} while (Process32Next(snapshot, &process));
	}
	CloseHandle(snapshot);
	return NULL;
}

void Initialize()
{
	HANDLE hMD = GetModuleHandleA(GetProcessName(::_getpid()));


	if (!hMD)
	{	
		printf("ERROR: Getting handle to game\n");
		return;
	}

	printf("Handle: %p\n", hMD);
	printf("Base: %llx\n", (INT64)hMD);

	ScanData signature = ScanData("48 89 5C 24 ? 48 89 74 24 ? 55 57 41 54 41 56 41 57 48 8B EC 48 83 EC ? 80 3D ? ? ? ? 00 45 0F B6 F1 49 8B F8 48 8B DA 4C 8B F9 74");
	ScanData data = ScanData(0x2000000);

	memcpy(data.data, hMD, data.size);
	uintptr_t offset = bruteForce(signature, data);
	
	MDGameFunctions.StaticFindObject = ((DWORD64)hMD + offset);
	printf("staticfind: %llx\n", MDGameFunctions.StaticFindObject);
	*(PDWORD64)&StaticFindObject = MDGameFunctions.StaticFindObject;

	//unsigned char* p = (unsigned char*)&hMD;
	//printf("b1: %x\n",p[0]);

	//initKernelBaseFunctions();
	//initInGameFunctions();

	//ModuleCheckingThread();
	UFunction* isb;
	UFunction* idb;

	DWORD64 ptr = 0;
	
	printf("Waiting for IsShippingBuild function to register.\n");
	while (ptr == 0)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		ptr = (DWORD64)StaticFindObject((DWORD64)0, (DWORD64)-1, L"TDBPL_IsShippingBuild", true);
	}
	
	*(PDWORD64)&isb = ptr;

	ptr = (DWORD64)StaticFindObject((DWORD64)0, (DWORD64)-1, L"TDBPL_IsDevelopmentBuild", true);
	*(PDWORD64)&idb = ptr;
		
	DWORD64 retTrue = isb->fptr;
	DWORD64 retFalse = idb->fptr;


	printf("Setting IsShippingBuild = false, IsDevelopmentBuild = true.\n");
	isb->fptr = retFalse;
	idb->fptr = retTrue;


	printf("isb.fptr: %llx\n", isb->fptr);
	printf("idb.fptr: %llx\n", idb->fptr);

	int err = GetLastError();
	if (err == 0)
	{
		printf("\n\nNo errors detected.\nCheat Menu should now be available after loading/starting a game and pressing ESC.\n");
	}
	else
	{
		printf("\n\nError %d reported.  No clue what this means, let Wulf know the details.\n", err);
	}
	printf("This window will disappear shortly after the game exits.\n");
	//_beginthread(&hotkeyThread, 0, 0);
}
void Cleanup()
{
	
}
void Run()
{
	bRunning = true;

	while (bRunning)
	{		
		Sleep(33);
	}
}

BOOL WINAPI OnConsoleSignal(DWORD dwCtrlType) {

	if (dwCtrlType == CTRL_C_EVENT)
	{
		printf("Ctrl-C handled, exiting...\n"); // do cleanup
		bRunning = false;
		return TRUE;
	}

	return FALSE;
}

DLLEXPORT void __cdecl hotkeyThread(void*)
{
	printf("hotkeyThread() called\n");

	bool hk_Enter_Pressed = false;
	
	bool hk_Num1_Pressed = false;
	bool hk_Num2_Pressed = false;
	bool hk_Num3_Pressed = false;

	bool hk_Numpad2_Pressed = false;
	bool hk_Numpad4_Pressed = false;
	bool hk_Numpad6_Pressed = false;
	bool hk_Numpad8_Pressed = false;

	bool hk_NumpadPlus_Pressed = false;
	


	short hk_Enter;

	short hk_Num1;
	short hk_Num2;
	short hk_Num3;

	short hk_Numpad2;
	short hk_Numpad4;
	short hk_Numpad6;
	short hk_Numpad8;

	short hk_NumpadPlus;


	while (bRunning)
	{
		HWND hforegroundWnd = GetForegroundWindow();
		HWND hMD = FindWindow(NULL, L"Medieval Dynasty");

		if ((hforegroundWnd == hMD) || (hMD == NULL))
		{
			
			hk_Enter = GetKeyState(0x0D);
			
			hk_Num1 = GetKeyState(0x31);
			hk_Num2 = GetKeyState(0x32);
			hk_Num3 = GetKeyState(0x33);

			hk_Numpad2 = GetKeyState(0x62);
			hk_Numpad4 = GetKeyState(0x64);
			hk_Numpad6 = GetKeyState(0x66);
			hk_Numpad8 = GetKeyState(0x68);

			hk_NumpadPlus = GetKeyState(0x6B);
			


			if (hk_Enter & 0x8000)
			{
				if (hk_Enter_Pressed == false)
				{
					hk_Enter_Pressed = true;

				}
			}
			else
			{
				hk_Enter_Pressed = false;
			}


			if (hk_Num1 & 0x8000) 
			{
				hk_Num1_Pressed = true;
				bRunning = false;
			}
			


			if (hk_Num2 & 0x8000) 
			{
				if (hk_Num2_Pressed == false) 
				{
					hk_Num2_Pressed = true;
				}
					
			}
			else
			{
				hk_Num2_Pressed = false;
			}




			if (hk_Num3 & 0x8000) 
			{
				if (hk_Num3_Pressed == false)
				{
					hk_Num3_Pressed = true;

				}
			}
			else
			{
				hk_Num3_Pressed = false;
			}
				


			if (hk_Numpad2 & 0x8000) 
			{
				if (hk_Numpad2_Pressed == false)
				{
					hk_Numpad2_Pressed = true;
				}
			}
			else
			{
				hk_Numpad2_Pressed = false;
			}



			if (hk_Numpad4 & 0x8000) 
			{
				if (hk_Numpad4_Pressed == false) 
				{
					hk_Numpad4_Pressed = true;
				}
			}
			else
			{
				hk_Numpad4_Pressed = false;
			}


			if (hk_Numpad6 & 0x8000) 
			{
				if (hk_Numpad6_Pressed == false) 
				{
					hk_Numpad6_Pressed = true;
				}
			}
			else
			{
				hk_Numpad6_Pressed = false;
			}


			if (hk_Numpad8 & 0x8000) 
			{
				if (hk_Numpad8_Pressed == false) 
				{
					hk_Numpad8_Pressed = true;
				}
			}
			else
			{
				hk_Numpad8_Pressed = false;
			}


			if (hk_NumpadPlus & 0x8000)
			{
				if (hk_NumpadPlus_Pressed == false)
				{
					hk_NumpadPlus_Pressed = true;
				}
			}
			else
			{
				hk_NumpadPlus_Pressed = false;
			}


		}
		Sleep(30);
	}
}

