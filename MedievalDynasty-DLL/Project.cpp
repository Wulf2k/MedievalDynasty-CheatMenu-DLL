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
DLLEXPORT void __cdecl  initialStuff(void*);
DLLEXPORT void __cdecl  hotkeyThread(void*);

BOOL WINAPI OnConsoleSignal(DWORD dwCtrlType);

HANDLE hHotkeyThread;

bool bRunning = false;

typedef PDWORD64(WINAPI* tStaticFindObject)(DWORD64 cls, DWORD64 inout, wchar_t* obj, bool flag);
PDWORD64 WINAPI hStaticFindObject(DWORD64 cls, DWORD64 input, wchar_t* obj, bool flag);
tStaticFindObject StaticFindObject = NULL;

/*
typedef PDWORD64(WINAPI* tStaticConstructObject)(DWORD64 cls, DWORD64 inout);
PDWORD64 WINAPI hStaticConstructObject(DWORD64 cls, DWORD64 inout);
tStaticConstructObject StaticConstructObject = NULL;
*/


struct sMDGameFunctions
{
	//DWORD64 StaticConstructObject;
	DWORD64 StaticFindObject;
};
sMDGameFunctions MDGameFunctions;

struct UFunction
{
	char misc[0xd8];
	DWORD64 fptr;
};

struct GI_MedievalDynasty_C
{
	char misc[0x1b0];
	int bDebugModeEnabled;
	int gi1;
	int gi2;
	int gi3;
	int gi4;
	int gi5;
	int DebugWidget; //0x1b8
	char misc2[0x3b4];
	byte TestVersion;
};

GI_MedievalDynasty_C* gi;
GI_MedievalDynasty_C* cgi;


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

	printf("Initializing....\n");
	Initialize();
	printf("Running....\n");
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
	//_beginthread(&hotkeyThread, 0, 0);
}
void Cleanup()
{
	
}
void Run()
{
	bRunning = true;

	_beginthread(initialStuff, 0, 0);

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

DLLEXPORT void __cdecl initialStuff(void*)
{
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	printf("pid: %llx\n", ::_getpid());
	printf("ProcessName: %s\n", GetProcessName(::_getpid()));
	HANDLE hMD = GetModuleHandleA(GetProcessName(::_getpid()));

	if (!hMD)
	{
		printf("ERROR: Getting handle to game\n");
		return;
	}

	//GEngine?
	//48 ? ? 05 ? ? ? ? ? ? ? ? 48 ? ? 88 ? ? 07 00 00 48 ? ? 01 ? ? 90 ? ? 01 00 00

	printf("Handle: %p\n", hMD);
	printf("Base: %llx\n", (INT64)hMD);
	//AoB signature courtesy of SunBeam
	ScanData signature = ScanData("48 89 5C 24 ? 48 89 74 24 ? 55 57 41 54 41 56 41 57 48 8B EC 48 83 EC ? 80 3D ? ? ? ? 00 45 0F B6 F1 49 8B F8 48 8B DA 4C 8B F9 74");
	ScanData data = ScanData(0x2000000);
	memcpy(data.data, hMD, data.size);
	uintptr_t offset = bruteForce(signature, data);
	MDGameFunctions.StaticFindObject = ((DWORD64)hMD + offset);
	*(PDWORD64)&StaticFindObject = MDGameFunctions.StaticFindObject;

	/*
	signature = ScanData("48 89 5C 24 10 48 89 74 24 18 55 57 41 54 41 56 41 57 48 8D AC 24 50 FF FF FF 48 81 EC B0 01 00 00 48 8B ?? ?? ?? ?? ?? 48 33 C4 48 89 85 A8 00 00 00");
	data = ScanData(0x2000000);
	memcpy(data.data, hMD, data.size);
	offset = bruteForce(signature, data);
	MDGameFunctions.StaticConstructObject = ((DWORD64)hMD + offset);
	*(PDWORD64)&StaticConstructObject = MDGameFunctions.StaticConstructObject;
	*/

	UFunction* isb;
	UFunction* idb;
	UFunction* icv;
	UFunction* itb;

	DWORD64 ptr = 0;
	printf("\n\nFinding the thing that should say 'Yes'....\n");
	while (ptr == 0)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
		ptr = (DWORD64)StaticFindObject((DWORD64)0, (DWORD64)-1, L"TDBPL_IsShippingBuild", true);
	}
	*(PDWORD64)&isb = ptr;

	ptr = 0;
	printf("Finding the things that should say 'No'....\n");
	while (ptr == 0)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
		ptr = (DWORD64)StaticFindObject((DWORD64)0, (DWORD64)-1, L"TDBPL_IsDevelopmentBuild", true);
		*(PDWORD64)&idb = ptr;
		
		ptr = (DWORD64)StaticFindObject((DWORD64)0, (DWORD64)-1, L"TDBPL_IsTestBuild", true);
		*(PDWORD64)&itb = ptr;

		ptr = (DWORD64)StaticFindObject((DWORD64)0, (DWORD64)-1, L"/Game/Blueprints/GI_MedievalDynasty.GI_MedievalDynasty_C:IsCheatVersion", true);
		*(PDWORD64)&icv = ptr;
	}
	ptr = 0;
	

	ptr = 0;
	printf("Waiting for the universe to spring forth from nothingness....\n\n");
	while (ptr == 0)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
		ptr = (DWORD64)StaticFindObject((DWORD64)0, (DWORD64)0, L"/Game/Blueprints/GI_MedievalDynasty.Default__GI_MedievalDynasty_C", false);
	}

	
	*(PDWORD64)&gi = ptr;
	gi->bDebugModeEnabled = 1;
	gi->TestVersion = 1;
	
	DWORD64 retTrue = isb->fptr;
	DWORD64 retFalse = idb->fptr;

	printf("Making the thing that should say 'Yes' say 'No'.\n");
	isb->fptr = retFalse;
	printf("Making the things that should say 'No' say 'Yes'.\n");
	icv->fptr = retTrue;
	idb->fptr = retTrue;
	itb->fptr = retTrue;

	//printf("Asking the universe nicely for unlimited cosmic power.\n");



	ptr = 0;
	printf("Waiting for the copied GI.....\n\n");
	while (ptr == 0)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
		ptr = (DWORD64)StaticFindObject((DWORD64)0, (DWORD64)0, L"/Engine/Transient.GameEngine_2147482624:GI_MedievalDynasty_C_2147482607", false);
	}

	*(PDWORD64)&cgi = ptr;
	
	printf("gi: %llx\n", (INT64)gi);
	printf("cgi: %llx\n", (INT64)cgi);

	cgi->bDebugModeEnabled = 1;
	cgi->TestVersion = 1;

	//_beginthread(&hotkeyThread, 0, 0);


	ptr = 0;
	printf("Waiting for DebugWidget\n\n");
	std::this_thread::sleep_for(std::chrono::milliseconds(7500));
	while (gi->DebugWidget == 0)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
	cgi->DebugWidget = gi->DebugWidget;



	int err = GetLastError();
	if (err == 0)
	{
		printf("\n\nNo errors detected.\nCheat Menu should now be available after loading/starting a game and pressing ESC.\n");
	}
	else
	{
		printf("\n\nError %d reported.  No clue what this means, let Wulf know the details.\n", err);
	}
	printf("\nThis window will disappear shortly after the game exits.\n");

}
DLLEXPORT void __cdecl hotkeyThread(void*)
{
	//printf("hotkeyThread() called\n");

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



			//cgi->gi1 = gi->gi1;
			//cgi->gi2 = gi->gi2;
			//cgi->gi3 = gi->gi3;
			//cgi->gi4 = gi->gi4;
			//cgi->gi5 = gi->gi5;
			if (cgi)
			{
				cgi->DebugWidget = gi->DebugWidget;
			}
			
			


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
				//bRunning = false;
			}
			


			if (hk_Num2 & 0x8000) 
			{
				if (hk_Num2_Pressed == false) 
				{
					hk_Num2_Pressed = true;
					/*


					HANDLE hMD = GetModuleHandleA(GetProcessName(::_getpid()));


					if (!hMD)
					{
						printf("ERROR: Getting handle to game\n");
						return;
					}

					printf("Handle: %p\n", hMD);
					printf("Base: %llx\n", (INT64)hMD);
					//AoB signature courtesy of SunBeam
					ScanData signature = ScanData("48 89 5C 24 ? 48 89 74 24 ? 55 57 41 54 41 56 41 57 48 8B EC 48 83 EC ? 80 3D ? ? ? ? 00 45 0F B6 F1 49 8B F8 48 8B DA 4C 8B F9 74");
					ScanData data = ScanData(0x2000000);

					memcpy(data.data, hMD, data.size);
					uintptr_t offset = bruteForce(signature, data);

					MDGameFunctions.StaticFindObject = ((DWORD64)hMD + offset);
					printf("staticfind: %llx\n", MDGameFunctions.StaticFindObject);
					*(PDWORD64)&StaticFindObject = MDGameFunctions.StaticFindObject;

					UFunction* icv;

					DWORD64 ptr = 0;

					ptr = 0;
					printf("Waiting for IsCheatVersion function to register.\n");
					while (ptr == 0)
					{
						std::this_thread::sleep_for(std::chrono::milliseconds(100));
						ptr = (DWORD64)StaticFindObject((DWORD64)0, (DWORD64)-1, L"GI_MedievalDynasty.IsCheatVersion", true);
					}
					*(PDWORD64)&icv = ptr;

					//printf("icv.fptr: %llx\n", icv->fptr);
					printf("GI_MedievalDynasty.IsCheatVersion:      %llx\n", icv);
					*/

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

