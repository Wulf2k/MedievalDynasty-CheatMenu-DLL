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



struct sMDGameAddresses
{
	DWORD64 GUObjectArray;
	DWORD64 NamePoolData;
	DWORD64 StaticFindObject;
};
sMDGameAddresses MDGameAddresses;

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
	uint32_t DebugWidget;
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
	_beginthread(&hotkeyThread, 0, 0);
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









constexpr DWORD64 OFF_UStruct_ChildProperties = 0x50;
constexpr DWORD64 OFF_FField_Next = 0x20;
constexpr DWORD64 OFF_FProperty_Offset_Internal = 0x4C;
struct FField_Layout
{
	void* VTable;
	void* ClassPrivate;
	void* OwnerA;
	void* OwnerB;
	void* Next;
};
int32_t GetNthPropertyOffset(DWORD64 uStructPtr, int index)
{
	DWORD64 node = *(DWORD64*)(uStructPtr + OFF_UStruct_ChildProperties);
	for (int i = 0; i < index; i++)
	{
		if (node == 0)
		{
			printf("ERROR: ChildProperties list ended early at index %d\n", i);
			return -1;
		}
		node = *(DWORD64*)(node + OFF_FField_Next);
	}
	return *(int32_t*)(node + OFF_FProperty_Offset_Internal);
}
struct FUObjectItem
{
	DWORD64 Object;
	int32_t Flags;
	int32_t ClusterRootIndex;
	int32_t SerialNumber;
};

constexpr DWORD64 OFF_ObjObjects = 0x10;
constexpr DWORD64 OFF_Objects_Chunks = 0x00;
constexpr DWORD64 OFF_NumElements = 0x14;
constexpr int      NumElementsPerChunk = 64 * 1024;

DWORD64 FindLiveInstance(DWORD64 guObjectArray, DWORD64 targetClassPtr, DWORD64 excludePtr)
{
	DWORD64 objObjects = guObjectArray + OFF_ObjObjects;
	DWORD64* chunks = *(DWORD64**)(objObjects + OFF_Objects_Chunks);
	int32_t numElements = *(int32_t*)(objObjects + OFF_NumElements);

	for (int i = 0; i < numElements; i++)
	{
		DWORD64 chunkBase = chunks[i / NumElementsPerChunk];
		if (!chunkBase) continue;

		FUObjectItem* item = (FUObjectItem*)(chunkBase + (i % NumElementsPerChunk) * sizeof(FUObjectItem));
		DWORD64 obj = item->Object;
		if (!obj || obj == excludePtr) continue;

		DWORD64 objClass = *(DWORD64*)(obj + 0x10);
		if (objClass == targetClassPtr)
			return obj;
	}
	return 0;
}

struct FNameRaw
{
	uint32_t ComparisonIndex;
	uint32_t Number;
};
struct FWeakObjectPtrRaw { int32_t ObjectIndex; int32_t ObjectSerialNumber; };

struct FSoftObjectPtrRaw
{
	FWeakObjectPtrRaw WeakPtr;
	int32_t TagAtLastTest;
	FNameRaw AssetPathName;
	DWORD64  SubPath_Data;
	int32_t  SubPath_Num;
	int32_t  SubPath_Max;
};

struct FNameEntryHeader
{
	uint16_t bIsWide : 1;
	uint16_t padding : 5;
	uint16_t Len : 10;
};


constexpr DWORD64 OFF_NamePool_Blocks = 0x10;
constexpr DWORD64 OFF_FField_NamePrivate = 0x28;
constexpr int      MaxNamePoolBlocks = 8192;
constexpr int      NamePoolStride = 2;
constexpr int      NamePoolBlockBits = 16;
bool DecodeNameEntryAt(DWORD64 entryAddr, char* outBuf, size_t bufSize, int* outStrideUnits)
{
	FNameEntryHeader header = *(FNameEntryHeader*)entryAddr;
	int len = header.Len;
	if (len == 0 || len >= (int)bufSize) { *outStrideUnits = 1; return false; }

	if (header.bIsWide)
	{
		*outStrideUnits = (2 + len * 2 + (NamePoolStride - 1)) / NamePoolStride;
		return false;
	}

	memcpy(outBuf, (const char*)(entryAddr + 2), len);
	outBuf[len] = 0;
	*outStrideUnits = (2 + len + (NamePoolStride - 1)) / NamePoolStride;
	return true;
}
bool DecodeFName(DWORD64 namePoolData, FNameRaw name, char* outBuf, size_t bufSize)
{
	DWORD64* blocks = (DWORD64*)(namePoolData + OFF_NamePool_Blocks);
	DWORD64 blockBase = blocks[name.ComparisonIndex >> NamePoolBlockBits];
	if (!blockBase) return false;

	DWORD64 entryAddr = blockBase + (name.ComparisonIndex & 0xFFFF) * NamePoolStride;
	int strideUnits = 0;
	return DecodeNameEntryAt(entryAddr, outBuf, bufSize, &strideUnits);
}
FNameRaw FindExistingFName(DWORD64 namePoolData, const char* target)
{
	DWORD64* blocks = (DWORD64*)(namePoolData + OFF_NamePool_Blocks);
	char buf[1024];

	for (uint32_t blockIdx = 0; blockIdx < MaxNamePoolBlocks; blockIdx++)
	{
		DWORD64 blockBase = blocks[blockIdx];
		if (!blockBase) continue;

		uint32_t offsetUnits = 0;
		DWORD64 cursor = blockBase;
		while (cursor < blockBase + 0x20000)
		{
			FNameEntryHeader* header = (FNameEntryHeader*)cursor;
			int strideUnits = 0;
			
			
			if (DecodeNameEntryAt(cursor, buf, sizeof(buf), &strideUnits) && strcmp(buf, target) == 0)
				return { (blockIdx << NamePoolBlockBits) | offsetUnits, 0 };

			cursor += strideUnits * NamePoolStride;
			offsetUnits += strideUnits;
		}
	}

	printf("FindExistingFName: '%s' not found\n", target);
	return { 0, 0 };
}
DWORD64 FindPropertyOffsetByName(DWORD64 namePoolData, DWORD64 uStructPtr, const char* propName)
{
	DWORD64 node = *(DWORD64*)(uStructPtr + OFF_UStruct_ChildProperties);
	char buf[256];
	while (node)
	{
		FNameRaw* name = (FNameRaw*)(node + OFF_FField_NamePrivate);  // 0x28
		if (DecodeFName(namePoolData, *name, buf, sizeof(buf)) && strcmp(buf, propName) == 0)
			return *(int32_t*)(node + OFF_FProperty_Offset_Internal);
		node = *(DWORD64*)(node + OFF_FField_Next);
	}
	printf("FindPropertyOffsetByName: '%s' not found\n", propName);
	return 0;
}








DLLEXPORT void __cdecl initialStuff(void*)
{
	std::this_thread::sleep_for(std::chrono::milliseconds(500));
	printf("pid: %llx\n", ::_getpid());
	printf("ProcessName: %s\n", GetProcessName(::_getpid()));
	HANDLE hMD = 0;
	
	

	while (!hMD)
	{
		hMD = GetModuleHandleA(GetProcessName(::_getpid()));
		std::this_thread::sleep_for(std::chrono::milliseconds(500));
	}


	printf("Handle: %p\n", hMD);
	printf("Base: %llx\n", (INT64)hMD);
	//AoB signature courtesy of SunBeam
	ScanData signature = ScanData("48 89 5C 24 ? 48 89 74 24 ? 55 57 41 54 41 ? 41 57 48 8B EC 48 83 EC ? 80 3D ? ? ? ? 00 45 0F B6 ? 49 8B ? 48 8B ? 4C 8B ? 74");
	ScanData data = ScanData(0x2000000);
	memcpy(data.data, hMD, data.size);
	uintptr_t offset = bruteForce(signature, data);
	MDGameAddresses.StaticFindObject = ((DWORD64)hMD + offset);
	*(PDWORD64)&StaticFindObject = MDGameAddresses.StaticFindObject;


	
	//GUObjectArray
	ScanData objarrSig = ScanData("8B 45 40 85 C0 89 05 ? ? ? ? 0F 9E C1 FF C9 89 0D ? ? ? ?");
	memcpy(data.data, hMD, data.size);
	offset = bruteForce(objarrSig, data);
	DWORD64 matchAddr = (DWORD64)hMD + offset;
	DWORD64 dispAddr = matchAddr + 18; 
	int32_t disp = *(int32_t*)dispAddr;
	DWORD64 nextInstr = matchAddr + 22;
	DWORD64 guObjArray = nextInstr + disp;
	MDGameAddresses.GUObjectArray = guObjArray;
	printf("GUObjectArray: %p\n", guObjArray);


	

	//NamePoolData
	ScanData npdSig = ScanData("48 89 6C 24 48 33 ED 40 38 2D ? ? ? ? 44 8B CD 48 89 6C 24 20 48 89 6C 24 28 74 09 4C 8D 05 ? ? ? ?");
	memcpy(data.data, hMD, data.size);
	offset = bruteForce(npdSig, data);
	matchAddr = (DWORD64)hMD + offset;
	dispAddr = matchAddr + 32;
	disp = *(int32_t*)dispAddr;
	nextInstr = matchAddr + 36; 
	DWORD64 namePoolData = nextInstr + disp;
	MDGameAddresses.NamePoolData = namePoolData;
	printf("NamePoolData: %p\n", namePoolData);
	



	UFunction* isb;
	UFunction* idb;
	UFunction* icv;
	UFunction* itb;
	UFunction* ipie;

	DWORD64 ptr = 0;




	
	



	ptr = 0;
	printf("\n\n********************************                 Finding the thing that should say 'Yes'....\n");
	while (ptr == 0)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
		ptr = (DWORD64)StaticFindObject((DWORD64)0, (DWORD64)-1, L"TDBPL_IsShippingBuild", true);
	}
	*(PDWORD64)&isb = ptr;

	ptr = 0;
	printf("********************************                 Finding the things that should say 'No'....\n");
	while (ptr == 0)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(33));
		ptr = (DWORD64)StaticFindObject((DWORD64)0, (DWORD64)-1, L"TDBPL_IsPlayInEditor", true);
		*(PDWORD64)&ipie = ptr;
	}



	DWORD64 retTrue = isb->fptr;
	//DWORD64 retFalse = idb->fptr;
	//printf("Making the thing that should say 'Yes' say 'No'.\n");
	//isb->fptr = retFalse;
	printf("********************************                 Making the things that should say 'No' say 'Yes'.\n");
	ipie->fptr = retTrue;



	
	ptr = 0;
	printf("********************************                 Waiting for the universe to spring forth from nothingness....\n\n");
	while (ptr == 0)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
		ptr = (DWORD64)StaticFindObject((DWORD64)0, (DWORD64)0, L"/Game/Blueprints/GI_MedievalDynasty.Default__GI_MedievalDynasty_C", false);
	}
	*(PDWORD64)&gi = ptr;






	DWORD64 giClass = 0;
	ptr = 0;
	printf("********************************                 Finding GI_MedievalDynasty_C class....\n");
	while (ptr == 0)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
		ptr = (DWORD64)StaticFindObject((DWORD64)0, (DWORD64)-1, L"GI_MedievalDynasty_C", true);
	}
	giClass = ptr;

	ptr = 0;
	printf("********************************                 Waiting for the live GI instance....\n");
	while (ptr == 0)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(33));
		ptr = FindLiveInstance(MDGameAddresses.GUObjectArray, giClass, (DWORD64)gi);
	}
	*(PDWORD64)&cgi = ptr;
	cgi->bDebugModeEnabled = 1;
	cgi->gi2 = 0;
	cgi->TestVersion = 1;


	printf("********************************                 gi: %llx\n", (INT64)gi);
	printf("********************************                 cgi: %llx\n", (INT64)cgi);



	//_beginthread(&hotkeyThread, 0, 0);
	FNameRaw giName = *(FNameRaw*)((DWORD64)gi + 0x18);
	char buf[256];
	DecodeFName(namePoolData, giName, buf, sizeof(buf));
	printf("********************************                 gi's name decodes to: %s\n", buf);


	FNameRaw cm = FindExistingFName(namePoolData, "/Game/Blueprints/UI/CheatMenu/UI_CheatMenu.UI_CheatMenu_C");
	printf("********************************                 FName for CheatMenu: %x\n", cm.ComparisonIndex);


	gi->DebugWidget = cm.ComparisonIndex;
	gi->bDebugModeEnabled = 1;
	
	cgi->DebugWidget = cm.ComparisonIndex;
	cgi->bDebugModeEnabled = 1;




	




	int err = GetLastError();
	if (err == 0)
	{
		printf("********************************                 No errors detected.\n********************************                 Cheat Menu should now be available after loading/starting a game and pressing ESC.\n");
	}
	else
	{
		printf("********************************                 Error %d reported.  No clue what this means, let Wulf know the details.\n", err);
	}
	printf("********************************                 This window will disappear shortly after the game exits.\n\n\n");

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
				//cgi->DebugWidget = gi->DebugWidget;
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

