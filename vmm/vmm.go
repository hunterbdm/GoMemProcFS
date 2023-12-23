package vmm

import (
	"C"
	"log"
	"os"
	"syscall"
	"unsafe"
)

var (
	initialize               *syscall.Proc
	procClose                *syscall.Proc
	closeAll                 *syscall.Proc
	pidGetFromName           *syscall.Proc
	procMapGetModuleFromName *syscall.Proc
	procGetProcAddressU      *syscall.Proc
	procMemRead              *syscall.Proc
	procMemWrite             *syscall.Proc
	procMemReadEx            *syscall.Proc
)

const VMMDLL_FLAG_NOCACHE = uint64(0x0001)                 // do not use the data cache (force reading from memory acquisition device)
const VMMDLL_FLAG_ZEROPAD_ON_FAIL = uint64(0x0002)         // zero pad failed physical memory reads and report success if read within range of physical memory.
const VMMDLL_FLAG_FORCECACHE_READ = uint64(0x0008)         // force use of cache - fail non-cached pages - only valid for reads, invalid with VMM_FLAG_NOCACHE/VMM_FLAG_ZEROPAD_ON_FAIL.
const VMMDLL_FLAG_NOPAGING = uint64(0x0010)                // do not try to retrieve memory from paged out memory from pagefile/compressed (even if possible)
const VMMDLL_FLAG_NOPAGING_IO = uint64(0x0020)             // do not try to retrieve memory from paged out memory if read would incur additional I/O (even if possible).
const VMMDLL_FLAG_NOCACHEPUT = uint64(0x0100)              // do not write back to the data cache upon successful read from memory acquisition device.
const VMMDLL_FLAG_CACHE_RECENT_ONLY = uint64(0x0200)       // only fetch from the most recent active cache region when reading.
const VMMDLL_FLAG_NO_PREDICTIVE_READ = uint64(0x0400)      // do not perform additional predictive page reads (default on smaller requests).
const VMMDLL_FLAG_FORCECACHE_READ_DISABLE = uint64(0x0800) // disable/override any use of VMM_FLAG_FORCECACHE_READ. only recommended for local files. improves forensic artifact order.

func init() {
	workingDir, _ := os.Getwd()

	// Must load leechcore.dll before vmm.dll
	_, err := syscall.LoadDLL(workingDir + "\\lib\\leechcore.dll")
	if err != nil {
		log.Fatal(err.Error())
	}
	vmmDll, err := syscall.LoadDLL(workingDir + "\\lib\\vmm.dll")
	if err != nil {
		log.Fatal(err.Error())
	}

	initialize = vmmDll.MustFindProc("VMMDLL_Initialize")
	procClose = vmmDll.MustFindProc("VMMDLL_Close")
	closeAll = vmmDll.MustFindProc("VMMDLL_CloseAll")
	pidGetFromName = vmmDll.MustFindProc("VMMDLL_PidGetFromName")
	procMapGetModuleFromName = vmmDll.MustFindProc("VMMDLL_Map_GetModuleFromNameU")
	procGetProcAddressU = vmmDll.MustFindProc("VMMDLL_ProcessGetProcAddressU")
	procMemRead = vmmDll.MustFindProc("VMMDLL_MemRead")
	procMemWrite = vmmDll.MustFindProc("VMMDLL_MemWrite")
	procMemReadEx = vmmDll.MustFindProc("VMMDLL_MemReadEx")
}

// Initialize is VMM_HANDLE VMMDLL_Initialize(_In_ DWORD argc, _In_ LPSTR argv[]);
func Initialize(argc uint32, argv []string) uintptr {
	var args []*uint8
	for i := range argv {
		args = append(args, toCharPtr(argv[i]))
	}

	h, _, _ := initialize.Call(uintptr(argc), uintptr(unsafe.Pointer(&args[0])))

	return h
}

// Close is VOID VMMDLL_Close(_In_opt_ _Post_ptr_invalid_ VMM_HANDLE hVMM);
func Close(handle uintptr) bool {
	r1, _, _ := procClose.Call(handle)
	return r1 == 1
}

// CloseAll is VOID VMMDLL_Close(_In_opt_ _Post_ptr_invalid_ VMM_HANDLE hVMM);
func CloseAll() bool {
	r1, _, _ := closeAll.Call()
	return r1 == 1
}

// PidGetFromName is BOOL VMMDLL_PidGetFromName(_In_ VMM_HANDLE hVMM, _In_ LPSTR szProcName, _Out_ PDWORD pdwPID);
func PidGetFromName(handle uintptr, procName string) uint32 {
	var result uint32

	_, _, _ = pidGetFromName.Call(handle,
		uintptr(unsafe.Pointer(toCharPtr(procName))),
		uintptr(unsafe.Pointer(&result)))

	return result
}

// MapGetModuleFromName is BOOL VMMDLL_Map_GetModuleFromNameU(
//
//	_In_ VMM_HANDLE hVMM,
//	_In_ DWORD dwPID,
//	_In_opt_ LPSTR wszModuleName,
//	_Out_ PVMMDLL_MAP_MODULEENTRY *ppModuleMapEntry);
func MapGetModuleFromName(handle uintptr, pid uint32, moduleName string) *ModuleEntry {
	var result *ModuleEntry

	r1, _, _ := procMapGetModuleFromName.Call(handle,
		uintptr(pid),
		uintptr(unsafe.Pointer(toCharPtr(moduleName))),
		uintptr(unsafe.Pointer(&result)))

	if r1 == 0 {
		return nil
	}

	return result
}

// GetProcAddress is ULONG64 VMMDLL_ProcessGetProcAddressU(
//
// _In_ VMM_HANDLE hVMM,
// _In_ DWORD dwPID,
// _In_ LPSTR  uszModuleName,
// _In_ LPSTR szFunctionName);
func GetProcAddress(handle uintptr, pid uint32, moduleName string, funcName string) uintptr {
	var result uintptr

	r1, _, _ := procGetProcAddressU.Call(handle,
		uintptr(pid),
		uintptr(unsafe.Pointer(toCharPtr(moduleName))),
		uintptr(unsafe.Pointer(toCharPtr(funcName))),
		uintptr(unsafe.Pointer(&result)))

	if r1 == 0 {
		return 0x0
	}

	return result
}

// MemRead is BOOL VMMDLL_MemRead(
//
//	_In_ VMM_HANDLE hVMM,
//	_In_ DWORD dwPID,
//	_In_ ULONG64 qwA,
//	_Out_writes_(cb) PBYTE pb,
//	_In_ DWORD cb);
func MemRead(handle uintptr, pid uint32, offset uintptr, out uintptr, size uintptr) bool {
	ok, _, _ := procMemRead.Call(handle,
		uintptr(pid),
		offset,
		out,
		size,
	)

	return ok == 1
}

// MemWrite is BOOL VMMDLL_MemWrite(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _In_ ULONG64 qwA, _In_reads_(cb) PBYTE pb, _In_ DWORD cb);
func MemWrite(handle uintptr, pid uint32, offset uintptr, in uintptr, size uintptr) bool {
	ok, _, _ := procMemWrite.Call(handle,
		uintptr(pid),
		offset,
		in,
		size,
	)

	return ok == 1
}

// MemReadEx is BOOL VMMDLL_MemRead(
//
//	_In_ VMM_HANDLE hVMM,
//	_In_ DWORD dwPID,
//	_In_ ULONG64 qwA,
//	_Out_writes_(cb) PBYTE pb,
//	_In_ DWORD cb,
//	_Out_opt_ PDWORD pcbReadOpt,
//	_In_ ULONG64 flags);
func MemReadEx(handle uintptr, pid uint32, offset uintptr, out uintptr, size uintptr, flags uintptr) bool {
	ok, _, _ := procMemReadEx.Call(handle,
		uintptr(pid),
		offset,
		out,
		size,
		0,
		flags,
	)

	return ok == 1
}
