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
	procMemRead              *syscall.Proc
	procMemWrite             *syscall.Proc
)

func init() {
	workingDir, _ := os.Getwd()

	// Must load leechcore.dll before vmm.dll
	_, err := syscall.LoadDLL(workingDir + "\\MemProcFS\\leechcore.dll")
	if err != nil {
		log.Fatal(err.Error())
	}
	vmmDll, err := syscall.LoadDLL(workingDir + "\\MemProcFS\\vmm.dll")
	if err != nil {
		log.Fatal(err.Error())
	}

	initialize = vmmDll.MustFindProc("VMMDLL_Initialize")
	procClose = vmmDll.MustFindProc("VMMDLL_Close")
	closeAll = vmmDll.MustFindProc("VMMDLL_CloseAll")
	pidGetFromName = vmmDll.MustFindProc("VMMDLL_PidGetFromName")
	procMapGetModuleFromName = vmmDll.MustFindProc("VMMDLL_Map_GetModuleFromNameU")
	procMemRead = vmmDll.MustFindProc("VMMDLL_MemRead")
	procMemWrite = vmmDll.MustFindProc("VMMDLL_MemWrite")
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

// MemRead is BOOL VMMDLL_MemRead(
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
