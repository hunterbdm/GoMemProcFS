package vmm

import (
	"C"
)

// Just for reference
//type (
//	BOOL          uint32
//	BOOLEAN       byte
//	BYTE          byte
//	DWORD         uint32
//	DWORD64       uint64
//	HANDLE        uintptr
//	HLOCAL        uintptr
//	LARGE_INTEGER int64
//	LONG          int32
//	LPVOID        uintptr
//	SIZE_T        uintptr
//	UINT          uint32
//	ULONG_PTR     uintptr
//	ULONG64       uint64
//	WORD          uint16
//	LPSTR         *uint8
//	QWORD         uint64
//)

type ModuleEntry struct {
	VaBase        uint64
	VaEntry       uint64
	CbImageSize   uint32
	UszText       *uint8
	reserved3     uint32
	reserved4     uint32
	UszFullName   *uint8
	tp            int32
	CbFileSizeRaw uint32
	CSection      uint32
	CEAT          uint32
	CIAT          uint32

	reserved2 uint32
	reserved1 [2]uint64
}
