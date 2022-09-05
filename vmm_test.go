package GoMemProcFS

import (
	"fmt"
	"github.com/hunterbdm/GoMemProcFS/vmm"
	"log"
	"testing"
	"unsafe"
)

var processName = "RustClient.exe"
var moduleName = "GameAssembly.dll"

func TestFPGA(t *testing.T) {
	vmm.LoadVMMDLL()

	// Test Initialize
	handle := vmm.Initialize(3, []string{
		"", "-device", "FPGA",
	})
	if handle == 0 {
		t.Error("Failed Initialize")
	} else {
		fmt.Println("vmm.dll Initialized: ", handle)
	}

	// Get Process PID
	pid := vmm.PidGetFromName(handle, processName)
	if pid == 0 {
		t.Error("Failed getting PID")
	} else {
		fmt.Println("Got Process ID: ", pid)
	}

	// Get Module from Name
	module := vmm.MapGetModuleFromName(handle, pid, moduleName)
	if module == nil || module.VaBase == 0 {
		t.Error("Failed getting module")
	} else {
		fmt.Println("Got Module Base: ", fmt.Sprintf("0x%x", module.VaBase))
	}

	// Try mem read
	var out [10]byte
	ok := vmm.MemRead(handle, pid,
		uintptr(module.VaBase),
		uintptr(unsafe.Pointer(&out)),
		unsafe.Sizeof(out))
	if !ok {
		t.Error("Failed MemRead")
	} else {
		fmt.Println("Read Memory: ", out)
	}

	// Try mem write
	var in = [10]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	ok = vmm.MemWrite(handle, pid,
		uintptr(module.VaBase),
		uintptr(unsafe.Pointer(&in)),
		unsafe.Sizeof(in))
	if !ok {
		t.Error("Failed MemWrite")
	} else {
		fmt.Println("Wrote Memory: ", in)
	}

	// Test Close
	if !vmm.Close(handle) {
		t.Error("Failed Close")
	}

	log.Println("Everything Succeeded")
}
