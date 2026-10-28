package vmprotect

/*
#include <stdbool.h>
#include <stdlib.h>
#include "VMProtectSDK.h"
#cgo amd64 LDFLAGS: -L./ -lVMProtectSDK64
#cgo 386 LDFLAGS: -L./ -lVMProtectSDK32
*/
import "C"

import (
	"unsafe"
	"time"
)

func IsProtected() bool {
	return bool(C.VMProtectIsProtected())
}

func IsDebuggerPresent(kernel bool) bool {
	return bool(C.VMProtectIsDebuggerPresent(C.bool(kernel)))
}

func IsVirtualMachinePresent() bool {
	return bool(C.VMProtectIsVirtualMachinePresent())
}

func IsValidImageCRC() bool {
	return bool(C.VMProtectIsValidImageCRC())
}

const (
	SERIAL_STATE_SUCCESS                = 0
	SERIAL_STATE_FLAG_CORRUPTED         = 0x00000001
	SERIAL_STATE_FLAG_INVALID           = 0x00000002
	SERIAL_STATE_FLAG_BLACKLISTED       = 0x00000004
	SERIAL_STATE_FLAG_DATE_EXPIRED      = 0x00000008
	SERIAL_STATE_FLAG_RUNNING_TIME_OVER = 0x00000010
	SERIAL_STATE_FLAG_BAD_HWID          = 0x00000020
	SERIAL_STATE_FLAG_MAX_BUILD_EXPIRED = 0x00000040
)

func SetSerialNumber(serial string) int {
	cserial := C.CString(serial)
	defer C.free(unsafe.Pointer(cserial))
	return int(C.VMProtectSetSerialNumber(cserial))
}

func GetSerialNumberState() int {
	return int(C.VMProtectGetSerialNumberState())
}

type SerialNumberData struct {
	State                int
	UserName, EMail      string
	Expire, MaxBuild     time.Time
	RunningTime          int
	UserData             []byte
}

func GetSerialNumberData() SerialNumberData {
	var data SerialNumberData
	var sd C.VMProtectSerialNumberData
	if C.VMProtectGetSerialNumberData(&sd, C.sizeof_VMProtectSerialNumberData) {
		data.State = int(sd.nState)
		for _, v := range sd.wUserName {
			if v == 0 {
				break
			}
			data.UserName += string(v)
		}
		for _, v := range sd.wEMail {
			if v == 0 {
				break
			}
			data.EMail += string(v)
		}
		if sd.dtExpire.wYear != 0 || sd.dtExpire.bMonth != 0 || sd.dtExpire.bDay != 0 {
			data.Expire = time.Date(int(sd.dtExpire.wYear), time.Month(sd.dtExpire.bMonth), int(sd.dtExpire.bDay), 0, 0, 0, 0, time.Local)
		}
		if sd.dtMaxBuild.wYear != 0 || sd.dtMaxBuild.bMonth != 0 || sd.dtMaxBuild.bDay != 0 {
			data.MaxBuild = time.Date(int(sd.dtMaxBuild.wYear), time.Month(sd.dtMaxBuild.bMonth), int(sd.dtMaxBuild.bDay), 0, 0, 0, 0, time.Local) 
		}
		data.RunningTime = int(sd.bRunningTime)
		data.UserData = make([]byte, sd.nUserDataLength)
        	for i := 0; i < int(sd.nUserDataLength); i++ {
			data.UserData[i] = byte(sd.bUserData[i])
		}
	}
	return data
}

func GetCurrentHWID() string {
	size := C.VMProtectGetCurrentHWID(nil, 0)
	buf := make([]byte, size)
	hwid := (*C.char)(unsafe.Pointer(&buf[0]))
	C.VMProtectGetCurrentHWID(hwid, size)
	return C.GoStringN(hwid, size)
}