//go:build darwin

package endpoint

/*
#cgo LDFLAGS: -framework CoreFoundation
#include <launch.h>
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

func activationListener(name string) (interfaceListener, error) {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	var descriptors *C.int
	var count C.size_t
	if result := C.launch_activate_socket(cName, &descriptors, &count); result != 0 {
		return nil, fmt.Errorf("launchd activation listener %q is unavailable", name)
	}
	defer C.free(unsafe.Pointer(descriptors))
	if count != 1 || descriptors == nil {
		return nil, errors.New("launchd activation must return exactly one listener")
	}
	return listenerFromFD(int(*descriptors))
}
