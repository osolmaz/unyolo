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

func activationListeners(names []string) (map[string]interfaceListener, error) {
	listeners := make(map[string]interfaceListener, len(names))
	for _, name := range names {
		listener, err := launchdActivationListener(name)
		if err != nil {
			return nil, closeActivatedListeners(listeners, err)
		}
		listeners[name] = listener
	}
	return listeners, nil
}

func launchdActivationListener(name string) (interfaceListener, error) {
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

func closeActivatedListeners(listeners map[string]interfaceListener, cause error) error {
	values := []error{cause}
	for _, listener := range listeners {
		values = append(values, listener.Close())
	}
	return errors.Join(values...)
}
