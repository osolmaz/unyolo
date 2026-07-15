//go:build linux || darwin

package privexec

import "errors"

type executableDescriptorMetadata struct {
	ownerUID uint32
	mode     uint32
	regular  bool
}

func validateExecutableDescriptor(fd int) error {
	metadata, err := inspectExecutableDescriptor(fd)
	if err != nil {
		return errors.New("inspect executable descriptor")
	}
	if metadata.ownerUID != 0 || !metadata.regular || metadata.mode&0o022 != 0 || metadata.mode&0o111 == 0 {
		return errors.New("executable descriptor is not trusted")
	}
	return nil
}
