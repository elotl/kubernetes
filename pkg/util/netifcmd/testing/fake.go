/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package testing

import (
	"net"

	"k8s.io/kubernetes/pkg/util/netifcmd"
)

// FakeNetsh is a no-op implementation of the netsh Interface
type FakeNetsh struct {
}

// NewFake returns a fakenetsh no-op implementation of the netsh Interface
func NewFake() *FakeNetsh {
	return &FakeNetsh{}
}

// EnsureIPAddress checks if the specified IP Address is added to vEthernet (HNSTransparent) interface, if not, add it.  If the address existed, return true.
func (*FakeNetsh) EnsureIPAddress(_ net.IP) (bool, error) {
	return true, nil
}

// DeleteIPAddress checks if the specified IP address is present and, if so, deletes it.
func (*FakeNetsh) DeleteIPAddress(_ net.IP) error {
	// Do Nothing
	return nil
}

var _ = netifcmd.Interface(&FakeNetsh{})
