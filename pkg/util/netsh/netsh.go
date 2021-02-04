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

package netsh

import "net"

// Provides a way to add and delete virtual IP addresses to the system’s interfaces.
type NetworkInterface interface {
	// Add IP address to the appropriate system interface. Does nothing if the
	// address is already assigned.
	AddIPAddress(net.IP) (bool, error)
	// Delete IP address from the system’s interfaces.
	// XXX: what happens if the IP address isn’t assigned???
	DeleteIPAddress(net.IP) error
}
