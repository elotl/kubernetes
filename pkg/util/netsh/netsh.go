package netsh

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"k8s.io/klog/v2"
	utilexec "k8s.io/utils/exec"
)

const (
	cmdNetsh string = "netsh"
)

// runner implements Interface in terms of exec("netsh").
type runner struct {
	exec utilexec.Interface
}

// Returns a new implementation of Interface to execute the Windows interface management tool: netsh.
func NewNetsh(exec utilexec.Interface) Interface {
	runner := &runner{
		exec: exec,
	}
	return runner
}

// EnsureIPAddress checks if the specified IP Address is added to interface identified by Environment variable INTERFACE_TO_ADD_SERVICE_IP, if not, add it.  If the address existed, return true.
func (runner *runner) AddIPAddress(ip net.IP) (bool, error) {
	// Check if the ip address exists
	intName := runner.getInterfaceToAddIP()
	ipToCheck := ip.String()

	exists, _ := runner.CheckIPExists(ipToCheck, intName)
	if exists == true {
		klog.V(4).Infof("not adding IP address %q as it already exists", ipToCheck)
		return true, nil
	}

	var args = []string{
		"interface", "ipv4", "add", "address", "name=" + intName,
		"address=" + ip.String(),
	}
	// IP Address is not already added, add it now
	klog.V(4).Infof("running netsh interface ipv4 add address %v", args)
	out, err := runner.exec.Command(cmdNetsh, args...).CombinedOutput()

	if err == nil {
		// Once the IP Address is added, it takes a bit to initialize and show up when querying for it
		// Query all the IP addresses and see if the one we added is present
		// PS: We are using netsh interface ipv4 show address here to query all the IP addresses, instead of
		// querying net.InterfaceAddrs() as it returns the IP address as soon as it is added even though it is uninitialized
		klog.V(3).Infof("Waiting until IP: %v is added to the network adapter", ipToCheck)
		for {
			if exists, _ := runner.CheckIPExists(ipToCheck, intName); exists {
				return true, nil
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
	if ee, ok := err.(utilexec.ExitError); ok {
		// netsh uses exit(0) to indicate a success of the operation,
		// as compared to a malformed commandline, for example.
		if ee.Exited() && ee.ExitStatus() != 0 {
			return false, nil
		}
	}
	return false, fmt.Errorf("error adding ipv4 address: %v: %s", err, out)
}

// DeleteIPAddress checks if the specified IP address is present and, if so, deletes it.
func (runner *runner) DeleteIPAddress(ip net.IP) error {
	var intName = runner.getInterfaceToAddIP()
	var args = []string{
		"interface", "ipv4", "delete", "address",
		"name=" + intName,
		"address=" + ip.String(),
	}
	klog.V(4).Infof("running netsh interface ipv4 delete address %v", args)
	out, err := runner.exec.Command(cmdNetsh, args...).CombinedOutput()

	if err == nil {
		return nil
	}
	if ee, ok := err.(utilexec.ExitError); ok {
		// netsh uses exit(0) to indicate a success of the operation,
		// as compared to a malformed commandline, for example.
		if ee.Exited() && ee.ExitStatus() == 0 {
			return nil
		}
	}
	return fmt.Errorf("error deleting ipv4 address: %v: %s", err, out)
}

// GetInterfaceToAddIP returns the interface name where Service IP needs to be added
// IP Address needs to be added for netsh portproxy to redirect traffic
// Reads Environment variable INTERFACE_TO_ADD_SERVICE_IP, if it is not defined then "vEthernet (HNS Internal NIC)" is returned
func (runner *runner) getInterfaceToAddIP() string {
	if iface := os.Getenv("INTERFACE_TO_ADD_SERVICE_IP"); len(iface) > 0 {
		return iface
	}
	return "vEthernet (HNS Internal NIC)"
}

// checkIPExists checks if an IP address exists in 'netsh interface ipv4 show address' output
func (runner *runner) CheckIPExists(ipToCheck string, interfaceName string) (bool, error) {
	args := []string{
		"interface", "ipv4", "show", "address", "name=" + interfaceName,
	}
	ipAddress, err := runner.exec.Command(cmdNetsh, args...).CombinedOutput()
	if err != nil {
		return false, err
	}
	ipAddressString := string(ipAddress[:])
	klog.V(3).Infof("Searching for IP: %v in IP dump: %v", ipToCheck, ipAddressString)
	showAddressArray := strings.Split(ipAddressString, "\n")
	for _, showAddress := range showAddressArray {
		if strings.Contains(showAddress, "IP") {
			ipFromNetsh := getIP(showAddress)
			if ipFromNetsh == ipToCheck {
				return true, nil
			}
		}
	}

	return false, nil
}

// getIP gets ip from showAddress (e.g. "IP Address: 10.96.0.4").
func getIP(showAddress string) string {
	list := strings.SplitN(showAddress, ":", 2)
	if len(list) != 2 {
		return ""
	}
	return strings.TrimSpace(list[1])
}
