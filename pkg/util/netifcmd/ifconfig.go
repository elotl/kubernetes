package netifcmd

import (
	"net"
	"os"

	"k8s.io/klog/v2"
	utilexec "k8s.io/utils/exec"
)

const (
	cmdIfconfig string = "ifconfig"
	cmdSysctl   string = "sysctl"
)

// runner implements Interface in terms of exec("ifconfig").
//
// This implementation is darwin specific, but may work on other platforms.
type ifConfigDarwinRunner struct {
	exec          utilexec.Interface
	checkIPExists func(string, net.IP) (bool, error)
}

// Ensure ifConfigDarwinRunner implements Interface
var _ Interface = &ifConfigDarwinRunner{}

// Returns a new implementation of Interface to execute the Darwin interface management tool: ifconfig.
// Uses the interface defined in INTERFACE_TO_ADD_SERVICE_IP environment variable, if this value is empty uses the interface en0.
func NewIfconfigDarwin(exec utilexec.Interface) (Interface, error) {
	var ipForwardingEnableArgs = []string{"-w", "net.inet.ip.forwarding=1"}
	output, err := exec.Command(cmdSysctl, ipForwardingEnableArgs...).CombinedOutput()
	if err != nil {
		klog.V(3).Infof("sysctl error:\n%s", string(output))
		return nil, err
	}
	runner := &ifConfigDarwinRunner{
		exec:          exec,
		checkIPExists: CheckIPExists,
	}
	return runner, nil
}

func (r *ifConfigDarwinRunner) EnsureIPAddress(ip net.IP) (bool, error) {
	var ifName = r.getInterfaceToAddIP()
	var found, err = CheckIPExists(ifName, ip)
	if found {
		klog.V(3).Infof("%s already assigned to %s", ip, ifName)
	}
	if err != nil || found == true {
		return false, err
	}
	var args = []string{ifName, "alias", ip.String()}
	output, err := r.exec.Command(cmdIfconfig, args...).CombinedOutput()
	if err != nil {
		klog.V(3).Infof("ifconfig error:\n%s", string(output))
		// XXX: This needs works. Check the exit code and the output maybe.
		// What happens if the ip is already attached (race condition)?
		// What happens if there’s another error?
		return false, err
	}
	return true, nil
}

func (r *ifConfigDarwinRunner) DeleteIPAddress(ip net.IP) error {
	var ifName = r.getInterfaceToAddIP()
	var found, err = CheckIPExists(ifName, ip)
	if err != nil {
		return err
	}
	if !found {
		klog.V(3).Infof("%s already deleted from %s", ip, ifName)
		return nil
	}

	var args = []string{ifName, "-alias", ip.String()}
	output, err := r.exec.Command(cmdIfconfig, args...).CombinedOutput()
	if err != nil {
		klog.V(3).Infof("ifconfig error:\n%s", string(output))
		return err
	}
	return nil
}

func CheckIPExists(ifName string, ip net.IP) (bool, error) {
	klog.V(3).Infof("searching for IP %v in interface %v", ip, ifName)
	var iface, err = net.InterfaceByName(ifName)
	if err != nil {
		return false, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		klog.V(3).Error(err, "getting IPs for %s", ifName)
	}
	for _, addr := range addrs {
		if addr.String() == ip.String() {
			// The Address was already added to the interface: we're done
			return true, nil
		}
	}
	return false, err
}

// Return the value of the environment variable INTERFACE_TO_ADD_SERVICE_IP or "en0"
func (r *ifConfigDarwinRunner) getInterfaceToAddIP() string {
	if iface := os.Getenv("INTERFACE_TO_ADD_SERVICE_IP"); len(iface) > 0 {
		return iface
	}
	return "en0"
}
