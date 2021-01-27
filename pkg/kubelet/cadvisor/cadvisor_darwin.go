// +build darwin

/*
Copyright 2021 The Kubernetes Authors.

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

package cadvisor

import (
	"time"

	"github.com/google/cadvisor/events"
	cadvisorapi "github.com/google/cadvisor/info/v1"
	v1 "github.com/google/cadvisor/info/v1"
	cadvisorapiv2 "github.com/google/cadvisor/info/v2"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/mem"
	psnet "github.com/shirou/gopsutil/net"
	"k8s.io/klog"
)

type darwinStats struct {
	timestamp               time.Time
	cpuUsageCoreNanoSeconds uint64
}

type cadvisorDarwin struct {
	rootPath string
	stats    darwinStats
}

var _ Interface = new(cadvisorDarwin)

// New creates a new cAdvisor Interface for darwin.
func New(imageFsInfoProvider ImageFsInfoProvider, rootPath string, cgroupsRoots []string, usingLegacyStats bool) (Interface, error) {
	return &cadvisorDarwin{
		rootPath: rootPath,
	}, nil
}

func (cd *cadvisorDarwin) Start() error {
	return nil
}

func (cd *cadvisorDarwin) DockerContainer(name string, req *cadvisorapi.ContainerInfoRequest) (cadvisorapi.ContainerInfo, error) {
	return cadvisorapi.ContainerInfo{}, nil
}

func (cd *cadvisorDarwin) ContainerInfo(name string, req *cadvisorapi.ContainerInfoRequest) (*cadvisorapi.ContainerInfo, error) {
	return &cadvisorapi.ContainerInfo{}, nil
}

func (cd *cadvisorDarwin) ContainerInfoV2(name string, options cadvisorapiv2.RequestOptions) (map[string]cadvisorapiv2.ContainerInfo, error) {
	return containerInfos(&cd.stats)
}

func (cd *cadvisorDarwin) SubcontainerInfo(name string, req *cadvisorapi.ContainerInfoRequest) (map[string]*cadvisorapi.ContainerInfo, error) {
	return nil, nil
}

func (cd *cadvisorDarwin) MachineInfo() (*cadvisorapi.MachineInfo, error) {
	cpuInfo, err := cpu.Info()
	if err != nil {
		return nil, err
	}
	// Set fallback values.
	numCores := 1
	cpuFrequency := uint64(1000 * 1000) // kHz
	if len(cpuInfo) > 0 {
		numCores = int(cpuInfo[0].Cores)
		cpuFrequency = uint64(cpuInfo[0].Mhz * 1000)
	}

	memInfo, err := mem.VirtualMemory()
	if err != nil {
		return nil, err
	}

	hostInfo, err := host.Info()
	if err != nil {
		return nil, err
	}

	return &cadvisorapi.MachineInfo{
		NumCores:       numCores,
		CpuFrequency:   cpuFrequency,
		MemoryCapacity: memInfo.Total,
		MachineID:      hostInfo.Hostname,
		SystemUUID:     hostInfo.HostID,
	}, nil
}

func (cd *cadvisorDarwin) VersionInfo() (*cadvisorapi.VersionInfo, error) {
	hostInfo, err := host.Info()
	if err != nil {
		return nil, err
	}
	return &cadvisorapi.VersionInfo{
		KernelVersion:      hostInfo.KernelVersion,
		ContainerOsVersion: hostInfo.PlatformVersion,
	}, nil
}

func (cd *cadvisorDarwin) ImagesFsInfo() (cadvisorapiv2.FsInfo, error) {
	return cadvisorapiv2.FsInfo{}, nil
}

func (cd *cadvisorDarwin) RootFsInfo() (cadvisorapiv2.FsInfo, error) {
	return cd.GetDirFsInfo(cd.rootPath)
}

func (cd *cadvisorDarwin) WatchEvents(request *events.Request) (*events.EventChannel, error) {
	return &events.EventChannel{}, nil
}

func (cd *cadvisorDarwin) GetDirFsInfo(path string) (cadvisorapiv2.FsInfo, error) {
	fsInfo := cadvisorapiv2.FsInfo{}

	diskUsage, err := disk.Usage(path)
	if err != nil {
		return fsInfo, err
	}

	fsInfo.Timestamp = time.Now()
	fsInfo.Capacity = uint64(diskUsage.Total)
	fsInfo.Available = uint64(diskUsage.Free)
	fsInfo.Usage = uint64(diskUsage.Used)
	fsInfo.Inodes = &diskUsage.InodesTotal
	fsInfo.InodesFree = &diskUsage.InodesFree

	klog.Infof("%s %v", path, fsInfo)

	return fsInfo, nil
}

func containerInfos(stats *darwinStats) (map[string]cadvisorapiv2.ContainerInfo, error) {
	infos := make(map[string]cadvisorapiv2.ContainerInfo)
	rootContainerInfo, err := createRootContainerInfo(stats)
	if err != nil {
		return nil, err
	}

	infos["/"] = *rootContainerInfo

	return infos, nil
}

func createRootContainerInfo(ds *darwinStats) (*cadvisorapiv2.ContainerInfo, error) {
	now := time.Now()
	cpuStats, err := cpu.Times(true)
	if err != nil {
		return nil, err
	}

	currentCPUUsageCoreNanoSeconds := uint64(0)
	for _, cs := range cpuStats {
		// The only fields used on Darwin besides .Idle.
		total := cs.User + cs.System + cs.Nice
		currentCPUUsageCoreNanoSeconds += uint64(total * 1024 * 1024 * 1024)
	}
	cpuUsageCoreNanoSeconds := currentCPUUsageCoreNanoSeconds
	if ds.cpuUsageCoreNanoSeconds < currentCPUUsageCoreNanoSeconds {
		cpuUsageCoreNanoSeconds = currentCPUUsageCoreNanoSeconds - ds.cpuUsageCoreNanoSeconds
	}
	ds.cpuUsageCoreNanoSeconds = currentCPUUsageCoreNanoSeconds

	cpuUsageNanoCores := uint64(0)
	if len(cpuStats) > 0 {
		cpuUsageNanoCores = uint64(cpuUsageCoreNanoSeconds) / uint64(len(cpuStats))
	}

	memStats, err := mem.VirtualMemory()
	if err != nil {
		return nil, err
	}
	memoryUsage := memStats.Used
	memoryWorkingSet := memStats.Used - memStats.Inactive

	netStats, err := psnet.IOCounters(true)
	if err != nil {
		return nil, err
	}
	interfaceStats := make([]v1.InterfaceStats, len(netStats))
	for i, ns := range netStats {
		interfaceStats[i].Name = ns.Name
		interfaceStats[i].RxBytes = ns.BytesRecv
		interfaceStats[i].TxBytes = ns.BytesSent
		interfaceStats[i].RxPackets = ns.PacketsRecv
		interfaceStats[i].TxPackets = ns.PacketsSent
		interfaceStats[i].RxErrors = ns.Errin
		interfaceStats[i].TxErrors = ns.Errout
		interfaceStats[i].RxDropped = ns.Dropin
		interfaceStats[i].TxDropped = ns.Dropout
	}

	var stats []*cadvisorapiv2.ContainerStats
	stats = append(stats, &cadvisorapiv2.ContainerStats{
		Timestamp: now,
		Cpu: &cadvisorapi.CpuStats{
			Usage: cadvisorapi.CpuUsage{
				Total: cpuUsageCoreNanoSeconds,
			},
		},
		CpuInst: &cadvisorapiv2.CpuInstStats{
			Usage: cadvisorapiv2.CpuInstUsage{
				Total: cpuUsageNanoCores,
			},
		},
		Memory: &cadvisorapi.MemoryStats{
			WorkingSet: memoryWorkingSet,
			Usage:      memoryUsage,
		},
		Network: &cadvisorapiv2.NetworkStats{
			Interfaces: interfaceStats,
		},
	})

	bootTime, err := host.BootTime()
	if err != nil {
		klog.Warningf("host.BootTime(): %v", err)
	}

	rootInfo := cadvisorapiv2.ContainerInfo{
		Spec: cadvisorapiv2.ContainerSpec{
			CreationTime: time.Unix(int64(bootTime), 0),
			HasCpu:       true,
			HasMemory:    true,
			HasNetwork:   true,
			Memory: cadvisorapiv2.MemorySpec{
				Limit: memStats.Total,
			},
		},
		Stats: stats,
	}

	return &rootInfo, nil
}
