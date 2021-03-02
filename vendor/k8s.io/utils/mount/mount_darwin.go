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

package mount

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"k8s.io/klog"
	utilexec "k8s.io/utils/exec"
)

// Mounter provides the default implementation of mount.Interface
// for the linux platform.  This implementation assumes that the
// kubelet is running in the host's root mount namespace.
type Mounter struct {
	mounterPath string
}

// New returns a mount.Interface for the current system.
// It provides options to override the default mounter behavior.
// mounterPath allows using an alternative to `/bin/mount` for mounting.
func New(mounterPath string) Interface {
	return &Mounter{
		mounterPath: mounterPath,
	}
}

// Mount mounts source to target as fstype with given options. 'source' and 'fstype' must
// be an empty string in case it's not required, e.g. for remount, or for auto filesystem
// type, where kernel handles fstype for you. The mount 'options' is a list of options,
// currently come from mount(8), e.g. "ro", "remount", "bind", etc. If no more option is
// required, call Mount with an empty string list or nil.
func (mounter *Mounter) Mount(source string, target string, fstype string, options []string) error {
	klog.V(2).Infof("Mount %s -> %s (%s %v)", source, target, fstype, options)
	return mounter.MountSensitive(source, target, fstype, options, nil)
}

// MountSensitive is the same as Mount() but this method allows
// sensitiveOptions to be passed in a separate parameter from the normal
// mount options and ensures the sensitiveOptions are never logged. This
// method should be used by callers that pass sensitive material (like
// passwords) as mount options.
func (mounter *Mounter) MountSensitive(source string, target string, fstype string, options []string, sensitiveOptions []string) error {
	klog.V(2).Infof("MountSensitive %s -> %s (%s %v)", source, target, fstype, options)
	mounterPath := ""
	// The list of filesystems that require containerized mounter on GCI image cluster
	fsTypesNeedMounter := map[string]struct{}{
		"nfs":       {},
		"glusterfs": {},
		"ceph":      {},
		"cifs":      {},
	}
	if _, ok := fsTypesNeedMounter[fstype]; ok {
		mounterPath = mounter.mounterPath
	}
	return mounter.doMount(mounterPath, defaultMountCommand, source, target, fstype, options, sensitiveOptions)
}

// doMount runs the mount command. mounterPath is the path to mounter binary if containerized mounter is used.
// sensitiveOptions is an extention of options except they will not be logged (because they may contain sensitive material)
func (mounter *Mounter) doMount(mounterPath string, mountCmd string, source string, target string, fstype string, options []string, sensitiveOptions []string) error {
	klog.V(2).Infof("doMount %s %s %s -> %s (%s %v)", mounterPath, mountCmd, source, target, fstype, options)

	if fstype == "tmpfs" {
		fstype = "hfs"
		// Create a 1MB ramdisk.
		out, err := exec.Command("hdiutil", "attach", "-nomount", "ram://2000").CombinedOutput()
		if err != nil {
			return err
		}
		source = strings.Trim(string(out), " \t\r\n")
		out, err = exec.Command("newfs_hfs", source).CombinedOutput()
		if err != nil {
			return fmt.Errorf("new_hfs %s: %s %v", source, string(out), err)
		}
		klog.V(2).Infof("using %s %s for tmpfs", source, out)
	}

	mountArgs, mountArgsLogStr := MakeMountArgsSensitive(source, target, fstype, options, sensitiveOptions)
	if len(mounterPath) > 0 {
		mountArgs = append([]string{mountCmd}, mountArgs...)
		mountArgsLogStr = mountCmd + " " + mountArgsLogStr
		mountCmd = mounterPath
	}

	// Logging with sensitive mount options removed.
	klog.V(2).Infof("Mounting cmd (%s) with arguments (%s)", mountCmd, mountArgsLogStr)
	command := exec.Command(mountCmd, mountArgs...)
	output, err := command.CombinedOutput()
	if err != nil {
		klog.Errorf("Mount failed: %v\nMounting command: %s\nMounting arguments: %s\nOutput: %s\n", err, mountCmd, mountArgsLogStr, string(output))
		return fmt.Errorf("mount failed: %v\nMounting command: %s\nMounting arguments: %s\nOutput: %s",
			err, mountCmd, mountArgsLogStr, string(output))
	}
	// add .metadata_never_index file to prevent mds opening files on this volume
	touchCmd := exec.Command("touch", filepath.Join(target, ".metadata_never_index"))
	output, err = touchCmd.CombinedOutput()
	if err != nil {
		klog.Warningf("cannot create .metadata_never_index on %s : %v", target, err)
		err = nil
	}

	return err
}

// MakeMountArgs makes the arguments to the mount(8) command.
// options MUST not contain sensitive material (like passwords).
func MakeMountArgs(source, target, fstype string, options []string) (mountArgs []string) {
	mountArgs, _ = MakeMountArgsSensitive(source, target, fstype, options, nil /* sensitiveOptions */)
	klog.V(2).Infof("mountArgs %v", mountArgs)
	return mountArgs
}

// MakeMountArgsSensitive makes the arguments to the mount(8) command.
// sensitiveOptions is an extention of options except they will not be logged (because they may contain sensitive material)
func MakeMountArgsSensitive(source, target, fstype string, options []string, sensitiveOptions []string) (mountArgs []string, mountArgsLogStr string) {
	klog.V(2).Infof("MakeMountArgsSensitive %s -> %s (%s %v)", source, target, fstype, options)
	// Build mount command as follows:
	//   mount [-t $fstype] [-o $options] [$source] $target
	mountArgs = []string{}
	mountArgsLogStr = ""
	if len(fstype) > 0 {
		mountArgs = append(mountArgs, "-t", fstype)
		mountArgsLogStr += strings.Join(mountArgs, " ")
	}
	if len(options) > 0 || len(sensitiveOptions) > 0 {
		combinedOptions := []string{}
		combinedOptions = append(combinedOptions, options...)
		combinedOptions = append(combinedOptions, sensitiveOptions...)
		mountArgs = append(mountArgs, "-o", strings.Join(combinedOptions, ","))
		// exclude sensitiveOptions from log string
		mountArgsLogStr += " -o " + sanitizedOptionsForLogging(options, sensitiveOptions)
	}
	if len(source) > 0 {
		mountArgs = append(mountArgs, source)
		mountArgsLogStr += " " + source
	}
	mountArgs = append(mountArgs, target)
	mountArgsLogStr += " " + target

	return mountArgs, mountArgsLogStr
}

// Unmount unmounts the target.
func (mounter *Mounter) Unmount(target string) error {
	klog.V(2).Infof("Unmounting %s", target)

	// Detach the device if it is a ramdisk.
	out, err := exec.Command("df", target).CombinedOutput()
	if err == nil {
		lines := strings.Split(string(out), "\n")
		lastLine := lines[len(lines)-1]
		fields := strings.Fields(lastLine)
		device := fields[0]
		klog.V(2).Infof("checking %s before unmount %s", device, target)
		out, err = exec.Command("hdiutil", "detach", device).CombinedOutput()
		if err != nil {
			klog.Warningf("detaching %s for %s: %v; output: %s", device, target, err, string(out))
		}
	}

	command := exec.Command("diskutil", "umount", target)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("unmount failed: %v\nUnmounting arguments: %s\nOutput: %s", err, target, string(output))
	}
	// diskutil eraseVolume
	// "A pseudo-format of "free" or "Free Space" will
	// remove the partition altogether, leaving a free space gap in the partition map."
	cmd := exec.Command("diskutil", "eraseVolume", "free", "free", target)
	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error erasing volume %s : %v", target, err)
	}
	return nil
}

// List returns a list of all mounted filesystems.
func (mounter *Mounter) List() ([]MountPoint, error) {
	klog.V(2).Infof("List")
	out, err := exec.Command("mount").CombinedOutput()
	if err != nil {
		_, isExitError := err.(utilexec.ExitError)
		switch {
		case err == utilexec.ErrExecutableNotFound:
			klog.Warningf("'mount' not found on system")
		case isExitError:
			klog.Infof("`mount` error %s", string(out))
		}
		return nil, err
	}

	lines := strings.Split(string(out), "\n")
	mountPoints := make([]MountPoint, 0, len(lines))
	for _, line := range lines {
		// Example: `/dev/disk1s5 on / (apfs, local, read-only, journaled)`
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Options.
		if len(fields[3]) < 2 {
			continue
		}
		options := fields[3][1 : len(fields[3])-2]
		optionsList := strings.Split(options, ",")
		if len(optionsList) < 1 {
			continue
		}

		mp := MountPoint{
			Device: fields[0],
			Path:   fields[2],
			Type:   optionsList[0],
			Opts:   optionsList[1:],
		}

		mountPoints = append(mountPoints, mp)
	}

	return mountPoints, nil
}

// IsLikelyNotMountPoint determines if a directory is not a mountpoint.
// It is fast but not necessarily ALWAYS correct.
func (mounter *Mounter) IsLikelyNotMountPoint(file string) (bool, error) {
	klog.V(2).Infof("IsLikelyNotMountPoint %s", file)
	stat, err := os.Stat(file)
	if err != nil {
		klog.Errorf("IsLikelyNotMountPoint %s: %v", file, err)
		return true, err
	}
	rootStat, err := os.Stat(filepath.Dir(strings.TrimSuffix(file, "/")))
	if err != nil {
		klog.Errorf("IsLikelyNotMountPoint %s: %v", file, err)
		return true, err
	}
	// If the directory has a different device as parent, then it is a mountpoint.
	if stat.Sys().(*syscall.Stat_t).Dev != rootStat.Sys().(*syscall.Stat_t).Dev {
		klog.V(2).Infof("IsLikelyNotMountPoint %s: false", file)
		return false, nil
	}

	klog.V(2).Infof("IsLikelyNotMountPoint %s: true", file)
	return true, nil
}

// GetMountRefs finds all mount references to pathname, returns a
// list of paths. Path could be a mountpoint or a normal
// directory (for bind mount).
func (mounter *Mounter) GetMountRefs(pathname string) ([]string, error) {
	klog.V(2).Infof("GetMountRefs %s", pathname)
	pathExists, pathErr := PathExists(pathname)
	if !pathExists {
		return []string{}, nil
	} else if IsCorruptedMnt(pathErr) {
		klog.Warningf("GetMountRefs found corrupted mount at %s, treating as unmounted path", pathname)
		return []string{}, nil
	} else if pathErr != nil {
		return nil, fmt.Errorf("error checking path %s: %v", pathname, pathErr)
	}
	realpath, err := filepath.EvalSymlinks(pathname)
	if err != nil {
		return nil, err
	}
	return []string{realpath}, nil
}

// checkAndRepairFileSystem checks and repairs filesystems using command fsck.
func (mounter *SafeFormatAndMount) checkAndRepairFilesystem(source string) error {
	klog.V(2).Infof("Checking for issues with fsck on disk: %s", source)
	args := []string{"-p", source}
	out, err := mounter.Exec.Command("fsck", args...).CombinedOutput()
	if err != nil {
		_, isExitError := err.(utilexec.ExitError)
		switch {
		case err == utilexec.ErrExecutableNotFound:
			klog.Warningf("'fsck' not found on system; continuing mount without running 'fsck'.")
		case isExitError:
			klog.Infof("`fsck` error %s", string(out))
		}
	}
	return nil
}

// formatAndMount uses unix utils to format and mount the given disk
func (mounter *SafeFormatAndMount) formatAndMountSensitive(source string, target string, fstype string, options []string, sensitiveOptions []string) error {
	readOnly := false
	for _, option := range options {
		if option == "ro" {
			readOnly = true
			break
		}
	}
	if !readOnly {
		// Check sensitiveOptions for ro
		for _, option := range sensitiveOptions {
			if option == "ro" {
				readOnly = true
				break
			}
		}
	}

	options = append(options, "defaults")
	mountErrorValue := UnknownMountError

	// Check if the disk is already formatted
	existingFormat, err := mounter.GetDiskFormat(source)
	if err != nil {
		return NewMountError(GetDiskFormatFailed, "failed to get disk format of disk %s: %v", source, err)
	}

	// Use 'ext4' as the default
	if len(fstype) == 0 {
		fstype = "hfs"
	}

	if existingFormat == "" {
		// Do not attempt to format the disk if mounting as readonly, return an error to reflect this.
		if readOnly {
			return NewMountError(UnformattedReadOnly, "cannot mount unformatted disk %s as we are manipulating it in read-only mode", source)
		}

		// Disk is unformatted so format it.
		args := []string{source}

		klog.Infof("Disk %q appears to be unformatted, attempting to format as type: %q with options: %v", source, fstype, args)
		output, err := mounter.Exec.Command("newfs_"+fstype, args...).CombinedOutput()
		if err != nil {
			// Do not log sensitiveOptions only options
			sensitiveOptionsLog := sanitizedOptionsForLogging(options, sensitiveOptions)
			detailedErr := fmt.Sprintf("format of disk %q failed: type:(%q) target:(%q) options:(%q) errcode:(%v) output:(%v) ", source, fstype, target, sensitiveOptionsLog, err, string(output))
			klog.Error(detailedErr)
			return NewMountError(FormatFailed, detailedErr)
		}

		klog.Infof("Disk successfully formatted (newfs): %s - %s %s", fstype, source, target)
	} else {
		if fstype != existingFormat {
			// Verify that the disk is formatted with filesystem type we are expecting
			mountErrorValue = FilesystemMismatch
			klog.Warningf("Configured to mount disk %s as %s but current format is %s, things might break", source, existingFormat, fstype)
		}

		if !readOnly {
			// Run check tools on the disk to fix repairable issues, only do this for formatted volumes requested as rw.
			err := mounter.checkAndRepairFilesystem(source)
			if err != nil {
				return err
			}
		}
	}

	// Mount the disk
	klog.V(2).Infof("Attempting to mount disk %s in %s format at %s", source, fstype, target)
	if err := mounter.MountSensitive(source, target, fstype, options, sensitiveOptions); err != nil {
		return NewMountError(mountErrorValue, err.Error())
	}

	return nil
}

// GetDiskFormat uses 'blkid' to see if the given disk is unformatted
func (mounter *SafeFormatAndMount) GetDiskFormat(disk string) (string, error) {
	klog.V(2).Infof("GetDiskFormat %s", disk)
	out, err := mounter.Exec.Command("diskutil", "info", disk).CombinedOutput()
	if err != nil {
		return "", err
	}

	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}

		if fields[0] == "Type" && fields[1] == "(Bundle):" {
			return fields[2], nil
		}
	}

	return "", fmt.Errorf("unable to find disk %s", disk)
}
