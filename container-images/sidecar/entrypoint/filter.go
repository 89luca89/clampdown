// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// auditArch is the AUDIT_ARCH constant for the native architecture.
var auditArch = func() uint32 {
	switch runtime.GOARCH {
	case "amd64":
		return unix.AUDIT_ARCH_X86_64
	case "arm64":
		return unix.AUDIT_ARCH_AARCH64
	default:
		panic("unsupported GOARCH: " + runtime.GOARCH)
	}
}()

// seccomp_data field offsets (stable kernel ABI).
const (
	dataOffNR   = 0 // offsetof(struct seccomp_data, nr)
	dataOffArch = 4 // offsetof(struct seccomp_data, arch)
)

// seccompNotif is the kernel notification struct (struct seccomp_notif).
// Not provided by x/sys/unix. Size: 80 bytes on both amd64 and arm64.
type seccompNotif struct {
	ID    uint64
	PID   uint32
	Flags uint32
	Data  struct {
		NR                 int32
		Arch               uint32
		InstructionPointer uint64
		Args               [6]uint64
	}
}

// seccompNotifResp is the response struct (struct seccomp_notif_resp).
// Not provided by x/sys/unix.
type seccompNotifResp struct {
	ID    uint64
	Val   int64
	Error int32
	Flags uint32
}

// buildNotifFilter constructs a cBPF program that returns USER_NOTIF for
// the given syscalls, ALLOW for everything else, and KILL_PROCESS on
// architecture mismatch.
//
// Adding a new intercepted syscall = appending one number to the list.
// Jump offsets are computed automatically.
func buildNotifFilter(arch uint32, syscalls []uint32) []unix.SockFilter {
	n := len(syscalls)
	// Layout: [0] load arch, [1] check arch, [2] kill,
	//         [3] load NR, [4..4+n-1] JEQ checks,
	//         [4+n] ALLOW, [4+n+1] USER_NOTIF
	notifIdx := uint32(4 + n + 1)

	filter := make([]unix.SockFilter, 0, notifIdx+1)

	// Load architecture.
	filter = append(filter, unix.SockFilter{
		Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS,
		K:    dataOffArch,
	})
	// Check architecture -- match jumps over kill.
	filter = append(filter, unix.SockFilter{
		Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K,
		Jt:   1, Jf: 0,
		K: arch,
	})
	// Wrong architecture -> kill.
	filter = append(filter, unix.SockFilter{
		Code: unix.BPF_RET | unix.BPF_K,
		K:    unix.SECCOMP_RET_KILL_PROCESS,
	})
	// Load syscall number.
	filter = append(filter, unix.SockFilter{
		Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS,
		K:    dataOffNR,
	})

	// For each intercepted syscall: JEQ -> USER_NOTIF, fall through otherwise.
	for i, nr := range syscalls {
		jt := uint8(notifIdx - uint32(4+i) - 1)
		filter = append(filter, unix.SockFilter{
			Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K,
			Jt:   jt, Jf: 0,
			K: nr,
		})
	}

	// Default: ALLOW.
	filter = append(filter, unix.SockFilter{
		Code: unix.BPF_RET | unix.BPF_K,
		K:    unix.SECCOMP_RET_ALLOW,
	})
	// Intercepted: USER_NOTIF.
	filter = append(filter, unix.SockFilter{
		Code: unix.BPF_RET | unix.BPF_K,
		K:    unix.SECCOMP_RET_USER_NOTIF,
	})

	return filter
}

// installFilter installs the seccomp-notif BPF filter and returns the
// notification file descriptor. Returns -1 if installation fails (caller
// should fall back to exec model).
//
// IMPORTANT: The caller MUST call runtime.LockOSThread() before this
// function and keep the thread locked until after cmd.Start(). Without
// TSYNC, only the calling thread gets the filter -- the child must be
// spawned from this same thread to inherit it.
func installFilter(filter []unix.SockFilter) int {
	prog := unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}

	// PR_SET_NO_NEW_PRIVS is required before installing a seccomp filter.
	// Idempotent if the container runtime already set it.
	err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "seccomp-notif: prctl(NO_NEW_PRIVS) failed: %v\n", err)
		return -1
	}

	flagSets := []struct {
		flags uintptr
		name  string
	}{
		{
			unix.SECCOMP_FILTER_FLAG_NEW_LISTENER | unix.SECCOMP_FILTER_FLAG_TSYNC | unix.SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV,
			"TSYNC|NEW_LISTENER|WAIT_KILLABLE",
		},
		{unix.SECCOMP_FILTER_FLAG_NEW_LISTENER | unix.SECCOMP_FILTER_FLAG_TSYNC, "TSYNC|NEW_LISTENER"},
		{unix.SECCOMP_FILTER_FLAG_NEW_LISTENER, "NEW_LISTENER"},
	}

	for _, fs := range flagSets {
		fd, _, errno := unix.RawSyscall(
			unix.SYS_SECCOMP,
			unix.SECCOMP_SET_MODE_FILTER,
			fs.flags,
			uintptr(unsafe.Pointer(&prog)),
		)
		if errno == 0 {
			fmt.Fprintf(os.Stderr, "seccomp-notif: installed (%s)\n", fs.name)
			runtime.KeepAlive(filter)
			return int(fd)
		}
		fmt.Fprintf(os.Stderr, "seccomp-notif: flags %s failed: %v (errno %d)\n", fs.name, errno, int(errno))
	}

	fmt.Fprintln(os.Stderr, "seccomp-notif: all flag combinations failed, supervisor disabled")
	return -1
}

// seccompNotifSizes queries the kernel for the expected sizes of the
// seccomp_notif and seccomp_notif_resp structs. Returns 0,0 on error.
func seccompNotifSizes() (uint16, uint16) {
	type notifSizes struct {
		Notif     uint16
		NotifResp uint16
		Data      uint16
	}
	var sizes notifSizes
	_, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_GET_NOTIF_SIZES, 0, uintptr(unsafe.Pointer(&sizes)))
	if errno != 0 {
		return 0, 0
	}
	return sizes.Notif, sizes.NotifResp
}

func verifyNotifStructSizes() {
	kNotif, kResp := seccompNotifSizes()
	if kNotif == 0 {
		return
	}
	goNotif := uint16(unsafe.Sizeof(seccompNotif{}))
	goResp := uint16(unsafe.Sizeof(seccompNotifResp{}))
	if kNotif != goNotif || kResp != goResp {
		fmt.Fprintf(os.Stderr, "seccomp-notif: struct size mismatch: kernel notif=%d/%d go=%d/%d\n",
			kNotif, kResp, goNotif, goResp)
		os.Exit(1)
	}
}

// serializeFilter converts the BPF filter to a byte slice for testing.
func serializeFilter(filter []unix.SockFilter) []byte {
	buf := make([]byte, len(filter)*8)
	for i, insn := range filter {
		binary.LittleEndian.PutUint16(buf[i*8:], insn.Code)
		buf[i*8+2] = insn.Jt
		buf[i*8+3] = insn.Jf
		binary.LittleEndian.PutUint32(buf[i*8+4:], insn.K)
	}
	return buf
}

// checkNotifValid checks if a seccomp notification ID is still valid.
// Call AFTER reading path from child memory to tighten the TOCTOU window.
func checkNotifValid(notifFD int, id *uint64) bool {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL,
		uintptr(notifFD),
		uintptr(unix.SECCOMP_IOCTL_NOTIF_ID_VALID),
		uintptr(unsafe.Pointer(id)))
	return errno == 0
}

func sendResp(notifFD int, resp *seccompNotifResp) {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL,
		uintptr(notifFD),
		unix.SECCOMP_IOCTL_NOTIF_SEND,
		uintptr(unsafe.Pointer(resp)))
	if errno != 0 && errno != unix.ENOENT {
		fmt.Fprintf(os.Stderr, "clampdown: %s seccomp-notif: SEND error: %v\n",
			time.Now().UTC().Format(time.RFC3339), errno)
	}
}
