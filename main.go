//go:build linux

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"syscall"

	"github.com/containerd/cgroups/v3/cgroup2"
	"github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
)

var rootNetworkNamespace netns.NsHandle
var veth0 string = "veth0"
var veth1 string = "veth1"
var bridge string = "br0"
var namespace string = "net1"

// go run main.go run <cmd> <args>
func main() {
	switch os.Args[1] {
	case "run":
		run()
	case "child":
		child()
	default:
		panic("help")
	}
}

func run() {
	log.Printf("Running %v \n", os.Args[2:])

	setupIpForwarding()

	// this cleanup func needs to run in parent process, since child process is chrooted out of cgroup mount visibility
	defer func() {
		// move current process back into user.slice CG so that custom CG is clear for cleanup
		userCG, err := cgroup2.Load("/user.slice")
		if err != nil {
			log.Printf("Failed to load default user.slice cgroup: %v", err)
			return
		}
		pid := os.Getpid()
		err = userCG.AddProc(uint64(pid))

		cg, err := cgroup2.Load("/user.slice/new_cgroup")
		if err != nil {
			log.Printf("Failed to load cgroup: %v", err)
			return
		}
		err = cg.Delete()
		if err != nil {
			log.Printf("Failed to delete cgroup: %v", err)
		} else {
			log.Println("cgroup deleted successfully")
		}
	}()

	cmd := exec.Command("/proc/self/exe", append([]string{"child"}, os.Args[2:]...)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:   syscall.CLONE_NEWUTS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS | syscall.CLONE_NEWNET,
		Unshareflags: syscall.CLONE_NEWNS,
	}

	must(cmd.Run())
}

func child() {
	log.Printf("Running %v \n", os.Args[2:])

	cg()

	cmd := exec.Command(os.Args[2], os.Args[3:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	must(setupNewNamespace())
	must(syscall.Sethostname([]byte("container")))
	must(syscall.Chroot("/container-test/ubuntu-fs"))
	must(os.Chdir("/"))
	must(syscall.Mount("proc", "proc", "proc", 0, ""))
	// must(syscall.Mount("thing", "mytemp", "tmpfs", 0, ""))

	must(cmd.Run())

	must(syscall.Unmount("proc", 0))
	// must(syscall.Unmount("thing", 0))
}

func cg() {
	cgroupPath := "/user.slice/new_cgroup"

	// check if the cgroup exists, create it if necessary
	if _, err := os.Stat("/sys/fs/cgroup" + cgroupPath); os.IsNotExist(err) {
		err := os.MkdirAll("/sys/fs/cgroup"+cgroupPath, 0755)
		if err != nil {
			log.Fatalf("Failed to create cgroup: %v", err)
		}
	}

	cg, err := cgroup2.Load(cgroupPath)
	if err != nil {
		log.Fatalf("Failed to load cgroup: %v", err)
	}

	// set max number of PIDs in the cgroup to 20
	err = cg.Update(&cgroup2.Resources{Pids: &cgroup2.Pids{Max: 20}})
	if err != nil {
		log.Fatalf("Failed to set pids.max: %v", err)
	}

	pid := os.Getpid()
	err = cg.AddProc(uint64(pid))
	if err != nil {
		log.Fatalf("Failed to add process to cgroup: %v", err)
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

/*
The following shell commands are adapted from "Networking and Kubernetes" by
James Strong and Vallery Lancey, and represent the basis of what our
container runtime is doing. The root namespace setup is handled by setupIpForwarding,
the namespace creation is handled by syscall.CLONE_NEWNET, so all this
function needs to do is create the veth pair, assign IPs and a default route,
and set up DNS resolution

$ sudo sysctl -w net.ipv4.ip_forward=1
$ sudo iptables -t nat -A POSTROUTING -s 10.0.1.0/24 -o $(ip route | grep default | cut -d' ' -f5) -j MASQUERADE
$ sudo ip netns add $$ # PID of current process
$ sudo ip link add veth0 type veth peer name veth1
$ sudo ip addr add 10.0.1.1/24 dev veth0
$ sudo ip link set veth0 up
$ sudo ip link set veth1 netns $$
$ sudo ip netns exec $$ ip addr add 10.0.1.2/24 dev veth1
$ sudo ip netns exec $$ ip link set veth1 up
$ sudo ip netns exec $$ ip link set lo up
$ sudo ip netns exec $$ ip route add default via 10.0.1.1
$ sudo mkdir -p /etc/netns/$$
$ sudo cp /etc/resolv.conf /etc/netns/$$/resolv.conf
$ sudo cp /etc/hosts /etc/netns/$$/hosts
*/
func setupNewNamespace() error {
	// create veth pair and set up
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: veth0},
		PeerName:  veth1,
	}
	if err := netlink.LinkAdd(veth); err != nil {
		return fmt.Errorf("Failed to create veth pair: %v", err)
	}
	linkVeth0, err := netlink.LinkByName(veth0)
	if err != nil {
		return fmt.Errorf("Failed to get veth0 link: %v", err)
	}
	linkVeth1, err := netlink.LinkByName(veth1)
	if err != nil {
		return fmt.Errorf("Failed to get veth1 link: %v", err)
	}
	if err := netlink.LinkSetUp(linkVeth0); err != nil {
		return fmt.Errorf("Failed to set veth0 up: %v", err)
	}
	if err := netlink.LinkSetUp(linkVeth1); err != nil {
		return fmt.Errorf("Failed to set veth1 up: %v", err)
	}

	// assign IPs to veths
	// TODO: add basic dynamic host configuration
	addr, _ := netlink.ParseAddr("10.0.1.1/24")
	if err := netlink.AddrAdd(linkVeth0, addr); err != nil {
		return fmt.Errorf("Failed to assign IP to veth0: %v", err)
	}
	addr, _ = netlink.ParseAddr("10.0.1.2/24")
	if err := netlink.AddrAdd(linkVeth1, addr); err != nil {
		return fmt.Errorf("Failed to assign IP to veth1: %v", err)
	}

	// create default route
	defaultRoute := &netlink.Route{
		Scope: netlink.SCOPE_UNIVERSE,
		Gw:    net.ParseIP("10.0.1.1"),
	}
	if err := netlink.RouteAdd(defaultRoute); err != nil {
		return fmt.Errorf("Failed to add default route: %v", err)
	}

	// move veth1 to the root network namespace
	rootNsHandle, err := netns.GetFromPid(1)
	if err != nil {
		return fmt.Errorf("Failed to get root network namespace fd: %v", err)
	}
	if err := netlink.LinkSetNsFd(linkVeth0, int(rootNsHandle)); err != nil {
		return fmt.Errorf("Failed to move veth0 to root namespace: %v", err)
	}

	log.Println("Network setup completed successfully.")
	return nil
}

func getDefaultRouteInterface() (string, error) {
	routes, err := netlink.RouteList(nil, nl.FAMILY_ALL)
	if err != nil {
		return "", err
	}

	// find and return interface name for first default route (0.0.0.0/0)
	for _, route := range routes {
		if route.Dst == nil || route.Dst.IP.IsUnspecified() {
			link, err := netlink.LinkByIndex(route.LinkIndex)
			if err != nil {
				return "", err
			}
			return link.Attrs().Name, nil
		}
	}

	return "", fmt.Errorf("default route not found")
}

func setupIpForwarding() {
	// enable IP forwarding on host
	err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644)
	if err != nil {
		log.Fatalf("Failed to enable IP forwarding: %v", err)
	}

	defaultIf, err := getDefaultRouteInterface()
	if err != nil {
		log.Fatalf("Failed to get default route interface: %v", err)
	}

	// Create a new iptables instance
	ipt, err := iptables.New()
	if err != nil {
		log.Fatalf("Error initializing iptables: %v", err)
	}

	// Add the rule to the chain
	err = ipt.AppendUnique("nat", "POSTROUTING", "-s", "10.0.1.0/24", "-o", defaultIf, "-j", "MASQUERADE")
	if err != nil {
		log.Fatalf("Error appending iptables rule: %v", err)
	}
}
