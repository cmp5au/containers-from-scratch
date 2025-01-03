// +build linux
package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"syscall"

	"github.com/containerd/cgroups/v3/cgroup2"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
)

var rootNetworkNamespace netns.NsHandle
var veth0 string = "veth0"
var veth1 string = "veth1"
var	bridge string = "br0"
var	namespace string = "net1"

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

	createNetworkNamespace()
	defer destroyNetworkNamespace()

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
		Cloneflags:   syscall.CLONE_NEWUTS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS,
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
		err := os.MkdirAll("/sys/fs/cgroup" + cgroupPath, 0755)
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
The following shell commands are adapted from "Networking and Kubernetes" by James
Strong and Vallery Lancey, and represent the basis of what createNetworkNamespace is
doing on the root network namespace and the newly-created network namespace:

$ echo 1 > /proc/sys/net/ipv4/ip_forward
$ sudo ip link add br0 type bridge
$ sudo ip link set dev br0 up
$ sudo ip link add veth0 type veth peer name veth1
$ sudo ip link set veth0 master br0
$ sudo ip link set enp0s3 master br0
$ sudo ip netns add net1
$ sudo ip link set veth1 netns net1
$ sudo ip netns exec net1 ip addr add 192.168.119.111/24 dev veth1
$ sudo ip netns exec net1 ip link set dev veth1 up
$ sudo ip netns exec net1 ip route add default via 192.168.1.100
*/
func createNetworkNamespace() {
	var err error
	rootNetworkNamespace, err = netns.Get()
	if err != nil {
		log.Fatalf("Failed to get root namespace: %v", err)
	}

	// enable IP forwarding on host
	err = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644)
	if err != nil {
		log.Fatalf("Failed to enable IP forwarding: %v", err)
	}

	// create and set up the bridge
	br := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: "br0"}}
	if err := netlink.LinkAdd(br); err != nil {
		log.Fatalf("Failed to create bridge: %v", err)
	}
	if err := netlink.LinkSetUp(br); err != nil {
		log.Fatalf("Failed to set bridge up: %v", err)
	}
	// addr, _ := netlink.ParseAddr("192.168.119.200/24")
	// if err := netlink.AddrAdd(br, addr); err != nil {
	// 	log.Fatalf("Failed to assign root namespace subnet IP to br0: %v", err)
	// }
	// addr, _ = netlink.ParseAddr("192.168.1.1/24")
	// if err := netlink.AddrAdd(br, addr); err != nil {
	// 	log.Fatalf("Failed to assign new namespace subnet IP to br0: %v", err)
	// }

	// create veth pair
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: veth0},
		PeerName:  veth1,
	}
	if err := netlink.LinkAdd(veth); err != nil {
		log.Fatalf("Failed to create veth pair: %v", err)
	}

	// add veth0 and external interface to bridge
	linkVeth0, err := netlink.LinkByName(veth0)
	if err != nil {
		log.Fatalf("Failed to get veth0 link: %v", err)
	}
	if err := netlink.LinkSetMaster(linkVeth0, br); err != nil {
		log.Fatalf("Failed to add veth0 to bridge: %v", err)
	}
	// addr, _ = netlink.ParseAddr("192.168.1.100/24")
	// if err := netlink.AddrAdd(linkVeth0, addr); err != nil {
	// 	log.Fatalf("Failed to assign IP to veth0: %v", err)
	// }

	externalIf, err := getDefaultRouteInterface()
	if err != nil {
		log.Fatalf("Failed to get external default route interface: %v", err)
	}

	linkExt, err := netlink.LinkByName(externalIf)
	if err != nil {
		interfaces, newErr := netlink.LinkList()
		if newErr != nil {
			log.Fatalf("Failed to get external interface: %v\nFailed to list interfaces: %v", err, newErr)
		}
		interfaceNames := make([]string, len(interfaces))
		for i, itfc := range interfaces {
			interfaceNames[i] = itfc.Attrs().Name
		}
		log.Fatalf("Failed to get external interface: %v\nAvailable interfaces are: %v", err, interfaceNames)
	}
	if err := netlink.LinkSetMaster(linkExt, br); err != nil {
		log.Fatalf("Failed to add external interface to bridge: %v", err)
	}

	// create a new network namespace
	netnsName := "net1"
	newNs, err := netns.NewNamed(netnsName)
	if err != nil {
		log.Fatalf("Failed to create network namespace: %v", err)
	}

	// move veth1 to the new namespace
	err = netns.Set(rootNetworkNamespace)
	if err != nil {
		log.Fatalf("Failed to switch to root network namespace: %v", err)
	}
	linkVeth1, err := netlink.LinkByName(veth1)
	if err != nil {
		log.Fatalf("Failed to get veth1 link: %v", err)
	}
	if err := netlink.LinkSetNsFd(linkVeth1, int(newNs)); err != nil {
		log.Fatalf("Failed to move veth1 to namespace: %v", err)
	}
	err = netns.Set(newNs)
	if err != nil {
		log.Fatalf("Failed to switch to namespace: %v", err)
	}

	// add ip and default route inside new network namespace
	linkVeth1, err = netlink.LinkByName(veth1)
	if err != nil {
		log.Fatalf("Failed to get veth1 in namespace: %v", err)
	}
	addr, _ := netlink.ParseAddr("192.168.119.111/24")
	if err := netlink.AddrAdd(linkVeth1, addr); err != nil {
		log.Fatalf("Failed to assign IP to veth1: %v", err)
	}
	if err := netlink.LinkSetUp(linkVeth1); err != nil {
		log.Fatalf("Failed to set veth1 up: %v", err)
	}
	defaultRoute := &netlink.Route{
		Scope: netlink.SCOPE_UNIVERSE,
		Gw:    net.ParseIP("192.168.1.100"),
	}
	if err := netlink.RouteAdd(defaultRoute); err != nil {
		log.Fatalf("Failed to add default route: %v", err)
	}

	log.Println("Network setup completed successfully.")
}

func destroyNetworkNamespace() {
	log.Println("Tearing down network namespace and associated configurations...")

	externalIf, err := getDefaultRouteInterface()
	if err != nil {
		log.Printf("Failed to get external default route interface: %v", err)
	}

	netns.Set(rootNetworkNamespace)

	// delete bridge
	brLink, err := netlink.LinkByName(bridge)
	if err == nil {
		if err := netlink.LinkSetDown(brLink); err != nil {
			log.Printf("Failed to bring down bridge %s: %v", bridge, err)
		}
		if err := netlink.LinkDel(brLink); err != nil {
			log.Printf("Failed to delete bridge %s: %v", bridge, err)
		} else {
			log.Printf("Bridge %s deleted.", bridge)
		}
	} else {
		log.Printf("Bridge %s not found: %v", bridge, err)
	}

	// delete veth pair
	vethLink, err := netlink.LinkByName(veth0)
	if err == nil {
		if err := netlink.LinkDel(vethLink); err != nil {
			log.Printf("Failed to delete veth pair %s: %v", veth0, err)
		} else {
			log.Printf("Veth pair %s deleted.", veth0)
		}
	} else {
		log.Printf("Veth pair %s not found: %v", veth0, err)
	}

	// delete network namespace
	if err := netns.DeleteNamed(namespace); err != nil {
		log.Printf("Failed to delete namespace %s: %v", namespace, err)
	} else {
		log.Printf("Namespace %s deleted.", namespace)
	}

	// remove the external interface from the bridge
	if externalIf != "" {
		extLink, err := netlink.LinkByName(externalIf)
		if err == nil {
			if err := netlink.LinkSetNoMaster(extLink); err != nil {
				log.Printf("Failed to remove external interface %s from bridge: %v", externalIf, err)
			} else {
				log.Printf("External interface %s detached from bridge.", externalIf)
			}
		} else {
			log.Printf("External interface %s not found: %v", externalIf, err)
		}
	}

	// disable IP forwarding on host 
	err = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("0"), 0644)
	if err != nil {
		log.Fatalf("Failed to disable IP forwarding: %v", err)
	}
	log.Println("IP forwarding disabled.")

	log.Println("Tear-down completed.")
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
