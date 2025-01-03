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
	fmt.Printf("Running %v \n", os.Args[2:])

	createNetworkNamespace()
	defer destroyNetworkNamespace()

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
	fmt.Printf("Running %v \n", os.Args[2:])

	cg := cg()
	defer func() {
		err := cg.Delete()
		if err != nil {
			log.Printf("Failed to delete cgroup: %v", err)
		} else {
			fmt.Println("Cgroup deleted successfully.")
		}
	}()

	cmd := exec.Command(os.Args[2], os.Args[3:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	must(syscall.Sethostname([]byte("container")))
	must(syscall.Chroot("/container-test/ubuntu-fs"))
	must(os.Chdir("/"))
	must(syscall.Mount("proc", "proc", "proc", 0, ""))
	must(syscall.Mount("thing", "mytemp", "tmpfs", 0, ""))

	must(cmd.Run())

	must(syscall.Unmount("proc", 0))
	must(syscall.Unmount("thing", 0))
}

func cg() *cgroup2.Manager {
cgroupPath := "/sys/fs/cgroup/pids/cparker" // Adjust the path accordingly

	// Load the cgroup
	cg, err := cgroup2.Load(cgroupPath)
	if err != nil {
		log.Fatalf("Failed to load cgroup: %v", err)
	}

	// Set the max number of PIDs in the cgroup (pids.max)
	err = cg.Update(&cgroup2.Resources{Pids: &cgroup2.Pids{Max: 20}})
	if err != nil {
		log.Fatalf("Failed to set pids.max: %v", err)
	}

	// Add a process to the cgroup (for demonstration, using the current process)
	// Replace with your process ID (pid) as needed
	pid := os.Getpid() // Example: Add the current process to the cgroup
	err = cg.AddProc(uint64(pid))
	if err != nil {
		log.Fatalf("Failed to add process to cgroup: %v", err)
	}
	return cg
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func createNetworkNamespace() {
	var err error
	rootNetworkNamespace, err = netns.Get()
	if err != nil {
		log.Fatalf("Failed to get root namespace: %v", err)
	}

	// Enable IP forwarding
	err = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644)
	if err != nil {
		log.Fatalf("Failed to enable IP forwarding: %v", err)
	}

	// Create and set up the bridge
	br := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: "br0"}}
	if err := netlink.LinkAdd(br); err != nil {
		log.Fatalf("Failed to create bridge: %v", err)
	}
	if err := netlink.LinkSetUp(br); err != nil {
		log.Fatalf("Failed to set bridge up: %v", err)
	}

	// Create veth pair
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: veth0},
		PeerName:  veth1,
	}
	if err := netlink.LinkAdd(veth); err != nil {
		log.Fatalf("Failed to create veth pair: %v", err)
	}

	// Add veth0 and external interface to bridge
	linkVeth0, err := netlink.LinkByName(veth0)
	if err != nil {
		log.Fatalf("Failed to get veth0 link: %v", err)
	}
	if err := netlink.LinkSetMaster(linkVeth0, br); err != nil {
		log.Fatalf("Failed to add veth0 to bridge: %v", err)
	}

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

	// Create a network namespace
	netnsName := "net1"
	newNs, err := netns.NewNamed(netnsName)
	if err != nil {
		log.Fatalf("Failed to create network namespace: %v", err)
	}

	// Move veth1 to the new namespace
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

	// Set up veth1 inside the namespace
	err = netns.Set(newNs)
	if err != nil {
		log.Fatalf("Failed to switch to namespace: %v", err)
	}

	linkVeth1, err = netlink.LinkByName(veth1)
	if err != nil {
		log.Fatalf("Failed to get veth1 in namespace: %v", err)
	}
	addr, _ := netlink.ParseAddr("192.168.1.101/24")
	if err := netlink.AddrAdd(linkVeth1, addr); err != nil {
		log.Fatalf("Failed to assign IP to veth1: %v", err)
	}
	if err := netlink.LinkSetUp(linkVeth1); err != nil {
		log.Fatalf("Failed to set veth1 up: %v", err)
	}

	// Add default route inside the namespace
	if err != nil {
		log.Fatalf("Failed to switch to namespace: %v", err)
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

	// Step 1: Delete the bridge
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

	// Step 2: Delete the veth pair
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

	// Step 3: Delete the network namespace
	if err := netns.DeleteNamed(namespace); err != nil {
		log.Printf("Failed to delete namespace %s: %v", namespace, err)
	} else {
		log.Printf("Namespace %s deleted.", namespace)
	}

	// Step 4: Remove the external interface from the bridge (if applicable)
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

	err = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("0"), 0644)
	if err != nil {
		log.Fatalf("Failed to disable IP forwarding: %v", err)
	}
	log.Println("IP forwarding disabled.")

	log.Println("Tear-down completed.")
}

func getDefaultRouteInterface() (string, error) {
	// Get the list of routes
	routes, err := netlink.RouteList(nil, nl.FAMILY_ALL)
	if err != nil {
		return "", err
	}

	// Iterate through the routes and find the default route (0.0.0.0/0)
	for _, route := range routes {
		if route.Dst == nil || route.Dst.IP.IsUnspecified() { // Default route
			// Get the interface by its index
			link, err := netlink.LinkByIndex(route.LinkIndex)
			if err != nil {
				return "", err
			}
			// Return the name of the link
			return link.Attrs().Name, nil
		}
	}

	return "", fmt.Errorf("default route not found")
}
