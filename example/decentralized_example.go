package main

import (
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
)

func main() {
	if len(os.Args) < 5 {
		fmt.Println("Usage: ./program <id> <total_parties> <threshold> <port>")
		return
	}

	id := party.ID(os.Args[1])
	totalParties, _ := strconv.Atoi(os.Args[2])
	threshold, _ := strconv.Atoi(os.Args[3])
	port, _ := strconv.Atoi(os.Args[4])

	// Create a slice of all party IDs
	var ids party.IDSlice
	for i := 1; i <= totalParties; i++ {
		ids = append(ids, party.ID(fmt.Sprintf("party%d", i)))
	}

	// Set up networking (simplified)
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		fmt.Println("Error listening:", err)
		return
	}
	defer ln.Close()

	// Create a pool
	pl := pool.NewPool(0)
	defer pl.TearDown()

	// Run CMP Keygen
	config, err := runCMPKeygen(id, ids, threshold, pl)
	if err != nil {
		fmt.Println("Error in CMP Keygen:", err)
		return
	}

	fmt.Printf("Node %s completed keygen. Config: %+v\n", id, config)
}

func runCMPKeygen(id party.ID, ids party.IDSlice, threshold int, pl *pool.Pool) (*cmp.Config, error) {
	h, err := protocol.NewMultiHandler(cmp.Keygen(curve.Secp256k1{}, id, ids, threshold, pl), nil)
	if err != nil {
		return nil, err
	}

	// Here you would implement the actual network communication
	// Instead of test.HandlerLoop, you'd need to handle incoming/outgoing messages

	r, err := h.Result()
	if err != nil {
		return nil, err
	}

	return r.(*cmp.Config), nil
}
