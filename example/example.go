package main

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/taurusgroup/multi-party-sig/internal/test"
	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/pkg/taproot"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
	"github.com/taurusgroup/multi-party-sig/protocols/example"
	"github.com/taurusgroup/multi-party-sig/protocols/frost"
)

func XOR(id party.ID, ids party.IDSlice, n *test.Network) error {
	h, err := protocol.NewMultiHandler(example.StartXOR(id, ids), nil)
	if err != nil {
		return err
	}
	test.HandlerLoop(id, h, n)
	_, err = h.Result()
	if err != nil {
		return err
	}
	return nil
}

func CMPKeygen(id party.ID, ids party.IDSlice, threshold int, n *test.Network, pl *pool.Pool) (*cmp.Config, error) {
	h, err := protocol.NewMultiHandler(cmp.Keygen(curve.Secp256k1{}, id, ids, threshold, pl), nil)
	if err != nil {
		return nil, err
	}
	test.HandlerLoop(id, h, n)
	r, err := h.Result()
	if err != nil {
		return nil, err
	}

	return r.(*cmp.Config), nil
}

func CMPRefresh(c *cmp.Config, n *test.Network, pl *pool.Pool) (*cmp.Config, error) {
	hRefresh, err := protocol.NewMultiHandler(cmp.Refresh(c, pl), nil)
	if err != nil {
		return nil, err
	}
	test.HandlerLoop(c.ID, hRefresh, n)

	r, err := hRefresh.Result()
	if err != nil {
		return nil, err
	}

	return r.(*cmp.Config), nil
}

func CMPSign(c *cmp.Config, m []byte, signers party.IDSlice, n *test.Network, pl *pool.Pool) error {
	h, err := protocol.NewMultiHandler(cmp.Sign(c, signers, m, pl), nil)
	if err != nil {
		return err
	}
	test.HandlerLoop(c.ID, h, n)

	signResult, err := h.Result()
	if err != nil {
		return err
	}
	signature := signResult.(*ecdsa.Signature)
	if !signature.Verify(c.PublicPoint(), m) {
		return errors.New("failed to verify cmp signature")
	}
	return nil
}

func CMPPreSign(c *cmp.Config, signers party.IDSlice, n *test.Network, pl *pool.Pool) (*ecdsa.PreSignature, error) {
	h, err := protocol.NewMultiHandler(cmp.Presign(c, signers, pl), nil)
	if err != nil {
		return nil, err
	}

	test.HandlerLoop(c.ID, h, n)

	signResult, err := h.Result()
	if err != nil {
		return nil, err
	}

	preSignature := signResult.(*ecdsa.PreSignature)
	if err = preSignature.Validate(); err != nil {
		return nil, errors.New("failed to verify cmp presignature")
	}
	return preSignature, nil
}

func CMPPreSignOnline(c *cmp.Config, preSignature *ecdsa.PreSignature, m []byte, n *test.Network, pl *pool.Pool) error {
	h, err := protocol.NewMultiHandler(cmp.PresignOnline(c, preSignature, m, pl), nil)
	if err != nil {
		return err
	}
	test.HandlerLoop(c.ID, h, n)

	signResult, err := h.Result()
	if err != nil {
		return err
	}
	signature := signResult.(*ecdsa.Signature)
	if !signature.Verify(c.PublicPoint(), m) {
		return errors.New("failed to verify cmp signature")
	}
	return nil
}

func FrostKeygen(id party.ID, ids party.IDSlice, threshold int, n *test.Network) (*frost.Config, error) {
	h, err := protocol.NewMultiHandler(frost.Keygen(curve.Secp256k1{}, id, ids, threshold), nil)
	if err != nil {
		return nil, err
	}
	test.HandlerLoop(id, h, n)
	r, err := h.Result()
	if err != nil {
		return nil, err
	}

	return r.(*frost.Config), nil
}

func FrostSign(c *frost.Config, id party.ID, m []byte, signers party.IDSlice, n *test.Network) error {
	h, err := protocol.NewMultiHandler(frost.Sign(c, signers, m), nil)
	if err != nil {
		return err
	}
	test.HandlerLoop(id, h, n)
	r, err := h.Result()
	if err != nil {
		return err
	}

	signature := r.(frost.Signature)
	if !signature.Verify(c.PublicKey, m) {
		return errors.New("failed to verify frost signature")
	}
	return nil
}

func FrostKeygenTaproot(id party.ID, ids party.IDSlice, threshold int, n *test.Network) (*frost.TaprootConfig, error) {
	h, err := protocol.NewMultiHandler(frost.KeygenTaproot(id, ids, threshold), nil)
	if err != nil {
		return nil, err
	}
	test.HandlerLoop(id, h, n)
	r, err := h.Result()
	if err != nil {
		return nil, err
	}

	return r.(*frost.TaprootConfig), nil
}
func FrostSignTaproot(c *frost.TaprootConfig, id party.ID, m []byte, signers party.IDSlice, n *test.Network) error {
	h, err := protocol.NewMultiHandler(frost.SignTaproot(c, signers, m), nil)
	if err != nil {
		return err
	}
	test.HandlerLoop(id, h, n)
	r, err := h.Result()
	if err != nil {
		return err
	}

	signature := r.(taproot.Signature)
	if !c.PublicKey.Verify(signature, m) {
		return errors.New("failed to verify frost signature")
	}
	return nil
}

func All(id party.ID, ids party.IDSlice, threshold int, message []byte, n *test.Network, wg *sync.WaitGroup, pl *pool.Pool) error {
	defer wg.Done()

	// XOR
	err := XOR(id, ids, n)
	if err != nil {
		return err
	}

	// CMP KEYGEN
	keygenConfig, err := CMPKeygen(id, ids, threshold, n, pl)
	if err != nil {
		return err
	}

	// CMP REFRESH
	refreshConfig, err := CMPRefresh(keygenConfig, n, pl)
	if err != nil {
		return err
	}

	// FROST KEYGEN
	frostResult, err := FrostKeygen(id, ids, threshold, n)
	if err != nil {
		return err
	}

	// FROST KEYGEN TAPROOT
	frostResultTaproot, err := FrostKeygenTaproot(id, ids, threshold, n)
	if err != nil {
		return err
	}

	signers := ids[:threshold+1]
	if !signers.Contains(id) {
		n.Quit(id)
		return nil
	}

	// CMP SIGN
	err = CMPSign(refreshConfig, message, signers, n, pl)
	if err != nil {
		return err
	}

	// CMP PRESIGN
	preSignature, err := CMPPreSign(refreshConfig, signers, n, pl)
	if err != nil {
		return err
	}

	// CMP PRESIGN ONLINE
	err = CMPPreSignOnline(refreshConfig, preSignature, message, n, pl)
	if err != nil {
		return err
	}

	// FROST SIGN
	err = FrostSign(frostResult, id, message, signers, n)
	if err != nil {
		return err
	}

	// FROST SIGN TAPROOT
	err = FrostSignTaproot(frostResultTaproot, id, message, signers, n)
	if err != nil {
		return err
	}

	return nil
}

func benchmarkCMP(id party.ID, ids party.IDSlice, threshold int, message []byte, n *test.Network, wg *sync.WaitGroup, pl *pool.Pool) (time.Duration, time.Duration, error) {
	defer wg.Done()

	keygenStart := time.Now()
	// CMP KEYGEN
	keygenConfig, err := CMPKeygen(id, ids, threshold, n, pl)
	if err != nil {
		return 0, 0, err
	}
	CMP_KEYGEN_time := time.Since(keygenStart)

	signers := ids[:threshold+1]
	if !signers.Contains(id) {
		n.Quit(id)
		return 0, 0, err
	}

	// CMP PRESIGN
	preSignature, err := CMPPreSign(keygenConfig, signers, n, pl)
	if err != nil {
		return 0, 0, err
	}

	// CMP PRESIGN ONLINE
	err = CMPPreSignOnline(keygenConfig, preSignature, message, n, pl)
	if err != nil {
		return 0, 0, err
	}

	CMP_time := time.Since(keygenStart)

	return CMP_KEYGEN_time, CMP_time, nil
}

func benchmarkFrost(id party.ID, ids party.IDSlice, threshold int, message []byte, n *test.Network, wg *sync.WaitGroup, pl *pool.Pool) (time.Duration, time.Duration, error) {
	defer wg.Done()

	keygenStart := time.Now()

	// FROST KEYGEN
	frostResult, err := FrostKeygen(id, ids, threshold, n)
	if err != nil {
		return 0, 0, err
	}

	Frost_KEYGEN_time := time.Since(keygenStart)

	/*// FROST KEYGEN TAPROOT
	frostResultTaproot, err := FrostKeygenTaproot(id, ids, threshold, n)
	if err != nil {
		return err
	}*/

	signers := ids[:threshold+1]
	if !signers.Contains(id) {
		n.Quit(id)
		return 0, 0, err
	}

	// FROST SIGN
	err = FrostSign(frostResult, id, message, signers, n)
	if err != nil {
		return 0, 0, err
	}

	/*// FROST SIGN TAPROOT
	err = FrostSignTaproot(frostResultTaproot, id, message, signers, n)
	if err != nil {
		return err
	}*/

	Frost_time := time.Since(keygenStart)

	return Frost_KEYGEN_time, Frost_time, nil
}

type TimeMetrics struct {
	Threshold  int
	N          int
	KeygenTime time.Duration
	SignTime   time.Duration
}

/*func main() {

	fmt.Print("lunching main")

	var timeMetrics []TimeMetrics

	full_ids := party.IDSlice{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t"}
	messageToSign := []byte("hello")
	for id_num := 1; id_num < 8; id_num++ {
		ids := full_ids[:id_num]
		for threshold := 2; threshold < int(math.Min(15, float64(id_num))); threshold++ {

			net := test.NewNetwork(ids)

			var wg sync.WaitGroup
			for _, id := range ids {
				wg.Add(1)
				go func(id party.ID) {
					pl := pool.NewPool(0)
					defer pl.TearDown()
					keygen_Time, sign_time, err := benchmarkFrost(id, ids, threshold, messageToSign, net, &wg, pl)
					if err != nil {
						fmt.Println(err)
					}
					timeMetrics = append(timeMetrics, TimeMetrics{Threshold: threshold, N: id_num, KeygenTime: keygen_Time, SignTime: sign_time})

				}(id)
			}
			wg.Wait()

		}
	}

	// Print or process the collected time metrics as needed
	for _, metric := range timeMetrics {
		fmt.Printf("Threshold: %d, N: %d, KeygenTime: %v, SignTime: %v\n", metric.Threshold, metric.N, metric.KeygenTime, metric.SignTime)
	}

	fmt.Print("end lunching main")
}*/

func main() {
	N := 3
	threshold := 2

	ids := party.IDSlice{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t"}
	ids = ids[:N]
	messageToSign := []byte("hello")

	net := test.NewNetwork(ids)

	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(id party.ID) {
			pl := pool.NewPool(0)
			defer pl.TearDown()
			keygen_Time, sign_time, err := benchmarkCMP(id, ids, threshold, messageToSign, net, &wg, pl)
			if err != nil {
				fmt.Println(err)
			}
			fmt.Printf("KeygenTime: %v, SignTime: %v\n", keygen_Time, sign_time)
		}(id)
	}

	wg.Wait()
}
