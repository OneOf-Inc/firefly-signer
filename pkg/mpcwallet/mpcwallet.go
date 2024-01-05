// Copyright © 2024 Kaleido, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mpcwallet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-signer/internal/signermsgs"
	"github.com/hyperledger/firefly-signer/pkg/ethsigner"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
)

// Wallet is a directory containing a set of eth address files, conforming
// to the ethsigner.Wallet interface and providing notifications when new
// keys are added to the wallet (via FS listener).
type Wallet interface {
	ethsigner.Wallet
	AddListener(listener chan<- ethtypes.Address0xHex)
}

type mpcWallet struct {
	conf              Config
	primaryMatchRegex *regexp.Regexp

	mux               sync.Mutex
	addressToFileMap  map[ethtypes.Address0xHex]string // map for lookup to filename
	addressList       []*ethtypes.Address0xHex         // ordered list in filename at startup, then notification order
	listeners         []chan<- ethtypes.Address0xHex
	fsListenerCancel  context.CancelFunc
	fsListenerStarted chan error
	fsListenerDone    chan struct{}
}

func NewMPCWallet(ctx context.Context, conf *Config, initialListeners ...chan<- ethtypes.Address0xHex) (ww Wallet, err error) {
	w := &mpcWallet{
		conf:             *conf,
		listeners:        initialListeners,
		addressToFileMap: make(map[ethtypes.Address0xHex]string),
	}

	if conf.Filenames.PrimaryMatchRegex != "" {
		if w.primaryMatchRegex, err = regexp.Compile(conf.Filenames.PrimaryMatchRegex); err != nil {
			return nil, i18n.NewError(ctx, signermsgs.MsgBadRegularExpression, ConfigFilenamesPrimaryMatchRegex, err)
		}
		if len(w.primaryMatchRegex.SubexpNames()) < 2 {
			return nil, i18n.NewError(ctx, signermsgs.MsgMissingRegexpCaptureGroup, w.primaryMatchRegex.String())
		}
	}

	return w, nil
}

type signTxRequest struct {
	To       string `json:"to"`
	Data     string `json:"data"`
	Value    string `json:"value"`
	GasLimit uint64 `json:"gasLimit"`
	ChainID  uint64 `json:"chainId"`
}

type signTxResponse struct {
	KeyID    string `json:"keyId"`
	SignedTx string `json:"signedTx"`
}

func (w *mpcWallet) Sign(ctx context.Context, txn *ethsigner.Transaction, chainID int64) ([]byte, error) {
	var fromStr string
	_ = json.Unmarshal(txn.From, &fromStr)

	url := fmt.Sprintf("%s/api/evm/%s/sign-evm", w.conf.WalletURL, fromStr)
	signTxReq := &signTxRequest{
		Data:     txn.Data.String(),
		Value:    txn.Value.BigInt().String(),
		GasLimit: txn.GasLimit.Uint64(),
		ChainID:  uint64(chainID),
	}
	if txn.To != nil {
		signTxReq.To = txn.To.String()
	}
	requestBody, _ := json.Marshal(signTxReq)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("wallet resp with wrong status code %d", resp.StatusCode)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var signTxResp signTxResponse
	err = json.Unmarshal(body, &signTxResp)
	if err != nil {
		return nil, err
	}
	signedTxResp, err := hexutil.Decode(signTxResp.SignedTx)
	if err != nil {
		return nil, err
	}

	return signedTxResp, nil
}

func (w *mpcWallet) Initialize(ctx context.Context) error {
	// Run a get accounts pass, to check all is ok
	lCtx, lCancel := context.WithCancel(log.WithLogField(ctx, "mpcwallet", w.conf.Path))
	w.fsListenerCancel = lCancel
	w.fsListenerStarted = make(chan error)
	w.fsListenerDone = make(chan struct{})
	// Make sure listener is listening for changes, before doing the scan
	if err := w.startFilesystemListener(lCtx); err != nil {
		return err
	}
	// Do an initial full scan before returning
	return w.Refresh(ctx)
}

func (w *mpcWallet) AddListener(listener chan<- ethtypes.Address0xHex) {
	w.mux.Lock()
	defer w.mux.Unlock()
	w.listeners = append(w.listeners, listener)
}

// GetAccounts returns the currently cached list of known addresses
func (w *mpcWallet) GetAccounts(_ context.Context) ([]*ethtypes.Address0xHex, error) {
	w.mux.Lock()
	defer w.mux.Unlock()
	accounts := make([]*ethtypes.Address0xHex, len(w.addressList))
	copy(accounts, w.addressList)
	return accounts, nil
}

func (w *mpcWallet) Close() error {
	if w.fsListenerCancel != nil {
		w.fsListenerCancel()
		<-w.fsListenerDone
	}
	return nil
}

func (w *mpcWallet) Refresh(ctx context.Context) error {
	log.L(ctx).Infof("Refreshing account list at %s", w.conf.Path)
	dirEntries, err := os.ReadDir(w.conf.Path)
	if err != nil {
		return i18n.WrapError(ctx, err, signermsgs.MsgReadDirFile)
	}
	files := make([]os.FileInfo, 0, len(dirEntries))
	for _, de := range dirEntries {
		fi, infoErr := de.Info()
		if infoErr == nil {
			files = append(files, fi)
		}
	}
	if len(files) > 0 {
		w.notifyNewFiles(ctx, files...)
	}
	return nil
}

func (w *mpcWallet) notifyNewFiles(ctx context.Context, files ...fs.FileInfo) {
	// Lock now we have the list
	w.mux.Lock()
	defer w.mux.Unlock()
	newAddresses := make([]*ethtypes.Address0xHex, 0)
	for _, f := range files {
		addr := w.matchFilename(ctx, f)
		if addr != nil {
			if existingFilename, exists := w.addressToFileMap[*addr]; existingFilename != f.Name() {
				w.addressToFileMap[*addr] = f.Name()
				if !exists {
					log.L(ctx).Debugf("Added address: %s (file=%s)", addr, f.Name())
					w.addressList = append(w.addressList, addr)
					newAddresses = append(newAddresses, addr)
				}
			}
		}
	}
	listeners := make([]chan<- ethtypes.Address0xHex, len(w.listeners))
	copy(listeners, w.listeners)
	log.L(ctx).Debugf("Processed %d files. Found %d new addresses", len(files), len(newAddresses))
	// Avoid holding the lock while calling the listeners, by using a go-routine
	go func() {
		for _, l := range w.listeners {
			for _, addr := range newAddresses {
				l <- *addr
			}
		}
	}()
}

func (w *mpcWallet) matchFilename(ctx context.Context, f fs.FileInfo) *ethtypes.Address0xHex {
	if f.IsDir() {
		log.L(ctx).Tracef("Ignoring '%s/%s: directory", w.conf.Path, f.Name())
		return nil
	}
	if w.primaryMatchRegex != nil {
		match := w.primaryMatchRegex.FindStringSubmatch(f.Name())
		if match == nil {
			log.L(ctx).Tracef("Ignoring '%s/%s': does not match regexp", w.conf.Path, f.Name())
			return nil
		}
		addr, err := ethtypes.NewAddress(match[1]) // safe due to SubexpNames() length check
		if err != nil {
			log.L(ctx).Warnf("Ignoring '%s/%s': invalid address '%s': %s", w.conf.Path, f.Name(), match[1], err)
			return nil
		}
		return addr
	}
	if !strings.HasSuffix(f.Name(), w.conf.Filenames.PrimaryExt) {
		log.L(ctx).Tracef("Ignoring '%s/%s: does not match extension '%s'", w.conf.Path, f.Name(), w.conf.Filenames.PrimaryExt)
	}
	addrString := strings.TrimSuffix(f.Name(), w.conf.Filenames.PrimaryExt)
	addr, err := ethtypes.NewAddress(addrString)
	if err != nil {
		log.L(ctx).Warnf("Ignoring '%s/%s': invalid address '%s': %s", w.conf.Path, f.Name(), addrString, err)
		return nil
	}
	return addr
}
