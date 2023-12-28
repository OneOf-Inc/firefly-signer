// Copyright © 2023 Kaleido, Inc.
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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/hyperledger/firefly-signer/pkg/ethsigner"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
)

type mpcWallet struct {
	conf Config
}

func NewMPCWallet(ctx context.Context, conf *Config) (ethsigner.Wallet, error) {
	return &mpcWallet{
		conf: *conf,
	}, nil
}

type signTxRequest struct {
	To       string `json:"to"`
	Data     string `json:"data"`
	Value    string `json:"value"`
	GasLimit uint64 `json:"gasLimit"`
	ChainID  uint64 `json:"chainId"`
}

type signTxResponse struct {
	KeyID     string `json:"keyId"`
	Signature string `json:"signature"`
}

func (w *mpcWallet) Sign(ctx context.Context, txn *ethsigner.Transaction, chainID int64) ([]byte, error) {
	var fromStr string
	_ = json.Unmarshal(txn.From, &fromStr)

	url := fmt.Sprintf("%s/api/evm/%s/sign-evm", w.conf.WalletURL, fromStr)
	signTxReq := &signTxRequest{
		To:       txn.To.String(),
		Data:     hex.EncodeToString(txn.Data),
		Value:    txn.Value.String(),
		GasLimit: txn.GasLimit.Uint64(),
		ChainID:  uint64(chainID),
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

	return []byte(signTxResp.Signature), nil
}

func (w *mpcWallet) Initialize(ctx context.Context) error {
	return nil
}

// GetAccounts returns the currently cached list of known addresses
func (w *mpcWallet) GetAccounts(_ context.Context) ([]*ethtypes.Address0xHex, error) {
	return nil, nil
}

func (w *mpcWallet) Refresh(ctx context.Context) error {
	return nil
}

func (w *mpcWallet) Close() error {
	return nil
}
