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
	From     string `json:"from"`
	To       string `json:"to"`
	Data     string `json:"data"`
	Value    string `json:"value"`
	GasLimit uint64 `json:"gas_limit"`
	ChainID  uint64 `json:"chainId"`
}

type signTxResponse struct {
	KeyID     string `json:"keyId"`
	Message   string `json:"message"`
	Signature string `json:"signature"`
	ASN1      string `json:"asn1"`
}

func (w *mpcWallet) Sign(ctx context.Context, txn *ethsigner.Transaction, chainID int64) ([]byte, error) {
	url := w.conf.WalletURL + "/api/mpc/key/" + w.conf.KeyID + "/sign-evm"
	signTxReq := w.buildSignTxRequest(txn, chainID)
	requestBody, _ := json.Marshal(signTxReq)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(requestBody))
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var signTxResp signTxResponse
	err = json.Unmarshal(body, &signTxResp)
	if err != nil {
		return nil, err
	}

	return []byte(signTxResp.Message), nil
}

func (w *mpcWallet) buildSignTxRequest(txn *ethsigner.Transaction, chainID int64) *signTxRequest {
	return &signTxRequest{
		From:     string(txn.From),
		To:       txn.To.String(),
		Data:     hex.EncodeToString(txn.Data),
		Value:    txn.Value.String(),
		GasLimit: txn.GasLimit.Uint64(),
		ChainID:  uint64(chainID),
	}
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
