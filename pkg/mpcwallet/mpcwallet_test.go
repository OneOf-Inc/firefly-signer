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
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hyperledger/firefly-common/pkg/config"
	"github.com/hyperledger/firefly-signer/pkg/ethsigner"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func newTestMpcWallet(t *testing.T, init bool) (context.Context, *mpcWallet, func()) {
	config.RootConfigReset()
	logrus.SetLevel(logrus.TraceLevel)

	unitTestConfig := config.RootSection("ut_mpc_config")
	InitConfig(unitTestConfig)
	unitTestConfig.Set(ConfigPath, "../../test/keystore_toml")
	unitTestConfig.Set(ConfigFilenamesPrimaryMatchRegex, "^((0x)?[0-9a-z]+).key.json$")
	unitTestConfig.Set(ConfigDisableListener, true)
	unitTestConfig.Set(ConfigURL, "http://127.0.0.1:4000")
	ctx := context.Background()

	w, err := NewMPCWallet(ctx, ReadConfig(unitTestConfig))
	assert.NoError(t, err)
	if init {
		err = w.Initialize(ctx)
		assert.NoError(t, err)
	}

	return ctx, w.(*mpcWallet), func() {
		w.Close()
	}
}

func newTestTOMLWallet(t *testing.T, init bool) (context.Context, *mpcWallet, func()) {
	config.RootConfigReset()
	logrus.SetLevel(logrus.TraceLevel)

	unitTestConfig := config.RootSection("ut_fs_config")
	InitConfig(unitTestConfig)
	unitTestConfig.Set(ConfigPath, "../../test/keystore_toml")
	unitTestConfig.Set(ConfigFilenamesPrimaryExt, ".toml")
	unitTestConfig.Set(ConfigDisableListener, true)
	unitTestConfig.Set(ConfigURL, "http://127.0.0.1:4000")
	ctx := context.Background()

	ff, err := NewMPCWallet(ctx, ReadConfig(unitTestConfig))
	assert.NoError(t, err)
	if init {
		err = ff.Initialize(ctx)
		assert.NoError(t, err)
	}
	return ctx, ff.(*mpcWallet), func() {
		ff.Close()
	}
}

func TestGetAccounts(t *testing.T) {
	ctx, w, done := newTestMpcWallet(t, true)
	defer done()

	_, err := w.GetAccounts(ctx)
	assert.NoError(t, err)
}

func TestRefresh(t *testing.T) {
	ctx, w, done := newTestMpcWallet(t, true)
	defer done()

	err := w.Refresh(ctx)
	assert.NoError(t, err)
}

func TestSignOK(t *testing.T) {
	ctx, w, done := newTestMpcWallet(t, true)
	defer done()

	// Set up http mocks
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("{\"signedTx\":\"0xf88c0185095ea991de8301002994f5ed78e81bb8abb24affade03447b35126e226\"}"))
	}))
	defer svr.Close()
	w.conf.WalletURL = svr.URL

	inputData, err := hex.DecodeString(
		"3674e15c00000000000000000000000000000000000000000000000000000000000000a03f04a4e93ded4d2aaa1a41d617e55c59ac5f1b28a47047e2a526e76d45eb9681d19642e9120d63a9b7f5f537565a430d8ad321ef1bc76689a4b3edc861c640fc00000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000000966665f73797374656d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002e516d58747653456758626265506855684165364167426f3465796a7053434b437834515a4c50793548646a6177730000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001a1f7502c8f8797999c0c6b9c2da653ea736598ed0daa856c47ae71411aa8fea2")
	assert.NoError(t, err)

	res, err := w.Sign(ctx, &ethsigner.Transaction{
		From:     json.RawMessage(`"0x1f185718734552d08278aa70f804580bab5fd2b4"`),
		To:       ethtypes.MustNewAddress("0x497eedc4299dea2f2a364be10025d0ad0f702de3"),
		Nonce:    ethtypes.NewHexInteger64(3),
		GasLimit: ethtypes.NewHexInteger64(40574),
		Data:     inputData,
	}, 2022)
	assert.NoError(t, err)
	assert.NotNil(t, res)
}

func TestSignEmptyContextErr(t *testing.T) {
	_, w, done := newTestMpcWallet(t, true)
	defer done()

	res, err := w.Sign(nil, &ethsigner.Transaction{
		From:     json.RawMessage(`"0x1f185718734552d08278aa70f804580bab5fd2b4"`),
		To:       ethtypes.MustNewAddress("0x497eedc4299dea2f2a364be10025d0ad0f702de3"),
		Nonce:    ethtypes.NewHexInteger64(3),
		GasLimit: ethtypes.NewHexInteger64(40574),
		Data:     nil,
	}, 2022)
	assert.Error(t, err)
	assert.Nil(t, res)
}

func TestSignInvalidURLErr(t *testing.T) {
	ctx, w, done := newTestMpcWallet(t, true)
	defer done()

	w.conf.WalletURL = "invalid_url"

	res, err := w.Sign(ctx, &ethsigner.Transaction{
		From:     json.RawMessage(`"0x1f185718734552d08278aa70f804580bab5fd2b4"`),
		To:       ethtypes.MustNewAddress("0x497eedc4299dea2f2a364be10025d0ad0f702de3"),
		Nonce:    ethtypes.NewHexInteger64(3),
		GasLimit: ethtypes.NewHexInteger64(40574),
		Data:     nil,
	}, 2022)
	assert.Error(t, err)
	assert.Nil(t, res)
}

func TestSignWrongStatusErr(t *testing.T) {
	ctx, w, done := newTestMpcWallet(t, true)
	defer done()

	// Set up http mocks
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte("internal error"))
	}))
	defer svr.Close()
	w.conf.WalletURL = svr.URL

	res, err := w.Sign(ctx, &ethsigner.Transaction{
		From:     json.RawMessage(`"0x1f185718734552d08278aa70f804580bab5fd2b4"`),
		To:       ethtypes.MustNewAddress("0x497eedc4299dea2f2a364be10025d0ad0f702de3"),
		Nonce:    ethtypes.NewHexInteger64(3),
		GasLimit: ethtypes.NewHexInteger64(40574),
		Data:     nil,
	}, 2022)
	assert.Error(t, err)
	assert.Nil(t, res)
}

func TestSigUnmarshalRespErr(t *testing.T) {
	ctx, w, done := newTestMpcWallet(t, true)
	defer done()

	// Set up http mocks
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(nil)
	}))
	defer svr.Close()
	w.conf.WalletURL = svr.URL

	res, err := w.Sign(ctx, &ethsigner.Transaction{
		From:     json.RawMessage(`"0x1f185718734552d08278aa70f804580bab5fd2b4"`),
		To:       ethtypes.MustNewAddress("0x497eedc4299dea2f2a364be10025d0ad0f702de3"),
		Nonce:    ethtypes.NewHexInteger64(3),
		GasLimit: ethtypes.NewHexInteger64(40574),
		Data:     nil,
	}, 2022)
	assert.Error(t, err)
	assert.Nil(t, res)
}

func TestSignDecodeErr(t *testing.T) {
	ctx, w, done := newTestMpcWallet(t, true)
	defer done()

	// Set up http mocks
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("{\"signature\":\"error\"}"))
	}))
	defer svr.Close()
	w.conf.WalletURL = svr.URL

	inputData, err := hex.DecodeString(
		"3674e15c00000000000000000000000000000000000000000000000000000000000000a03f04a4e93ded4d2aaa1a41d617e55c59ac5f1b28a47047e2a526e76d45eb9681d19642e9120d63a9b7f5f537565a430d8ad321ef1bc76689a4b3edc861c640fc00000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000000966665f73797374656d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002e516d58747653456758626265506855684165364167426f3465796a7053434b437834515a4c50793548646a6177730000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001a1f7502c8f8797999c0c6b9c2da653ea736598ed0daa856c47ae71411aa8fea2")
	assert.NoError(t, err)

	res, err := w.Sign(ctx, &ethsigner.Transaction{
		From:     json.RawMessage(`"0x1f185718734552d08278aa70f804580bab5fd2b4"`),
		To:       ethtypes.MustNewAddress("0x497eedc4299dea2f2a364be10025d0ad0f702de3"),
		Nonce:    ethtypes.NewHexInteger64(3),
		GasLimit: ethtypes.NewHexInteger64(40574),
		Data:     inputData,
	}, 2022)
	assert.Error(t, err)
	assert.Nil(t, res)
}

func TestBadRegexp(t *testing.T) {
	_, err := NewMPCWallet(context.Background(), &Config{
		Path: "../../test/keystore_toml",
		Filenames: FilenamesConfig{
			PrimaryMatchRegex: "[[[[!bad",
		},
	})
	assert.Regexp(t, "FF22056", err)
}

func TestMissingCaptureRegexp(t *testing.T) {
	_, err := NewMPCWallet(context.Background(), &Config{
		Path: "../../test/keystore_toml",
		Filenames: FilenamesConfig{
			PrimaryMatchRegex: ".*",
		},
	})
	assert.Regexp(t, "FF22057", err)
}

func TestRefreshOK(t *testing.T) {
	ctx, f, done := newTestMpcWallet(t, true)
	defer done()
	err := f.Refresh(ctx)
	assert.NoError(t, err)
}

func TestRefreshFail(t *testing.T) {
	config.RootConfigReset()
	logrus.SetLevel(logrus.TraceLevel)

	unitTestConfig := config.RootSection("ut_fs_config")
	InitConfig(unitTestConfig)
	unitTestConfig.Set(ConfigPath, "!!!")
	unitTestConfig.Set(ConfigFilenamesPrimaryExt, ".toml")
	unitTestConfig.Set(ConfigDisableListener, true)
	ctx := context.Background()

	ff, err := NewMPCWallet(ctx, ReadConfig(unitTestConfig))
	assert.NoError(t, err)
	defer ff.Close()

	err = ff.Refresh(ctx)
	assert.Error(t, err)
}

func TestListAccountsTOMLOk(t *testing.T) {
	ctx, f, done := newTestTOMLWallet(t, true)
	defer done()
	accounts, err := f.GetAccounts(ctx)
	assert.NoError(t, err)
	assert.Len(t, accounts, 3)
	all := map[string]bool{}
	for _, a := range accounts {
		all[a.String()] = true
	}
	assert.True(t, all["0x1f185718734552d08278aa70f804580bab5fd2b4"])
	assert.True(t, all["0x497eedc4299dea2f2a364be10025d0ad0f702de3"])
	assert.True(t, all["0x5d093e9b41911be5f5c4cf91b108bac5d130fa83"])
}