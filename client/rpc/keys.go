package rpc

import (
	"encoding/json"
	"fmt"
	"github.com/cosmos/cosmos-sdk/client/context"
	cli "github.com/cosmos/cosmos-sdk/client/keys"
	"github.com/cosmos/cosmos-sdk/crypto/keys"
	"github.com/cosmos/cosmos-sdk/crypto/keys/keyerror"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/rest"
	"github.com/gorilla/mux"
	"io/ioutil"
	"net/http"

	"github.com/cosmos/go-bip39"
)

/////////////////////////
// REST
// used for outputting keys.Info over REST

const (
	maxValidAccountValue = int(0x80000000 - 1)
	maxValidIndexalue    = int(0x80000000 - 1)
)

// KeyOutput key output format
type KeyOutput struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Address  string `json:"address"`
	PubKey   string `json:"pub_key"`
	Mnemonic string `json:"mnemonic,omitempty"`
}

// DeleteKeyBody delete key request REST body
type DeleteKeyBody struct {
	Password string `json:"password"`
}

// UpdateKeyBody update key request REST body
type UpdateKeyBody struct {
	NewPassword string `json:"new_password"`
	OldPassword string `json:"old_password"`
}

type bechKeyOutFn func(keyInfo keys.Info) (keys.KeyOutput, error)

// QueryKeysRequestHandlerFn query key list REST handler
func QueryKeysRequestHandlerFn(cliCtx context.CLIContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		kb, err := cli.NewKeyBaseFromHomeFlag()
		if err != nil {
			rest.WriteErrorResponse(w, http.StatusInternalServerError, err.Error())
			return
		}
		infos, err := kb.List()
		if err != nil {
			rest.WriteErrorResponse(w, http.StatusInternalServerError, err.Error())
			return
		}
		// an empty list will be JSONized as null, but we want to keep the empty list
		if len(infos) == 0 {
			rest.PostProcessResponseBare(w, cliCtx, []string{})
			return
		}
		keysOutput, err := keys.Bech32KeysOutput(infos)
		if err != nil {
			rest.WriteErrorResponse(w, http.StatusInternalServerError, err.Error())
			return
		}
		rest.PostProcessResponseBare(w, cliCtx, keysOutput)
	}
}

// generateMnemonic function to just create a new seed to display in the UI before actually persisting it in the keybase
func generateMnemonic(algo keys.SigningAlgo) string {
	kb := keys.NewInMemory()
	pass := cli.DefaultKeyPass
	name := "inmemorykey"
	_, seed, _ := kb.CreateMnemonic(name, keys.English, pass, algo)
	return seed
}

// AddNewKeyRequestHandlerFn add new key REST handler
func AddNewKeyRequestHandlerFn(cliCtx context.CLIContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var kb keys.Keybase
		var m cli.AddNewKey

		kb, err := cli.NewKeyBaseFromHomeFlag()
		if err != nil {
			rest.WriteErrorResponse(w, http.StatusInternalServerError, err.Error())
			return
		}

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			rest.WriteErrorResponse(w, http.StatusBadRequest, err.Error())
			return
		}

		err = json.Unmarshal(body, &m)
		if err != nil {
			rest.WriteErrorResponse(w, http.StatusBadRequest, err.Error())
			return
		}

		// Check parameters
		if m.Name == "" {
			rest.WriteErrorResponse(w, http.StatusBadRequest, errMissingName().Error())
			return
		}
		if m.Password == "" {
			rest.WriteErrorResponse(w, http.StatusBadRequest, errMissingPassword().Error())
			return
		}

		mnemonic := m.Mnemonic
		// if mnemonic is empty, generate one
		if mnemonic == "" {
			mnemonic = generateMnemonic(keys.Secp256k1)
		}
		if !bip39.IsMnemonicValid(mnemonic) {
			rest.WriteErrorResponse(w, http.StatusBadRequest, errInvalidMnemonic().Error())
		}

		if m.Account < 0 || m.Account > maxValidAccountValue {
			rest.WriteErrorResponse(w, http.StatusBadRequest, errInvalidAccountNumber().Error())
			return
		}

		if m.Index < 0 || m.Index > maxValidIndexalue {
			rest.WriteErrorResponse(w, http.StatusBadRequest, errInvalidIndexNumber().Error())
			return
		}

		_, err = kb.Get(m.Name)
		if err == nil {
			rest.WriteErrorResponse(w, http.StatusBadRequest, errKeyNameConflict(m.Name).Error())
			return
		}

		// create account
		account := uint32(m.Account)
		index := uint32(m.Index)
		info, err := kb.CreateAccount(m.Name, mnemonic, keys.DefaultBIP39Passphrase, m.Password, account, index)
		if err != nil {
			rest.WriteErrorResponse(w, http.StatusInternalServerError, err.Error())
			return
		}

		keyOutput, err := keys.Bech32KeyOutput(info)
		if err != nil {
			rest.WriteErrorResponse(w, http.StatusInternalServerError, err.Error())
			return
		}

		keyOutput.Mnemonic = mnemonic

		rest.PostProcessResponseBare(w, cliCtx, keyOutput)
	}
}

// SeedRequestHandlerFn Seed REST request handler
func SeedRequestHandlerFn(cliCtx context.CLIContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		algoType := vars["type"]

		// algo type defaults to secp256k1
		if algoType == "" {
			algoType = "secp256k1"
		}

		algo := keys.SigningAlgo(algoType)
		seed := generateMnemonic(algo)

		rest.PostProcessResponseBare(w, cliCtx, seed)
	}
}

// RecoverRequestHandlerFn performs key recover request
func RecoverRequestHandlerFn(cliCtx context.CLIContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		name := vars["name"]
		var m cli.RecoverKey

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			rest.WriteErrorResponse(w, http.StatusBadRequest, err.Error())
			return
		}

		err = json.Unmarshal(body, &m)
		if err != nil {
			rest.WriteErrorResponse(w, http.StatusBadRequest, err.Error())
			return
		}

		kb, err := cli.NewKeyBaseFromHomeFlag()
		if err != nil {
			rest.WriteErrorResponse(w, http.StatusInternalServerError, err.Error())
		}

		if name == "" {
			rest.WriteErrorResponse(w, http.StatusBadRequest, errMissingName().Error())
			return
		}
		if m.Password == "" {
			rest.WriteErrorResponse(w, http.StatusBadRequest, errMissingPassword().Error())
			return
		}

		err = kb.Delete(name, m.Password, true)
		if keyerror.IsErrKeyNotFound(err) {
			rest.WriteErrorResponse(w, http.StatusNotFound, err.Error())
			return
		} else if keyerror.IsErrWrongPassword(err) {
			rest.WriteErrorResponse(w, http.StatusUnauthorized, err.Error())
			return
		} else if err != nil {
			rest.WriteErrorResponse(w, http.StatusInternalServerError, err.Error())
			return
		}

		mnemonic := m.Mnemonic
		if !bip39.IsMnemonicValid(mnemonic) {
			rest.WriteErrorResponse(w, http.StatusBadRequest, errInvalidMnemonic().Error())
			return
		}

		if m.Mnemonic == "" {
			rest.WriteErrorResponse(w, http.StatusBadRequest, errInvalidMnemonic().Error())
			return
		}

		if m.Account < 0 || m.Account > maxValidAccountValue {
			rest.WriteErrorResponse(w, http.StatusBadRequest, errInvalidAccountNumber().Error())
			return
		}

		if m.Index < 0 || m.Index > maxValidIndexalue {
			rest.WriteErrorResponse(w, http.StatusBadRequest, errInvalidIndexNumber().Error())
			return
		}

		_, err = kb.Get(name)
		if err == nil {
			rest.WriteErrorResponse(w, http.StatusConflict, errKeyNameConflict(name).Error())
			return
		}

		account := uint32(m.Account)
		index := uint32(m.Index)
		info, err := kb.CreateAccount(name, mnemonic, keys.DefaultBIP39Passphrase, m.Password, account, index)
		if err != nil {
			rest.WriteErrorResponse(w, http.StatusInternalServerError, err.Error())
			return
		}

		//keyOutput, err := keys.Bech32KeyOutput(info)
		_, err = keys.Bech32KeyOutput(info)
		if err != nil {
			rest.WriteErrorResponse(w, http.StatusInternalServerError, err.Error())
			return
		}

		//rest.PostProcessResponseBare(w, cliCtx, keyOutput)
		rest.WriteSuccessResponse(w, http.StatusOK, true)
	}
}

// DeleteKeyRequestHandler delete key REST handler
func DeleteKeyRequestHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]
	var kb keys.Keybase
	var m DeleteKeyBody

	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&m)
	if err != nil {
		rest.WriteErrorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	kb, err = cli.NewKeyBaseFromHomeFlag()
	if err != nil {
		rest.WriteErrorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}

	err = kb.Delete(name, m.Password, false)
	if keyerror.IsErrKeyNotFound(err) {
		rest.WriteErrorResponse(w, http.StatusNotFound, err.Error())
		return
	} else if keyerror.IsErrWrongPassword(err) {
		rest.WriteErrorResponse(w, http.StatusUnauthorized, err.Error())
		return
	} else if err != nil {
		rest.WriteErrorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}

	rest.WriteSuccessResponse(w, http.StatusOK, true)
}

// getBechKeyOut get Bech Key
func getBechKeyOut(bechPrefix string) (bechKeyOutFn, error) {
	switch bechPrefix {
	case sdk.PrefixAccount:
		return keys.Bech32KeyOutput, nil
	case sdk.PrefixValidator:
		return keys.Bech32ValKeyOutput, nil
	case sdk.PrefixConsensus:
		return keys.Bech32ConsKeyOutput, nil
	}

	return nil, fmt.Errorf("invalid Bech32 prefix encoding provided: %s", bechPrefix)
}

// GetKeyRequestHandlerFn get key REST handler
func GetKeyRequestHandlerFn(cliCtx context.CLIContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		name := vars["name"]
		bechPrefix := r.URL.Query().Get(cli.FlagBechPrefix)

		if bechPrefix == "" {
			bechPrefix = "acc"
		}

		bechKeyOut, err := getBechKeyOut(bechPrefix)
		if err != nil {
			rest.WriteErrorResponse(w, http.StatusBadRequest, err.Error())
			return
		}

		info, err := GetKeyInfo(name)
		if keyerror.IsErrKeyNotFound(err) {
			rest.WriteErrorResponse(w, http.StatusNotFound, err.Error())
			return
		} else if err != nil {
			rest.WriteErrorResponse(w, http.StatusInternalServerError, err.Error())
			return
		}

		keyOutput, err := bechKeyOut(info)
		if err != nil {
			rest.WriteErrorResponse(w, http.StatusInternalServerError, err.Error())
			return
		}

		rest.PostProcessResponseBare(w, cliCtx, keyOutput)
	}
}

// UpdateKeyRequestHandler update key REST handler
func UpdateKeyRequestHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]
	var kb keys.Keybase
	var m UpdateKeyBody

	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&m)
	if err != nil {
		rest.WriteErrorResponse(w, http.StatusNotFound, err.Error())
		return
	}

	kb, err = cli.NewKeyBaseFromHomeFlag()
	if err != nil {
		rest.WriteErrorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}

	getNewpass := func() (string, error) { return m.NewPassword, nil }

	err = kb.Update(name, m.OldPassword, getNewpass)
	if keyerror.IsErrKeyNotFound(err) {
		rest.WriteErrorResponse(w, http.StatusNotFound, err.Error())
		return
	} else if keyerror.IsErrWrongPassword(err) {
		rest.WriteErrorResponse(w, http.StatusUnauthorized, err.Error())
		return
	} else if err != nil {
		rest.WriteErrorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}

	rest.WriteSuccessResponse(w, http.StatusOK, true)
}

///////////////////////
// Utils

// GetKeyInfo returns key info for a given name. An error is returned if the
// keybase cannot be retrieved or getting the info fails.
func GetKeyInfo(name string) (keys.Info, error) {
	keybase, err := cli.NewKeyBaseFromHomeFlag()
	if err != nil {
		return nil, err
	}

	return keybase.Get(name)
}
