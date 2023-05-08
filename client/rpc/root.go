package rpc

import (
	"github.com/gorilla/mux"

	"github.com/cosmos/cosmos-sdk/client/context"
)

// Register REST endpoints
func RegisterRPCRoutes(cliCtx context.CLIContext, r *mux.Router) {
	r.HandleFunc("/node_info", NodeInfoRequestHandlerFn(cliCtx)).Methods("GET")
	r.HandleFunc("/syncing", NodeSyncingRequestHandlerFn(cliCtx)).Methods("GET")
	r.HandleFunc("/blocks/latest", LatestBlockRequestHandlerFn(cliCtx)).Methods("GET")
	r.HandleFunc("/blocks/{height}", BlockRequestHandlerFn(cliCtx)).Methods("GET")
	r.HandleFunc("/validatorsets/latest", LatestValidatorSetRequestHandlerFn(cliCtx)).Methods("GET")
	r.HandleFunc("/validatorsets/{height}", ValidatorSetRequestHandlerFn(cliCtx)).Methods("GET")
}

// Register REST endpoints
func RegisterKeysRoutes(cliCtx context.CLIContext, r *mux.Router) {
	r.HandleFunc("/keys", QueryKeysRequestHandlerFn(cliCtx)).Methods("GET")
	r.HandleFunc("/keys", AddNewKeyRequestHandlerFn(cliCtx)).Methods("POST")
	r.HandleFunc("/keys/mnemonic", SeedRequestHandlerFn(cliCtx)).Methods("GET")
	r.HandleFunc("/keys/{name}/recover", RecoverRequestHandlerFn(cliCtx)).Methods("POST")
	r.HandleFunc("/keys/{name}", GetKeyRequestHandlerFn(cliCtx)).Methods("GET")
	// r.HandleFunc("/keys/{name}", UpdateKeyRequestHandler).Methods("PUT")
	// r.HandleFunc("/keys/{name}", DeleteKeyRequestHandler).Methods("DELETE")
}
