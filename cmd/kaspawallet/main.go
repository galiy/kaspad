package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/kaspanet/kaspad/cmd/kaspawallet/daemon/client"
	"github.com/kaspanet/kaspad/cmd/kaspawallet/daemon/pb"
	"github.com/kaspanet/kaspad/cmd/kaspawallet/keys"
	"github.com/kaspanet/kaspad/cmd/kaspawallet/libkaspawallet"
	"github.com/pkg/errors"
)

var sconf *sendConfig

type hRpcResult struct {
	Result   int8     `json:"result"`
	TxIds    []string `json:"txs"`
	ErrorMsg string   `json:"error"`
}

func rpcRetAny(w http.ResponseWriter, r *http.Request, rObj any) {
	jMsg, err := json.Marshal(rObj)

	if err != nil {
		log.Printf("Error Marshal jMsg %s", err.Error())
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.Write(jMsg)
}

func rpcRetAll(w http.ResponseWriter, r *http.Request) {
	var aMsg any
	var err error
	switch r.URL.Path {
	case "/SendMoney":
		sWallet := r.URL.Query().Get("wallet")
		sAmount := r.URL.Query().Get("amount")
		sPassword := r.URL.Query().Get("password")

		keysFile, err := keys.ReadKeysFile(sconf.NetParams(), sconf.KeysFile)

		if err == nil {
			if len(keysFile.ExtendedPublicKeys) > len(keysFile.EncryptedMnemonics) {
				err = errors.New("Cannot use 'send' command for multisig wallet without all of the keys")
			}
		}

		var daemonClient pb.KaspawalletdClient
		var tearDown func()

		if err == nil {
			daemonClient, tearDown, err = client.Connect(sconf.DaemonAddress)
			if err == nil {
				defer tearDown()
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), daemonTimeout)
		defer cancel()

		var sendAmountSompi uint64
		sendAmountSompi, err = strconv.ParseUint(sAmount, 10, 64)

		var createUnsignedTransactionsResponse *pb.CreateUnsignedTransactionsResponse

		if err == nil {
			createUnsignedTransactionsResponse, err =
				daemonClient.CreateUnsignedTransactions(ctx, &pb.CreateUnsignedTransactionsRequest{
					From:                     sconf.FromAddresses,
					Address:                  sWallet,
					Amount:                   sendAmountSompi,
					IsSendAll:                false,
					UseExistingChangeAddress: sconf.UseExistingChangeAddress,
				})
		}

		var mnemonics []string

		if err == nil {
			mnemonics, err = keysFile.DecryptMnemonics(sPassword)
			if err != nil {
				if strings.Contains(err.Error(), "message authentication failed") {
					fmt.Fprintf(os.Stderr, "Password decryption failed. Sometimes this is a result of not "+
						"specifying the same keys file used by the wallet daemon process.\n")
				}
			}
		}

		var signedTransactions [][]byte

		if err == nil {
			signedTransactions = make([][]byte, len(createUnsignedTransactionsResponse.UnsignedTransactions))
			for i, unsignedTransaction := range createUnsignedTransactionsResponse.UnsignedTransactions {
				signedTransaction, err := libkaspawallet.Sign(sconf.NetParams(), mnemonics, unsignedTransaction, keysFile.ECDSA)
				if err == nil {
					signedTransactions[i] = signedTransaction
				}
			}
		}

		var broadcastCtx context.Context
		var broadcastCancel context.CancelFunc

		if err == nil {
			if len(signedTransactions) > 1 {
				fmt.Printf("Broadcasting %d transactions\n", len(signedTransactions))
			}
			// Since we waited for user input when getting the password, which could take unbound amount of time -
			// create a new context for broadcast, to reset the timeout.
			broadcastCtx, broadcastCancel = context.WithTimeout(context.Background(), daemonTimeout)
			defer broadcastCancel()
		}

		var respIDs []string

		if err == nil {
			response, err := daemonClient.Broadcast(broadcastCtx, &pb.BroadcastRequest{Transactions: signedTransactions})
			if err == nil {
				fmt.Println("Transactions were sent successfully")
				fmt.Println("Transaction ID(s): ")
				respIDs = response.TxIDs
				for _, txID := range response.TxIDs {
					fmt.Printf("\t%s\n", txID)
				}
			}
		}

		if err == nil {
			aMsg = &hRpcResult{
				Result:   0,
				TxIds:    respIDs,
				ErrorMsg: "",
			}
		}

	default:
		err = nil
		aMsg = &hRpcResult{
			Result:   1,
			ErrorMsg: "No rpc procedure found for path " + r.URL.Path,
		}
	}

	if err != nil {
		aMsg = &hRpcResult{
			Result:   1,
			ErrorMsg: err.Error(),
		}
	}
	rpcRetAny(w, r, aMsg)
}

func startHttp() {
	http.HandleFunc("/", rpcRetAll)
	log.Printf("Listening to HTTP on %s", "localhost:16117")
	fmt.Fprintf(os.Stderr, "%s\n", http.ListenAndServe(":16117", nil))
}

func main() {
	subCmd, config := parseCommandLine()

	var err error

	//sconf = config.(*sendConfig)

	go startHttp()

	switch subCmd {
	case createSubCmd:
		err = create(config.(*createConfig))
	case balanceSubCmd:
		err = balance(config.(*balanceConfig))
	case sendSubCmd:
		err = send(config.(*sendConfig))
	case createUnsignedTransactionSubCmd:
		err = createUnsignedTransaction(config.(*createUnsignedTransactionConfig))
	case signSubCmd:
		err = sign(config.(*signConfig))
	case broadcastSubCmd:
		err = broadcast(config.(*broadcastConfig))
	case parseSubCmd:
		err = parse(config.(*parseConfig))
	case showAddressesSubCmd:
		err = showAddresses(config.(*showAddressesConfig))
	case newAddressSubCmd:
		err = newAddress(config.(*newAddressConfig))
	case dumpUnencryptedDataSubCmd:
		err = dumpUnencryptedData(config.(*dumpUnencryptedDataConfig))
	case startDaemonSubCmd:
		err = startDaemon(config.(*startDaemonConfig))
	case sweepSubCmd:
		err = sweep(config.(*sweepConfig))
	default:
		err = errors.Errorf("Unknown sub-command '%s'\n", subCmd)
	}

	if err != nil {
		printErrorAndExit(err)
	}
}
