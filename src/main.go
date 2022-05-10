package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/apexskier/httpauth"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
)

var (
	aaa         httpauth.Authorizer
	backendfile = "auth.leveldb"
	roles       map[string]httpauth.Role
	backend     httpauth.LeveldbAuthBackend
)

const (
	asciiZero = 48
	asciiTen  = 57
)

type creditCard struct {
	number     string
	expireDate string
	currency   string
	amount     int
	CVV        string
	billing    int
}

type transactionsMGR struct {
	mut                sync.Mutex
	transactions       map[string]creditCard
	blockedTransaction []string
	clients            map[string]string
}

var transMngr transactionsMGR

func findTransactionOnBlackList(id string, transactions []string) bool {
	for _, trans := range transactions {
		if trans == id {
			return true
		}
	}
	return false
}

// luhnValidation returns an error if the provided string does not pass the luhn check.
func luhnValidation(number string) error {
	p := len(number) % 2
	sum, err := calculateLuhnSum(number, p)
	if err != nil {
		return err
	}

	// If the total modulo 10 is not equal to 0, then the number is invalid.
	if sum%10 != 0 {
		return fmt.Errorf("invalid number")
	}

	return nil
}
func calculateLuhnSum(number string, parity int) (int64, error) {
	var sum int64
	for i, d := range number {
		if d < asciiZero || d > asciiTen {
			return 0, errors.New("invalid digit")
		}

		d = d - asciiZero
		// Double the value of every second digit.
		if i%2 == parity {
			d *= 2
			// If the result of this doubling operation is greater than 9.
			if d > 9 {
				// The same final result can be found by subtracting 9 from that result.
				d -= 9
			}
		}

		// Take the sum of all the digits.
		sum += int64(d)
	}

	return sum, nil
}

func createTransaction(w http.ResponseWriter, r *http.Request) {
	id := uuid.New().String()
	var cli creditCard
	val := r.URL.Query().Get("number")
	err := luhnValidation(val)
	if err != nil {
		http.Error(w, "credit card "+val+" "+err.Error(), http.StatusBadRequest)
		return
	}
	cli.number = val
	val = r.URL.Query().Get("expireDate")
	cli.expireDate = val
	val = r.URL.Query().Get("currency")
	if val == "" {
		http.Error(w, "incorrect currency "+cli.number+": authorisation failure", http.StatusBadRequest)
		return
	}
	cli.currency = val
	val = r.URL.Query().Get("CVV")
	if val == "" {
		http.Error(w, "incorrect CVV "+cli.number+": authorisation failure", http.StatusBadRequest)
		return
	}
	cli.CVV = val
	val = r.URL.Query().Get("amount")
	amo, err := strconv.Atoi(val)
	if err != nil {
		http.Error(w, "incorrect ammount "+cli.number+": authorisation failure", http.StatusBadRequest)
		return
	}
	cli.amount = amo
	w.Write([]byte("ciustommerID: " + id + " ammount available: " + strconv.Itoa(cli.amount)))
	transMngr.transactions[id] = cli
}

func captureTransaction(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("number")
	if id == "" {
		http.Error(w, "lack custommer ID", http.StatusBadRequest)
		return
	}
	custommer, found := transMngr.transactions[id]
	if !found {
		http.Error(w, "wrong transaction numer", http.StatusBadRequest)
		return
	}
	val := r.URL.Query().Get("amount")
	amo, err := strconv.Atoi(val)
	if err != nil {
		http.Error(w, "incorrect ammount "+custommer.number+": capture failure", http.StatusBadRequest)
		return
	}
	custommer.billing += amo
	custommer.amount -= amo
	w.Write([]byte("Ammout available: " + strconv.Itoa(custommer.amount) + " currency " + custommer.currency))
	transMngr.mut.Lock()
	transMngr.transactions[id] = custommer
	transMngr.mut.Unlock()
}

func voidTransaction(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("number")
	if id == "" {
		http.Error(w, "lack custommer ID", http.StatusBadRequest)
		return
	}
	custommer, found := transMngr.transactions[id]
	if !found {
		http.Error(w, "wrong transaction numer", http.StatusBadRequest)
		return
	}
	custommer.amount += custommer.billing
	w.Write([]byte("Ammout available: " + strconv.Itoa(custommer.amount) + " currency " + custommer.currency))
	transMngr.mut.Lock()
	transMngr.transactions[id] = custommer
	transMngr.mut.Unlock()
}

func refundTransaction(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("number")
	if id == "" {
		http.Error(w, "lack custommer ID", http.StatusBadRequest)
		return
	}
	custommer, found := transMngr.transactions[id]
	if !found {
		http.Error(w, "wrong transaction numer", http.StatusBadRequest)
		return
	}
	if findTransactionOnBlackList(id, transMngr.blockedTransaction) {
		http.Error(w, "Transaction already refunded", http.StatusBadRequest)
		return
	}
	transMngr.blockedTransaction = append(transMngr.blockedTransaction, id)
	val := r.URL.Query().Get("amount")
	amo, err := strconv.Atoi(val)
	if err != nil {
		http.Error(w, "incorrect ammount "+custommer.number+": refund failure", http.StatusBadRequest)
		return
	}
	custommer.amount += amo
	w.Write([]byte("Ammout available: " + strconv.Itoa(custommer.amount) + " currency " + custommer.currency))
	custommer.billing = 0
	transMngr.mut.Lock()
	transMngr.transactions[id] = custommer
	transMngr.mut.Unlock()
}

func login(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	password := r.URL.Query().Get("password")
	if err := aaa.Login(w, r, username, password, "/"); err == nil || (err != nil && strings.Contains(err.Error(), "already authenticated")) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	} else if err != nil {
		fmt.Println(err)
	}
}

func init() {
	transMngr.clients = make(map[string]string)
	transMngr.transactions = map[string]creditCard{}
	transMngr.clients["test"] = "test"
	var err error
	os.Mkdir(backendfile, 0755)
	defer os.Remove(backendfile)

	// create the backend
	backend, err = httpauth.NewLeveldbAuthBackend(backendfile)
	if err != nil {
		panic(err)
	}

	// create some default roles
	roles = make(map[string]httpauth.Role)
	roles["user"] = 30
	roles["admin"] = 80
	aaa, err = httpauth.NewAuthorizer(backend, []byte("cookie-encryption-key"), "user", roles)
	if err != nil {
		panic(err)
	}

	// create a default user
	username := "user"
	defaultUser := httpauth.UserData{Username: username, Role: "user"}
	err = backend.SaveUser(defaultUser)
	if err != nil {
		panic(err)
	}
	// Update user with a password and email address
	err = aaa.Update(nil, nil, username, "test", "user@localhost.com")
	if err != nil {
		panic(err)
	}
}

func main() {

	router := chi.NewRouter()
	router.Use(middleware.Logger)
	router.Post("/login", login)
	router.Get("/authorize", createTransaction)
	router.Get("/capture", captureTransaction)
	router.Get("/void", voidTransaction)
	router.Get("/refund", refundTransaction)
	http.ListenAndServe(":3001", router)
}
