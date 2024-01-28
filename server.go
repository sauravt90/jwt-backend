package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
)

type Server struct {
	Address string
}

type ErrorResponse struct {
	Error string
	Code  int
}

var listOfAccounts []IdPass

func init() {
	listOfAccounts = make([]IdPass, 0)
	for i := 0; i < 5; i++ {
		idpass := IdPass{
			Id:       "id" + strconv.Itoa(i),
			Password: "pass" + strconv.Itoa(i),
		}
		listOfAccounts = append(listOfAccounts, idpass)
	}
}

func NewServer(address string) (s *Server) {
	return &Server{Address: address}
}

func (s *Server) Run() {
	router := mux.NewRouter()
	router.Use(CORS)
	router.HandleFunc("/getUsers", handGetAllUsers).Methods("GET")
	router.HandleFunc("/test1", handleTest1).Methods("GET")
	router.HandleFunc("/sigin", middleWare(handleSignin)).Methods("POST")
	router.HandleFunc("/lognin", handleLogin).Methods("POST")
	router.HandleFunc("/test", validate(handleSecurePage)).Methods("GET", "OPTIONS")
	router.HandleFunc("/refresh_token", handleRefreshToken).Methods("POST", "OPTIONS")
	// router.handleFunc("/info",WithJWT(handleSignin)).Methods("POST")
	// router.handleFunc("/about",handleSignin).Methods("POST")

	fmt.Println("server started listing on address", s.Address)

	http.ListenAndServe(":8081", router)
	http.ListenAndServe(s.Address, router)
}

func handGetAllUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(listOfAccounts)
}
func handleTest1(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	w.Write([]byte("hey its me"))
}

func CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Set headers
		w.Header().Set("Access-Control-Allow-Headers", "Token,token,Content-Type")
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
		w.Header().Set("Access-Control-Allow-Methods", "*")

		fmt.Println("in middleware", r)

		if r.Method == "OPTIONS" {
			fmt.Println("in options")
			w.WriteHeader(http.StatusOK)
			return
		}

		fmt.Println("ok")

		// Next
		next.ServeHTTP(w, r)
		return
	})
}

func middleWare(fun http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), "time", time.Now()))
		fun(w, r)
	}

}

func validate(fun http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Token")
		fmt.Println("token is ", token)
		claims, err := ValidateToken(token, "accessToken")
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(string("invalid token refresh the token")))
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), "claims", claims))
		fun(w, r)
	}
}
func handleSignin(w http.ResponseWriter, r *http.Request) {
	var idPass IdPass

	json.NewDecoder(r.Body).Decode(&idPass)

	fmt.Println(listOfAccounts)
	for _, val := range listOfAccounts {
		fmt.Println("val is ", val)
		if val.Id == idPass.Id {
			w.WriteHeader(404)
			fmt.Println("request body is ", idPass.Id, idPass.Password)
			w.Write([]byte(string("account with id already exists")))
			return
		}
	}

	listOfAccounts = append(listOfAccounts, idPass)
	fmt.Println("request body is ", idPass.Id, idPass.Password)
	w.Header().Add("Content-Type", "application/json")
	fmt.Println(time.Now().Sub(r.Context().Value("time").(time.Time)).Seconds() * 1000)

	json.NewEncoder(w).Encode(idPass)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	var idPass IdPass

	json.NewDecoder(r.Body).Decode(&idPass)

	fmt.Println(listOfAccounts)
	for _, val := range listOfAccounts {
		fmt.Println("val is ", val)
		if val.Id == idPass.Id {
			if val.Password == idPass.Password {
				fmt.Println("request body is ", idPass.Id, idPass.Password)
				w.Header().Add("Content-Type", "application/json")
				tokenString, refreshToken, err := CreateToken(val.Id)
				if err != nil {
					errResp := ErrorResponse{Error: err.Error(), Code: 404}
					w.Header().Set("Access-Control-Allow-Credentials", "true")
					w.WriteHeader(http.StatusBadRequest)
					json.NewEncoder(w).Encode(errResp)
					return
				}
				tkn := Token{Token: tokenString}
				coockie := http.Cookie{
					Name:  "jid",
					Value: refreshToken,
				}
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				http.SetCookie(w, &coockie)
				json.NewEncoder(w).Encode(tkn)
				return
			}
		}
	}
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte("please enter correct credentials id or password is incorrect"))
}

func handleSecurePage(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims")
	fmt.Println("claims is ", claims)
	w.Write([]byte("<h1>You Have Successfully </h1>"))
}

func handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("jid")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	refreshToken := cookie.Value
	claims, err := ValidateToken(refreshToken, "refreshToken")
	if err != nil {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(string("invalid refresh token")))
		return
	}
	userName, err := claims.GetSubject()
	if err != nil {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(string("invalid refresh token")))
		return
	}
	accessToken, newRefreshToken, err := CreateToken(userName)
	if err != nil {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(string("invalid refresh token")))
		return
	}
	tkn := Token{Token: accessToken}
	coockie := http.Cookie{
		Name:  "jid",
		Value: newRefreshToken,
	}
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	http.SetCookie(w, &coockie)
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tkn)

}
