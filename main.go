package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
)

type apiConfig struct{
	fileserverHits atomic.Int32
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request){
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w,r)
	})
}

func handle(w http.ResponseWriter, r *http.Request){
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	w.Write([]byte("OK"))
}

func (cfg *apiConfig) handleMetrics(w http.ResponseWriter, r *http.Request){
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	val := cfg.fileserverHits.Load()
	msg := fmt.Sprintf("<html><body><h1>Welcome, Chirpy Admin</h1><p>Chirpy has been visited %d times!</p></body></html>", val)
	w.Write([]byte(msg))
}

func (cfg *apiConfig) handleReset(w http.ResponseWriter, r *http.Request){
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	cfg.fileserverHits.Store(0)
	val := cfg.fileserverHits.Load()
	msg := fmt.Sprintf("fileserverHits reset to %v", val)
	w.Write([]byte(msg))
}

func respondWithError(w http.ResponseWriter, code int, msg string){
	type returnError struct{
		Error string `json:"error"`
	}
	r := returnError{
		Error: msg,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	if err := json.NewEncoder(w).Encode(r); err!=nil{
		log.Printf("Error marshalling JSON %v", err)
		w.Write([]byte(`{"error":"internal server error"}`))
	}
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}){
	data, err := json.Marshal(payload)
	if err!=nil{
		log.Printf("Error marshalling JSON %v", err)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(data)
}

func (cfg *apiConfig) handleValidate(w http.ResponseWriter, r *http.Request){
	type parameters struct{
		Body string `json:"body"`
	}
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err!=nil{
		log.Printf("Error decoding parameters: %s", err)
		w.WriteHeader(500)
		return
	}

	type returnValid struct{
		Valid 		bool 	`json:"valid"`
		CleanedBody string 	`json:"cleaned_body"`
	}
	data := returnValid{
		Valid:  true,
		CleanedBody: cleanMsg(params.Body),
	}

	if len([]rune(params.Body))>140{
		respondWithError(w, 400, "Chirp is too long")
	}else{
		respondWithJSON(w, 200, data)
	}
}

func cleanMsg(msg string) string{
	words := strings.Split(msg, " ")
	cleanWords := []string{}
	for _, word := range words{
		cleanWords = append(cleanWords, lowCaseCheckPr(word))
	}
	return strings.Join(cleanWords, " ")
}
func lowCaseCheckPr(word string) string{
	profanities := make(map[string]struct{})
	profanities["kerfuffle"] = struct{}{}
	profanities["sharbert"] = struct{}{}
	profanities["fornax"] = struct{}{}

	_, ok := profanities[strings.ToLower(word)]
	if ok{
		return "****"
	}
	return word
}

func main() {
	apiCfg := &apiConfig{}
	apiCfg.fileserverHits.Store(0)
	mux := http.NewServeMux()	
	fs := http.FileServer(http.Dir("."))
	fsHandler := http.StripPrefix("/app", fs)
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(fsHandler))
	mux.HandleFunc("GET /api/healthz", handle)
	mux.HandleFunc("POST /api/validate_chirp", apiCfg.handleValidate)
	mux.HandleFunc("GET /admin/metrics", apiCfg.handleMetrics)
	mux.HandleFunc("POST /admin/reset", apiCfg.handleReset)
	server := http.Server{
		Addr: ":8080",
		Handler: mux,
	}
	server.ListenAndServe()
}
