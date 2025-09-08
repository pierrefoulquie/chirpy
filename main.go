package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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
		Valid bool `json:"valid"`
	}
	type returnError struct{
		Error string `json:"error"`
	}
	if len([]rune(params.Body))>140{
		respBody := returnError{}
		respBody.Error = "Chirp is too long"
		if data, err := json.Marshal(respBody); err!=nil{
			log.Printf("Error marshalling JSON: %s", err)
		}else{
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(400)
			w.Write(data)
		}

	}else{
		respBody := returnValid{}
		respBody.Valid = true 
		if data, err := json.Marshal(respBody); err!=nil{
			log.Printf("Error marshalling JSON: %s", err)
		}else{
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			w.Write(data)
		}
	}
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
