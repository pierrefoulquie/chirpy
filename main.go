package main

import (
	"chirpy/internal/auth"
	"chirpy/internal/database"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)
type apiConfig struct{
	fileserverHits atomic.Int32
	db *database.Queries
	platform string
}

type Chirp struct{
	ID uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body string `json:"body"`
	UserID uuid.UUID  `json:"user_id"`
}

type User struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time	`json:"created_at"`
	UpdatedAt time.Time	`json:"updated_at"`
	Email     string	`json:"email"`
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
	if cfg.platform!="dev"{
		respondWithError(w, 403, "Forbidden")
	}else{
		w.WriteHeader(200)
		if err := cfg.db.Reset(r.Context()); err!=nil{
			log.Fatal(err)
		}
		cfg.fileserverHits.Store(0)
		val := cfg.fileserverHits.Load()
		msg := fmt.Sprintf("fileserverHits reset to %v", val)
		w.Write([]byte(msg))
	}
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

func (cfg *apiConfig) handleChirps(w http.ResponseWriter, r *http.Request){
	decoder := json.NewDecoder(r.Body)
	type parameters struct{
		Body string `json:"body"`
		UserID uuid.UUID `json:"user_id"`
	}
	params := parameters{}
	err := decoder.Decode(&params)
	if err!=nil{
		log.Printf("Error decoding parameters: %s", err)
		w.WriteHeader(500)
		return
	}

	if len([]rune(params.Body))>140{
		respondWithError(w, 400, "Chirp is too long")
	}else{
		if data, err :=cfg.db.CreateChirp(r.Context(), database.CreateChirpParams{
			Body: params.Body,
			UserID: params.UserID,
		}); err!=nil{
			log.Fatal(err)
		}else{
			chirp := Chirp{
				ID: data.ID,
				CreatedAt: data.CreatedAt,
				UpdatedAt: data.UpdatedAt,
				Body: data.Body,
				UserID: data.UserID,
			}
			respondWithJSON(w, 201, chirp)
		}
	}
}

func (cfg *apiConfig) handleGetAllChirps(w http.ResponseWriter, r *http.Request){
	if data, err := cfg.db.GetAllChirps(r.Context()); err!=nil{
		log.Fatal(err)
	}else{
		AllChirps := []Chirp{}
		for _, row := range data{
			chirp := Chirp{
				ID: row.ID,
				CreatedAt: row.CreatedAt,
				UpdatedAt: row.UpdatedAt,
				Body: row.Body,
				UserID: row.UserID,
			}
			AllChirps = append(AllChirps, chirp)
		}
		respondWithJSON(w, 200, AllChirps)
	}
}

func (cfg *apiConfig) handleGetChirpById(w http.ResponseWriter, r *http.Request){
	chirpId := uuid.MustParse(r.PathValue("chirpId"))

	if data, err := cfg.db.GetChirpsById(r.Context(), chirpId); err!=nil{
		respondWithError(w, 404, err.Error())
	}else{
		chirp := Chirp{
			ID: data.ID,
			CreatedAt: data.CreatedAt,
			UpdatedAt: data.UpdatedAt,
			Body: data.Body,
			UserID: data.UserID,
		}
		respondWithJSON(w, 200, chirp)
	}
}

func (cfg *apiConfig) handleLogin(w http.ResponseWriter, r *http.Request){
	type parameters struct{
		Password string `json:"password"`
		Email string `json:"email"`
	}
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err!=nil{
		log.Printf("Error decoding parameters: %s", err)
		w.WriteHeader(500)
		return
	}
	if user, err := cfg.db.GetUser(r.Context(), params.Email);err!=nil{
		log.Printf("Error retrieving email: %s", err)
		w.WriteHeader(500)
		return
	}else{
		if err = auth.CheckPasswordHash(params.Password, user.HashedPassword);err!=nil{
			respondWithError(w, 401, err.Error())
		}else{
			data := User{
				ID: user.ID,
				CreatedAt: user.CreatedAt,
				UpdatedAt: user.UpdatedAt,
				Email: user.Email,
			}
			respondWithJSON(w, 200, data)
		}
	}
}

func (cfg *apiConfig) handleUser(w http.ResponseWriter, r *http.Request){
	type parameters struct{
		Password string `json:"password"`
		Email string `json:"email"`
	}
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err!=nil{
		log.Printf("Error decoding parameters: %s", err)
		w.WriteHeader(500)
		return
	}
	if hashedPassword, err := auth.HashPassword(params.Password); err!=nil{
		log.Printf("Password encryption error: %s", err)
		w.WriteHeader(500)
		return
	}else{

		createUserParams := database.CreateUserParams{
			Email: params.Email,
			HashedPassword: hashedPassword,
		}
			
		if data, err := cfg.db.CreateUser(r.Context(), createUserParams); err!=nil{
			log.Fatal(err)
		}else{

			user := User{
				ID: data.ID,
				CreatedAt: data.CreatedAt,
				UpdatedAt: data.UpdatedAt,
				Email: data.Email,
			}
			respondWithJSON(w, 201, user)
		}
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
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err!=nil{
		log.Fatal(err)
	}
	apiCfg := &apiConfig{}
	apiCfg.fileserverHits.Store(0)
	apiCfg.db = database.New(db)
	apiCfg.platform = os.Getenv("PLATFORM")
	mux := http.NewServeMux()	
	fs := http.FileServer(http.Dir("."))
	fsHandler := http.StripPrefix("/app", fs)
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(fsHandler))
	mux.HandleFunc("GET /api/healthz", handle)
	mux.HandleFunc("POST /api/validate_chirp", apiCfg.handleValidate)
	mux.HandleFunc("POST /api/login", apiCfg.handleLogin)
	mux.HandleFunc("POST /api/chirps", apiCfg.handleChirps)
	mux.HandleFunc("GET /api/chirps", apiCfg.handleGetAllChirps)
	mux.HandleFunc("GET /api/chirps/{chirpId}", apiCfg.handleGetChirpById)
	mux.HandleFunc("POST /api/users", apiCfg.handleUser)
	mux.HandleFunc("GET /admin/metrics", apiCfg.handleMetrics)
	mux.HandleFunc("POST /admin/reset", apiCfg.handleReset)
	server := http.Server{
		Addr: ":8080",
		Handler: mux,
	}
	server.ListenAndServe()
}
