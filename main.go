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
	"sort"
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
	secret string
	polkaKey string
}

type Chirp struct{
	ID uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body string `json:"body"`
	UserID uuid.UUID  `json:"user_id"`
}

type LoginResp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time	`json:"created_at"`
	UpdatedAt time.Time	`json:"updated_at"`
	Email     string	`json:"email"`
	Token     string	`json:"token"`
	RefreshToken     string	`json:"refresh_token"`
	IsChirpyRed	  bool		`json:"is_chirpy_red"`
}

type User struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time	`json:"created_at"`
	UpdatedAt time.Time	`json:"updated_at"`
	Email     string	`json:"email"`
	IsChirpyRed	  bool		`json:"is_chirpy_red"`
}

type RefreshToken struct {
	Token string `json:"token"`
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
		return
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

func respondWithJSON(w http.ResponseWriter, code int, payload any){
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
		return
	}else{
		respondWithJSON(w, 200, data)
	}
}

func (cfg *apiConfig) handleChirps(w http.ResponseWriter, r *http.Request){
	decoder := json.NewDecoder(r.Body)
	type parameters struct{
		Body string `json:"body"`
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
		return
	}else{
		tokenStr, err := auth.GetBearerToken(r.Header)
		if err!=nil{
			log.Fatal(err)
		}else{
			userID, err := auth.ValidateJWT(tokenStr, cfg.secret)
			if err!=nil{
				respondWithError(w, 401, "invalid or missing access token")
				return
			}else{


				if data, err :=cfg.db.CreateChirp(r.Context(), database.CreateChirpParams{
					Body: params.Body,
					UserID: userID,
				}); err!=nil{
					respondWithError(w, 400, err.Error())
					return
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
	}
}

func (cfg *apiConfig) handleGetAllChirps(w http.ResponseWriter, r *http.Request){
	authIDStr := r.URL.Query().Get("author_id")
	sortStr := r.URL.Query().Get("sort")
	var data []database.Chirp
	var err error

	// If empty author
	if authIDStr == ""{
		if data, err = cfg.db.GetAllChirps(r.Context()); err!=nil{
			log.Fatal(err)
		}
	// If identified author
	}else{
		authorID, err := uuid.Parse(authIDStr)
		if err!=nil{
			respondWithError(w, 500, "Server error")
			return
		}
		if data, err = cfg.db.GetChirpsFromUser(r.Context(), authorID); err!=nil{
			log.Fatal(err)
		}
	}
	// Chirps have beend retrieved
	
	Chirps := make([]Chirp, 0, len(data))
	// Chirps := []Chirp{}
	for _, row := range data{
		chirp := Chirp{
			ID: row.ID,
			CreatedAt: row.CreatedAt,
			UpdatedAt: row.UpdatedAt,
			Body: row.Body,
			UserID: row.UserID,
		}
		Chirps = append(Chirps, chirp)
	}
	// Sort if needed
	if sortStr == "desc"{
		sort.Slice(Chirps, func(i, j int) bool { return Chirps[i].CreatedAt.After(Chirps[j].CreatedAt)})
	}
	respondWithJSON(w, 200, Chirps)
}

func (cfg *apiConfig) handleGetChirpByID(w http.ResponseWriter, r *http.Request){
	chirpID := uuid.MustParse(r.PathValue("chirpId"))

	if data, err := cfg.db.GetChirpsById(r.Context(), chirpID); err!=nil{
		respondWithError(w, 404, err.Error())
		return
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

func (cfg *apiConfig) handleDeleteChirpByID(w http.ResponseWriter, r *http.Request){
	tokenStr, err := auth.GetBearerToken(r.Header)
	if err!=nil{
		respondWithError(w, 401, "invalid or missing token")
		return
	}else{
		tokenUserID, err := auth.ValidateJWT(tokenStr, cfg.secret)
		if err!=nil{
			respondWithError(w, 401, "invalid or missing access token")
			return
		}else{
			chirpID := uuid.MustParse(r.PathValue("chirpId"))
			if chirp, err := cfg.db.GetChirpsById(r.Context(), chirpID); err!=nil{
				respondWithError(w, 404, err.Error())
				return
			}else{
				if chirp.UserID != tokenUserID{
					respondWithError(w, 403, "Wrong user")
					return
				}
				err := cfg.db.DeleteChirpsById(r.Context(), chirpID)
				if err!=nil{
					respondWithError(w, 500, "Server error")
					return
				}else{
					respondWithJSON(w, 204, nil) 
				}
			}
		}
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
		token, err := auth.MakeJWT(user.ID, cfg.secret)
		if err!=nil{
			respondWithError(w, 401, err.Error())
			return
		}
		if err = auth.CheckPasswordHash(params.Password, user.HashedPassword);err!=nil{
			respondWithError(w, 401, err.Error())
			return
		}else{
			refreshToken, err := auth.MakeRefreshToken()
			refreshTokenParams := database.GenerateRefreshTokenParams{
				Token: refreshToken,
				UserID: user.ID,
			}
			cfg.db.GenerateRefreshToken(r.Context(), refreshTokenParams)
			if err!=nil{
				respondWithError(w, 401, err.Error())
				return
			}
			data := LoginResp{
				ID: user.ID,
				CreatedAt: user.CreatedAt,
				UpdatedAt: user.UpdatedAt,
				Email: user.Email,
				Token: token,
				RefreshToken: refreshToken,
				IsChirpyRed: user.IsChirpyRed,
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
				IsChirpyRed: data.IsChirpyRed,
			}
			respondWithJSON(w, 201, user)
		}
	}
}

func (cfg *apiConfig) handlePutUser(w http.ResponseWriter, r *http.Request){
	tokenStr, err := auth.GetBearerToken(r.Header)
	if err!=nil{
		respondWithError(w, 401, "invalid or missing token")
		return
	}else{
		userID, err := auth.ValidateJWT(tokenStr, cfg.secret)
		if err!=nil{
			respondWithError(w, 401, "invalid or missing access token")
			return
		}else{
			type parameters struct{
				Password string `json:"password"`
				Email string `json:"email"`
			}
			decoder := json.NewDecoder(r.Body)
			params := parameters{}
			err := decoder.Decode(&params)
			if err!=nil{
				respondWithError(w, 500, "server error")
				return
			}else{
				if hashedPassword, err := auth.HashPassword(params.Password); err!=nil{
					respondWithError(w, 500, "Password encryption error")
					return
				}else{
					updateUserParams := database.UpdateUserParams{
						ID: userID,
						Email: params.Email,
						HashedPassword: hashedPassword,
					}
					updateUserRow, err := cfg.db.UpdateUser(r.Context(), updateUserParams)
					if err!=nil{
						respondWithError(w, 500, "server error")
						return
					}else{
						updatedUser := User{
							ID: userID,
							CreatedAt: updateUserRow.CreatedAt,
							UpdatedAt: updateUserRow.UpdatedAt,
							Email: updateUserRow.Email,
							IsChirpyRed: updateUserRow.IsChirpyRed,
						}
						respondWithJSON(w, 200, updatedUser)
					}
				}
			}
		}
	}
}

func (cfg *apiConfig) handleRefresh(w http.ResponseWriter, r *http.Request){
	tokenStr, err := auth.GetBearerToken(r.Header)
	if err!=nil{
		respondWithError(w, 401, "invalid or missing refresh token")
		return
	}else{
		refreshToken, err := cfg.db.ValidateRefreshToken(r.Context(), tokenStr)
		if err!=nil{
			respondWithError(w, 401, "invalid or missing refresh token")
			return
		}else{
			if refreshToken.Token == ""{
				respondWithError(w, 401, "missing token")
				return
			}else if time.Now().After(refreshToken.ExpiresAt){ 
				respondWithError(w, 401, "expired token")
				return
			}else if refreshToken.RevokedAt.Valid { 
				respondWithError(w, 401, "revoked token")
				return
			}else{
				token, err := auth.MakeJWT(refreshToken.UserID, cfg.secret)
				if err!=nil{
					respondWithError(w, 500, "server error")
					return
				}else{
					data := RefreshToken{
						Token: token,
					}
					respondWithJSON(w, 200, data)
				}
			}

		}
	}
}

func (cfg *apiConfig) handleRevoke(w http.ResponseWriter, r *http.Request){
	tokenStr, err := auth.GetBearerToken(r.Header)
	if err!=nil{
		respondWithError(w, 401, "invalid or missing refresh token")
		return
	}else{
		err = cfg.db.RevokeRefreshToken(r.Context(), tokenStr)
		if err!=nil{
			respondWithError(w, 500, err.Error())
			return
		}
		respondWithJSON(w, 204, nil) 
	}
}

func (cfg *apiConfig) handleWebhook(w http.ResponseWriter, r *http.Request){
	headerPolkaKey, err := auth.GetAPIKey(r.Header)
	if err!=nil{
		respondWithError(w, 401, err.Error())
		return
	}
	if headerPolkaKey != cfg.polkaKey{
		respondWithError(w, 401, "wrong key")
		return
	}
	type data struct{
		UserID uuid.UUID `json:"user_id"`
	}
	type parameters struct{
		Event 	string 	`json:"event"`
		Data 	data	`json:"data"`
	}
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err = decoder.Decode(&params)
	if err!=nil{
		respondWithError(w, 500, err.Error())
		return
	}
	if params.Event != "user.upgraded"{
		respondWithError(w, 204, "")
		return
	}
	err = cfg.db.UpdateToRed(r.Context(), params.Data.UserID)
	if err!=nil{
		respondWithError(w, 404, err.Error())
		return
	}
	respondWithJSON(w, 204, "")
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
	apiCfg.secret = os.Getenv("SECRET")
	apiCfg.polkaKey = os.Getenv("POLKA_KEY")

	mux := http.NewServeMux()	
	fs := http.FileServer(http.Dir("."))
	fsHandler := http.StripPrefix("/app", fs)
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(fsHandler))
	mux.HandleFunc("GET /api/healthz", handle)
	mux.HandleFunc("POST /api/validate_chirp", apiCfg.handleValidate)
	mux.HandleFunc("POST /api/login", apiCfg.handleLogin)
	mux.HandleFunc("POST /api/chirps", apiCfg.handleChirps)
	mux.HandleFunc("GET /api/chirps", apiCfg.handleGetAllChirps)
	mux.HandleFunc("GET /api/chirps/{chirpId}", apiCfg.handleGetChirpByID)
	mux.HandleFunc("DELETE /api/chirps/{chirpId}", apiCfg.handleDeleteChirpByID)
	mux.HandleFunc("POST /api/users", apiCfg.handleUser)
	mux.HandleFunc("PUT /api/users", apiCfg.handlePutUser)
	mux.HandleFunc("POST /api/refresh", apiCfg.handleRefresh)
	mux.HandleFunc("POST /api/revoke", apiCfg.handleRevoke)
	mux.HandleFunc("POST /api/polka/webhooks", apiCfg.handleWebhook)
	mux.HandleFunc("GET /admin/metrics", apiCfg.handleMetrics)
	mux.HandleFunc("POST /admin/reset", apiCfg.handleReset)
	server := http.Server{
		Addr: ":8080",
		Handler: mux,
	}
	server.ListenAndServe()
}
