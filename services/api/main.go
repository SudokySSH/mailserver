package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/crypto/pbkdf2"
)

//go:embed schema.sql
var schema string

var (
	apiKey        = env("API_KEY", "")
	adminHash     = env("PANEL_ADMIN_HASH", "")
	sessionSecret = env("PANEL_SESSION_SECRET", apiKey)
	mailDomain    = env("MAIL_DOMAIN", "example.com")
	secureCookie  = env("SECURE_COOKIE", "true") == "true"
	db            *sql.DB
	emailRe       = regexp.MustCompile(`^[A-Za-z0-9._%+-]+@` + regexp.QuoteMeta(mailDomain) + `$`)
	localRe       = regexp.MustCompile(`^[a-z0-9._%+-]{1,64}$`)
)

type event struct {
	ID      int64  `json:"id"`
	Ts      string `json:"ts"`
	Type    string `json:"type"`
	Actor   string `json:"actor"`
	Detail  string `json:"detail"`
	IP      string `json:"ip"`
	HMAC    string `json:"hmac"`
	Tampered bool  `json:"tampered"`
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func sign(data []byte) string {
	m := hmac.New(sha256.New, []byte(sessionSecret))
	m.Write(data)
	return hex.EncodeToString(m.Sum(nil))
}

// ---------- аутентификация ----------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func apiKeyOK(r *http.Request) bool {
	return apiKey != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Api-Key")), []byte(apiKey)) == 1
}

func sessionOK(r *http.Request) bool {
	c, err := r.Cookie("aether_session")
	return err == nil && subtle.ConstantTimeCompare([]byte(c.Value), []byte(sessionToken())) == 1
}

func sessionToken() string {
	return sign([]byte("authenticated"))
}

func clientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return host
}

// ---------- HTTP handlers ----------

func healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type loginReq struct {
	Password string `json:"password"`
}

func insertEvent(etype, actor, detail, ip string) {
	ts := time.Now().UTC().Format(time.RFC3339)
	canonical := strings.Join([]string{ts, etype, actor, detail, ip}, "|")
	sig := sign([]byte(canonical))
	_, err := db.Exec(`INSERT INTO audit_events (ts, type, actor, detail, ip, hmac)
		VALUES ($1,$2,$3,$4,$5,$6)`, ts, etype, actor, detail, ip, sig)
	if err != nil {
		log.Printf("audit insert: %v", err)
	}
}

func login(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	if !checkPassword(req.Password, adminHash) {
		insertEvent("login.fail", "unknown", "", clientIP(r))
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	insertEvent("login.ok", "admin", "", clientIP(r))
	c := &http.Cookie{
		Name: "aether_session", Value: sessionToken(), Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: secureCookie,
		MaxAge: 86400,
	}
	http.SetCookie(w, c)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func checkPassword(password, stored string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 3 {
		return false
	}
	salt, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}
	dk := pbkdf2.Key([]byte(password), salt, 200000, 32, sha256.New)
	candidate := "pbkdf2$" + parts[1] + "$" + hex.EncodeToString(dk)
	return subtle.ConstantTimeCompare([]byte(candidate), []byte(stored)) == 1
}

func session(w http.ResponseWriter, r *http.Request) {
	if sessionOK(r) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no session"})
}

// ---------- аудит ----------

func addEvent(w http.ResponseWriter, r *http.Request) {
	if !apiKeyOK(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var e struct {
		Type   string `json:"type"`
		Actor  string `json:"actor"`
		Detail string `json:"detail"`
		IP     string `json:"ip"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&e); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	e.Type = strings.TrimSpace(e.Type)
	if e.Type == "" || len(e.Type) > 64 || len(e.Detail) > 1024 || len(e.Actor) > 128 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid fields"})
		return
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	canonical := strings.Join([]string{ts, e.Type, e.Actor, e.Detail, e.IP}, "|")
	sig := sign([]byte(canonical))
	_, err := db.Exec(`INSERT INTO audit_events (ts, type, actor, detail, ip, hmac)
		VALUES ($1,$2,$3,$4,$5,$6)`, ts, e.Type, e.Actor, e.Detail, e.IP, sig)
	if err != nil {
		log.Printf("audit insert: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "recorded"})
}

func listEvents(w http.ResponseWriter, r *http.Request) {
	if !apiKeyOK(r) && !sessionOK(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 10000 {
		limit = 200
	}
	rows, err := db.Query(`SELECT id, ts, type, actor, detail, ip, hmac
		FROM audit_events ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db"})
		return
	}
	defer rows.Close()
	out := []event{}
	for rows.Next() {
		var e event
		if err := rows.Scan(&e.ID, &e.Ts, &e.Type, &e.Actor, &e.Detail, &e.IP, &e.HMAC); err != nil {
			continue
		}
		canonical := strings.Join([]string{e.Ts, e.Type, e.Actor, e.Detail, e.IP}, "|")
		e.Tampered = !hmac.Equal([]byte(sign([]byte(canonical))), []byte(e.HMAC))
		out = append(out, e)
	}
	writeJSON(w, http.StatusOK, out)
}

// ---------- ящики (управление через docker-mailserver) ----------

func dockerSetup(args ...string) (string, error) {
	cmd := exec.Command("docker", append([]string{"exec", "mailserver", "setup"}, args...)...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func listMailboxes(w http.ResponseWriter, r *http.Request) {
	if !apiKeyOK(r) && !sessionOK(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	out, err := dockerSetup("email", "list")
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": strings.TrimSpace(out)})
		return
	}
	re := regexp.MustCompile(`[A-Za-z0-9._%+-]+@` + regexp.QuoteMeta(mailDomain))
	seen := map[string]bool{}
	boxes := []string{}
	for _, m := range re.FindAllString(out, -1) {
		if !seen[m] {
			seen[m] = true
			boxes = append(boxes, m)
		}
	}
	sort.Strings(boxes)
	writeJSON(w, http.StatusOK, boxes)
}

type mailboxReq struct {
	Local    string `json:"local"`
	Password string `json:"password"`
}

func createMailbox(w http.ResponseWriter, r *http.Request) {
	if !apiKeyOK(r) && !sessionOK(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var req mailboxReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	req.Local = strings.ToLower(strings.TrimSpace(req.Local))
	if !localRe.MatchString(req.Local) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid local part"})
		return
	}
	if len(req.Password) < 8 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password too short"})
		return
	}
	email := req.Local + "@" + mailDomain
	out, err := dockerSetup("email", "add", email, req.Password)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": strings.TrimSpace(out)})
		return
	}
	insertEvent("mailbox.create", "admin", email, clientIP(r))
	writeJSON(w, http.StatusCreated, map[string]string{"email": email})
}

func deleteMailbox(w http.ResponseWriter, r *http.Request) {
	if !apiKeyOK(r) && !sessionOK(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	email := strings.TrimPrefix(r.URL.Path, "/v1/mailboxes/")
	if !emailRe.MatchString(email) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid email"})
		return
	}
	out, err := dockerSetup("email", "del", email)
	if err != nil {
		out2, err2 := dockerSetup("email", "delete", email)
		if err2 != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": strings.TrimSpace(out + out2)})
			return
		}
		out = out2
	}
	insertEvent("mailbox.delete", "admin", email, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"deleted": email})
}

// ---------- main ----------

func method(h http.HandlerFunc, m string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != m {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method"})
			return
		}
		h(w, r)
	}
}

func main() {
	var err error
	db, err = sql.Open("pgx", env("DATABASE_URL", ""))
	if err != nil {
		log.Fatalf("db open: %v", err)
	}
	defer db.Close()
	for i := 0; i < 30; i++ {
		if err = db.Ping(); err == nil {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		log.Fatalf("db ping: %v", err)
	}
	if _, err := db.Exec(schema); err != nil {
		log.Fatalf("schema: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", method(healthz, http.MethodGet))
	mux.HandleFunc("/v1/login", method(login, http.MethodPost))
	mux.HandleFunc("/v1/session", method(session, http.MethodGet))
	mux.HandleFunc("/v1/events", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			listEvents(w, r)
		case http.MethodPost:
			addEvent(w, r)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method"})
		}
	})
	mux.HandleFunc("/v1/mailboxes", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			listMailboxes(w, r)
		case http.MethodPost:
			createMailbox(w, r)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method"})
		}
	})
	mux.HandleFunc("/v1/mailboxes/", method(deleteMailbox, http.MethodDelete))

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	log.Printf("aether-api listening on %s (domain %s)", srv.Addr, mailDomain)
	log.Fatal(srv.ListenAndServe())
}
