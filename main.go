package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Config struct {
	ListenAddr           string        `json:"listen_addr"`             // e.g. ":8080"
	CAPEBaseURL          string        `json:"cape_base_url"`           // e.g. "https://capesandbox.local"
	CAPEAPIToken         string        `json:"cape_api_token"`          // optional; if nepoužíváš, nech prázdné
	CAPEUploadPath       string        `json:"cape_upload_path"`        // e.g. "/apiv2/tasks/create/file"  (ponech konfigurovatelné)
	CAPEStatusPath       string        `json:"cape_status_path"`        // e.g. "/apiv2/tasks/view/{id}"
	CAPEReportPath       string        `json:"cape_report_path"`        // e.g. "/apiv2/tasks/report/{id}"
	PollInterval         time.Duration `json:"poll_interval"`           // e.g. "5s"
	RequestLogUnknownURI bool          `json:"request_log_unknown_uri"` // logování neznámých endpointů
}

// SandBlast-ish response structs (minimal compatible subset)
type SBUploadResp struct {
	MD5        string `json:"md5"`
	SHA1       string `json:"sha1"`
	SHA256     string `json:"sha256"`
	StatusCode int    `json:"status_code"` // 100=accepted, 200=done (zde 100 po uploadu)
	TaskID     string `json:"task_id"`     // náš identifikátor, mapuje na CAPE TaskID
}

type SBStatusResp struct {
	TaskID     string `json:"task_id"`
	Status     string `json:"status"`      // "queued" | "running" | "done" | "failed"
	StatusCode int    `json:"status_code"` // 100=processing, 200=done, 400/500=error
}

type SBReportResp = map[string]any // volné pole; vracíme JSON ve stylu SandBlast

// in-memory map task_id -> CAPE task id (nebo analýza)
var taskMap = struct {
	sync.RWMutex
	m map[string]int
}{m: make(map[string]int)}

func main() {
	cfg := loadConfig()

	mux := http.NewServeMux()
	// SandBlast-compatible-ish endpoints (subset)
	mux.HandleFunc("/tecloud/api/v1/file/upload", withLogging(cfg, handleUpload(cfg)))
	mux.HandleFunc("/tecloud/api/v1/file/status", withLogging(cfg, handleStatus(cfg)))
	mux.HandleFunc("/tecloud/api/v1/file/report", withLogging(cfg, handleReport(cfg)))

	// fallback – loguj neznámé cesty (ať vidíš co tvůj klient zkouší)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if cfg.RequestLogUnknownURI {
			log.Printf("UNKNOWN %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		}
		http.NotFound(w, r)
	})

	server := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      mux,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 300 * time.Second,
	}
	log.Printf("SandBlast→CAPE bridge listening on %s", cfg.ListenAddr)
	log.Fatal(server.ListenAndServe())
}

func loadConfig() *Config {
	// defaulty
	cfg := &Config{
		ListenAddr:           ":8080",
		CAPEBaseURL:          "http://127.0.0.1:8000",
		CAPEAPIToken:         "",
		CAPEUploadPath:       "/apiv2/tasks/create/file",
		CAPEStatusPath:       "/apiv2/tasks/view/{id}",
		CAPEReportPath:       "/apiv2/tasks/report/{id}",
		PollInterval:         5 * time.Second,
		RequestLogUnknownURI: true,
	}
	// možnost načíst z JSON souboru CONFIG_PATH nebo config.json v cwd
	path := os.Getenv("CONFIG_PATH")
	if path == "" {
		path = "config.json"
	}
	if f, err := os.Open(path); err == nil {
		defer f.Close()
		_ = json.NewDecoder(f).Decode(cfg)
	}
	return cfg
}

func withLogging(cfg *Config, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		var bodyPreview string
		if r.Method == http.MethodPost {
			// jen lehký náhled hlaviček a velikosti
			bodyPreview = fmt.Sprintf("ctlen=%v content-type=%s", r.ContentLength, r.Header.Get("Content-Type"))
		}
		log.Printf("%s %s from %s %s", r.Method, r.URL.Path, r.RemoteAddr, bodyPreview)
		sr := &statusRecorder{ResponseWriter: w}
		next(sr, r)
		log.Printf("→ %s %s %d in %s", r.Method, r.URL.Path, httpStatusFromWriter(sr), time.Since(start))
	}
}

func sandblastStatusFromCAPE(s string) string {
	// Normalize CAPE status to a SandBlast-like status set
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "pending", "submitted", "queued", "scheduled", "created", "waiting", "received":
		return "queued"
	case "running", "processing", "started", "analysis", "analyzing", "in-progress":
		return "running"
	case "reported", "completed", "finished", "success", "done":
		return "done"
	case "failed", "failure", "error", "aborted", "terminated", "stopped", "timeout":
		return "failed"
	default:
		// Unknown → považuj za zpracovávání
		return "queued"
	}
}

func sandblastStatusCodeFromCAPE(s string) int {
	// Map SandBlast-like textual status to status_code values expected by clients
	switch sandblastStatusFromCAPE(s) {
	case "done":
		return 200
	case "failed":
		return 500
	case "queued", "running":
		return 100
	default:
		return 100
	}
}

// --- SandBlast endpoints ---

func handleUpload(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseMultipartForm(200 << 20); err != nil { // 200MB
			httpErrorJSON(w, http.StatusBadRequest, err)
			return
		}

		// SandBlast API typicky používá field "file" (ponech flexibilní)
		file, header, err := r.FormFile("file")
		if err != nil {
			// fallback: zkus "upload" apod.
			for _, k := range []string{"upload", "sample", "upfile"} {
				file, header, err = r.FormFile(k)
				if err == nil {
					break
				}
			}
		}
		if err != nil {
			httpErrorJSON(w, http.StatusBadRequest, fmt.Errorf("missing file: %w", err))
			return
		}
		defer file.Close()

		buf := &bytes.Buffer{}
		if _, err := io.Copy(buf, file); err != nil {
			httpErrorJSON(w, http.StatusInternalServerError, err)
			return
		}

		md5h := md5.Sum(buf.Bytes())
		sha1h := sha1.Sum(buf.Bytes())
		sha256h := sha256.Sum256(buf.Bytes())

		// Odešli do CAPE
		taskID, err := capeSubmitFile(cfg, header.Filename, buf.Bytes(), r.Context())
		if err != nil {
			httpErrorJSON(w, http.StatusBadGateway, fmt.Errorf("CAPE submit failed: %w", err))
			return
		}

		// vymyslíme SandBlast-like TaskID jako string
		sbTask := fmt.Sprintf("sb-%d", taskID)
		taskMap.Lock()
		taskMap.m[sbTask] = taskID
		taskMap.Unlock()

		resp := SBUploadResp{
			MD5:        hex.EncodeToString(md5h[:]),
			SHA1:       hex.EncodeToString(sha1h[:]),
			SHA256:     hex.EncodeToString(sha256h[:]),
			StatusCode: 100, // accepted/processing
			TaskID:     sbTask,
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleStatus(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		task := r.URL.Query().Get("task_id")
		if task == "" {
			httpErrorJSON(w, http.StatusBadRequest, errors.New("missing task_id"))
			return
		}
		capeID, ok := mapTask(task)
		if !ok {
			httpErrorJSON(w, http.StatusNotFound, fmt.Errorf("unknown task_id %q", task))
			return
		}

		st, err := capeStatus(cfg, capeID, r.Context())
		if err != nil {
			httpErrorJSON(w, http.StatusBadGateway, err)
			return
		}

		sb := SBStatusResp{
			TaskID:     task,
			Status:     sandblastStatusFromCAPE(st),
			StatusCode: sandblastStatusCodeFromCAPE(st),
		}
		writeJSON(w, http.StatusOK, sb)
	}
}

func handleReport(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		task := r.URL.Query().Get("task_id")
		if task == "" {
			httpErrorJSON(w, http.StatusBadRequest, errors.New("missing task_id"))
			return
		}
		typ := r.URL.Query().Get("type")
		if typ == "" {
			typ = "json"
		}
		if strings.ToLower(typ) != "json" {
			httpErrorJSON(w, http.StatusBadRequest, errors.New("only type=json is supported here"))
			return
		}
		capeID, ok := mapTask(task)
		if !ok {
			httpErrorJSON(w, http.StatusNotFound, fmt.Errorf("unknown task_id %q", task))
			return
		}

		rawReport, err := capeReportJSON(cfg, capeID, r.Context())
		if err != nil {
			httpErrorJSON(w, http.StatusBadGateway, fmt.Errorf("failed to fetch CAPE report: %w", err))
			return
		}

		sbReport, err := capeToSandblast(rawReport)
		if err != nil {
			httpErrorJSON(w, http.StatusInternalServerError, fmt.Errorf("mapping CAPE→SandBlast failed: %w", err))
			return
		}
		writeJSON(w, http.StatusOK, sbReport)
	}
}

// --- CAPE client (udrž schválně konfigurovatelné cesty, CAPE má různé varianty API) ---

func capeSubmitFile(cfg *Config, filename string, data []byte, ctx context.Context) (int, error) {
	target := mustJoin(cfg.CAPEBaseURL, cfg.CAPEUploadPath)

	var body bytes.Buffer
	mp := multipart.NewWriter(&body)
	fw, err := mp.CreateFormFile("file", filepath.Base(filename))
	if err != nil {
		return 0, err
	}
	if _, err := io.Copy(fw, bytes.NewReader(data)); err != nil {
		return 0, err
	}
	// zde případně přidej CAPE-specific parametry (timeout, machine, package, custom, …)
	if err := mp.Close(); err != nil {
		return 0, err
	}

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, target, &body)
	req.Header.Set("Content-Type", mp.FormDataContentType())
	if cfg.CAPEAPIToken != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.CAPEAPIToken)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("CAPE upload HTTP %d: %s", resp.StatusCode, string(b))
	}

	// Očekáváme JSON s task ID – ponech flexibilní
	var anyResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&anyResp); err != nil {
		return 0, err
	}
	// hledej "task_id", "id", "taskid"…
	for _, k := range []string{"task_id", "id", "taskid", "task"} {
		if v, ok := anyResp[k]; ok {
			switch t := v.(type) {
			case float64:
				return int(t), nil
			case string:
				if n, err := strconv.Atoi(t); err == nil {
					return n, nil
				}
			}
		}
	}
	return 0, fmt.Errorf("cannot find CAPE task id in response: %v", anyResp)
}

func capeStatus(cfg *Config, id int, ctx context.Context) (string, error) {
	path := strings.ReplaceAll(cfg.CAPEStatusPath, "{id}", strconv.Itoa(id))
	target := mustJoin(cfg.CAPEBaseURL, path)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if cfg.CAPEAPIToken != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.CAPEAPIToken)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("CAPE status HTTP %d: %s", resp.StatusCode, string(b))
	}
	var anyResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&anyResp); err != nil {
		return "", err
	}

	// Zkus vytáhnout pole stavu – CAPE mívá "status" / "task"->"status"
	if s, ok := anyResp["status"].(string); ok && s != "" {
		return s, nil
	}
	if task, ok := anyResp["task"].(map[string]any); ok {
		if s, ok := task["status"].(string); ok && s != "" {
			return s, nil
		}
	}
	// fallback: pokud je "reported"/"completed"/"failed" apod. v jiném klíči
	for _, k := range []string{"state", "stage", "result", "phase"} {
		if s, ok := anyResp[k].(string); ok && s != "" {
			return s, nil
		}
	}
	// když nevíme, vrátíme něco rozumného
	return "unknown", nil
}

func capeReportJSON(cfg *Config, id int, ctx context.Context) (json.RawMessage, error) {
	path := strings.ReplaceAll(cfg.CAPEReportPath, "{id}", strconv.Itoa(id))
	target := mustJoin(cfg.CAPEBaseURL, path)

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if cfg.CAPEAPIToken != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.CAPEAPIToken)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("CAPE report HTTP %d: %s", resp.StatusCode, string(b))
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	// pokud CAPE vrací už JSON report.json → použij přímo
	return json.RawMessage(b), nil
}

// --- Mapping CAPE → SandBlast (doladíš podle svých dat) ---

func capeToSandblast(cape json.RawMessage) (SBReportResp, error) {
	// Příklad: vytáhneme pár klíčů a poskládáme SandBlast-like výstup.
	// SandBlast mívá sekce: verdict, signatures, indicators, file_info, extraction, static, dynamic…
	var capemap map[string]any
	if err := json.Unmarshal(cape, &capemap); err != nil {
		return nil, err
	}

	// Heuristicky z CAPE:
	verdict := "benign"
	if sigs, ok := digSlice(capemap, "signatures"); ok && len(sigs) > 0 {
		verdict = "malicious"
	}
	// skóre pokud CAPE má "scores" / "malscore"
	var score float64
	if v, ok := digFloat(capemap, "malscore"); ok {
		score = v
	} else if v, ok := digFloat(capemap, "info", "score"); ok {
		score = v
	}

	fileInfo := map[string]any{}
	// md5/sha1/sha256
	for _, k := range []string{"md5", "sha1", "sha256"} {
		if v, ok := digString(capemap, "target", "file", k); ok {
			fileInfo[k] = v
		}
	}

	// indicators (flat)
	var indicators []map[string]any
	if beh, ok := capemap["behavior"].(map[string]any); ok {
		if procs, ok := beh["processes"].([]any); ok {
			for _, p := range procs {
				if mp, ok := p.(map[string]any); ok {
					if call, ok := mp["process_name"].(string); ok && call != "" {
						indicators = append(indicators, map[string]any{
							"indicator": "process",
							"value":     call,
						})
					}
				}
			}
		}
	}

	// signatures → SandBlast-like "signatures"
	var sbSigs []map[string]any
	if sigs, ok := digSlice(capemap, "signatures"); ok {
		for _, s := range sigs {
			if sm, ok := s.(map[string]any); ok {
				name, _ := sm["name"].(string)
				desc, _ := sm["description"].(string)
				severity := 0
				if sev, ok := sm["severity"].(float64); ok {
					severity = int(sev)
				}
				sbSigs = append(sbSigs, map[string]any{
					"name":        name,
					"description": desc,
					"severity":    severity,
				})
			}
		}
	}

	out := SBReportResp{
		"verdict": map[string]any{
			"category": verdict, // benign/suspicious/malicious
			"score":    score,
		},
		"file_info":  fileInfo,
		"signatures": sbSigs,
		"indicators": indicators,
		// „raw_cape“ se hodí pro ladění – můžeš vypnout až budeš spokojen
		"_raw_cape": json.RawMessage(cape),
	}
	return out, nil
}

// --- helpers ---

func mapTask(sbTask string) (int, bool) {
	taskMap.RLock()
	defer taskMap.RUnlock()
	v, ok := taskMap.m[sbTask]
	return v, ok
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (s *statusRecorder) WriteHeader(c int) { s.code = c; s.ResponseWriter.WriteHeader(c) }

func httpStatusFromWriter(w http.ResponseWriter) int {
	if sr, ok := w.(*statusRecorder); ok && sr.code != 0 {
		return sr.code
	}
	// není k dispozici → OK
	return 200
}

func httpErrorJSON(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]any{
		"error":       err.Error(),
		"status_code": code,
	})
}

func mustJoin(base, p string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base + p
	}
	if strings.HasPrefix(p, "/") {
		u.Path = strings.TrimRight(u.Path, "/") + p
	} else {
		u.Path = strings.TrimRight(u.Path, "/") + "/" + p
	}
	return u.String()
}

func digString(m map[string]any, path ...string) (string, bool) {
	cur := any(m)
	for _, k := range path {
		mp, ok := cur.(map[string]any)
		if !ok {
			return "", false
		}
		cur, ok = mp[k]
		if !ok {
			return "", false
		}
	}
	s, ok := cur.(string)
	return s, ok
}

func digFloat(m map[string]any, path ...string) (float64, bool) {
	cur := any(m)
	for _, k := range path {
		mp, ok := cur.(map[string]any)
		if !ok {
			return 0, false
		}
		cur, ok = mp[k]
		if !ok {
			return 0, false
		}
	}
	switch v := cur.(type) {
	case float64:
		return v, true
	case json.Number:
		f, err := v.Float64()
		if err == nil {
			return f, true
		}
	}
	return 0, false
}

func digSlice(m map[string]any, path ...string) ([]any, bool) {
	cur := any(m)
	for _, k := range path {
		mp, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = mp[k]
		if !ok {
			return nil, false
		}
	}
	s, ok := cur.([]any)
	return s, ok
}
