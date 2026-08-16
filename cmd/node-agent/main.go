package main

import (
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

type PingRequest struct {
	RequestID      string `json:"requestId"`
	ControllerTime string `json:"controllerTime"`
	Machine        string `json:"machine"`
}

type PongResponse struct {
	Type           string `json:"type"`
	RequestID      string `json:"requestId"`
	ReceivedAt     string `json:"receivedAt"`
	NodeID         string `json:"nodeId"`
	OverlayIP      string `json:"overlayIp"`
	Hostname       string `json:"hostname"`
	OS             string `json:"os"`
	Architecture   string `json:"architecture"`
	CPUCores       int    `json:"cpuCores"`
	MemoryTotalKiB uint64 `json:"memoryTotalKiB,omitempty"`
}

func main() {
	var listen, token, nodeID, overlayIP string
	var once bool
	flag.StringVar(&listen, "listen", "127.0.0.1:19090", "HTTP listen address")
	flag.StringVar(&token, "token", "", "shared probe token")
	flag.StringVar(&nodeID, "node-id", "", "stable node identifier")
	flag.StringVar(&overlayIP, "overlay-ip", "", "EasyTier overlay IPv4")
	flag.BoolVar(&once, "once", false, "exit after one successful ping")
	flag.Parse()
	if token == "" || nodeID == "" || overlayIP == "" {
		log.Fatal("--token, --node-id, and --overlay-ip are required")
	}

	var server *http.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/ping", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		if !authorized(r, token) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var ping PingRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&ping); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		hostname, _ := os.Hostname()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(PongResponse{
			Type: "pong", RequestID: ping.RequestID, ReceivedAt: time.Now().UTC().Format(time.RFC3339Nano),
			NodeID: nodeID, OverlayIP: overlayIP, Hostname: hostname, OS: runtime.GOOS,
			Architecture: runtime.GOARCH, CPUCores: runtime.NumCPU(), MemoryTotalKiB: memoryTotalKiB(),
		})
		if once {
			go func() { time.Sleep(100 * time.Millisecond); _ = server.Close() }()
		}
	})

	server = &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("node probe listening on %s", listen)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func authorized(request *http.Request, token string) bool {
	value := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
	return len(value) == len(token) && subtle.ConstantTimeCompare([]byte(value), []byte(token)) == 1
}

func memoryTotalKiB() uint64 {
	if runtime.GOOS != "linux" {
		return 0
	}
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		var value uint64
		if _, err := fmt.Sscanf(line, "MemTotal: %d kB", &value); err == nil {
			return value
		}
	}
	return 0
}
