package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	webRoot := "./public"
	fs := http.FileServer(http.Dir(webRoot))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		if strings.HasPrefix(path, "/.git") {
			fullPath := filepath.Join(webRoot, path)
			info, err := os.Stat(fullPath)
			if err == nil && info.IsDir() {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}

		if path == "/" {
			http.ServeFile(w, r, filepath.Join(webRoot, "index.html"))
			return
		}

		fs.ServeHTTP(w, r)
	})

	log.Println("Server starting on :80...")
	if err := http.ListenAndServe(":80", nil); err != nil {
		log.Fatal(err)
	}
}
