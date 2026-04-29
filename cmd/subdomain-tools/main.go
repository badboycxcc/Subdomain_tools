package main

import (
	"log"

	"subdomain-tools/internal/gui"
)

func main() {
	w, err := gui.New()
	if err != nil {
		log.Fatalf("init gui failed: %v", err)
	}
	w.Run()
}
