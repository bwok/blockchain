package blockchain

import (
	"crypto/sha512"
	"io"
	"log"
	"os"
	"testing"
)

func BenchmarkGenerateBlock(b *testing.B) {
	//var oldHash = "f4478aa868071a0424ce4a90cd5b48d781e15971e383ad1a9044fc7c8318d5bd6cba5d9712a42723de9f1c2d3e797184f575282d21a614c5b6bdfdd0d5204aec"
	var oldHash string
	file, err := os.Open("testLedger")
	if err != nil {
		return
	}
	defer file.Close()

	// calculate the hash of the input data
	hasher := sha512.New()
	if _, err = io.Copy(hasher, file); err != nil {
		log.Fatal(err)
	}
	dataHash := hasher.Sum(nil)

	for i := 0; i < b.N; i++ {
		GenerateBlock([]byte(oldHash), dataHash[:], 17)
	}
}