package blockchain

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"testing"
)

func TestCheckHash(t *testing.T) {
	var convHexToByes = func(s string) []byte {
		retVal, err := hex.DecodeString(s)
		if err != nil {
			fmt.Println(err)
		}
		return retVal
	}

	var tests = []struct {
		b    Block
		want bool
	}{
		{	// previous hash = []
			b: Block{
				PreviousHash: convHexToByes(""),
				DataHash:     convHexToByes("a6e7426704cbf59dd5ddaf574c5409988df6baf7f0467f482de7a98a6c4556f8c6a99b2a8d17cbf193001d8813aca4091306ec795a013d8b6754beb4098374f6"),
				Timestamp:    1547761477424052813,
				Nonce:        13835058055282267343,
				BlockHash:    convHexToByes("000006ded5eda75721b4c3a01be20c0dd9b2f41e8469eaf321e8f52a83143df19e97b57e4258b3f164e0d2e606426a2f5b42dd673cd5b96d5d2b9277d3a6fbda"),
			},
			want: true,
		},
		{	// previous hash = nil
			b: Block{
				PreviousHash: nil,
				DataHash:     convHexToByes("a6e7426704cbf59dd5ddaf574c5409988df6baf7f0467f482de7a98a6c4556f8c6a99b2a8d17cbf193001d8813aca4091306ec795a013d8b6754beb4098374f6"),
				Timestamp:    1547761477424052813,
				Nonce:        13835058055282267343,
				BlockHash:    convHexToByes("000006ded5eda75721b4c3a01be20c0dd9b2f41e8469eaf321e8f52a83143df19e97b57e4258b3f164e0d2e606426a2f5b42dd673cd5b96d5d2b9277d3a6fbda"),
			},
			want: true,
		},

		// normal block chain sequence continuing on from the first two cases
		{
			b: Block{
				PreviousHash: convHexToByes("000006ded5eda75721b4c3a01be20c0dd9b2f41e8469eaf321e8f52a83143df19e97b57e4258b3f164e0d2e606426a2f5b42dd673cd5b96d5d2b9277d3a6fbda"),
				DataHash:     convHexToByes("a6e7426704cbf59dd5ddaf574c5409988df6baf7f0467f482de7a98a6c4556f8c6a99b2a8d17cbf193001d8813aca4091306ec795a013d8b6754beb4098374f6"),
				Timestamp:    1547761477481446179,
				Nonce:        4611686018427630966,
				BlockHash:    convHexToByes("00000f6c489cb4b74bd189bb74d6a9856c98343a26d7a027d75597bba175e599a9851c84461cb8bd5273327fc680a0d828d68a36c95fb3458472f12718591566"),
			},
			want: true,
		},
		{
			b: Block{
				PreviousHash: convHexToByes("00000f6c489cb4b74bd189bb74d6a9856c98343a26d7a027d75597bba175e599a9851c84461cb8bd5273327fc680a0d828d68a36c95fb3458472f12718591566"),
				DataHash:     convHexToByes("a6e7426704cbf59dd5ddaf574c5409988df6baf7f0467f482de7a98a6c4556f8c6a99b2a8d17cbf193001d8813aca4091306ec795a013d8b6754beb4098374f6"),
				Timestamp:    1547761477647785674,
				Nonce:        4611686018427586970,
				BlockHash:    convHexToByes("00000379b38eb726deeed0c1520deff5a75c55b53bf1a38f4b38d504e44112e10b2251ffe31c7874c59b57d170cc5e440422c77c5623d326fe146495c57db598"),
			},
			want: true,
		},
		{
			b: Block{
				PreviousHash: convHexToByes("00000379b38eb726deeed0c1520deff5a75c55b53bf1a38f4b38d504e44112e10b2251ffe31c7874c59b57d170cc5e440422c77c5623d326fe146495c57db598"),
				DataHash:     convHexToByes("a6e7426704cbf59dd5ddaf574c5409988df6baf7f0467f482de7a98a6c4556f8c6a99b2a8d17cbf193001d8813aca4091306ec795a013d8b6754beb4098374f6"),
				Timestamp:    1547761477826864721,
				Nonce:        4611686018427704284,
				BlockHash:    convHexToByes("00000c89f73b920028f9119c0953c6472679ea144ad8d31cc44687a6451aff072656cb3d1a18c5b2d7409cbb1ff015bdda3defd3adaea9d318c57f1dbb1f1bd4"),
			},
			want: true,
		},
		{
			b: Block{
				PreviousHash: convHexToByes("00000c89f73b920028f9119c0953c6472679ea144ad8d31cc44687a6451aff072656cb3d1a18c5b2d7409cbb1ff015bdda3defd3adaea9d318c57f1dbb1f1bd4"),
				DataHash:     convHexToByes("a6e7426704cbf59dd5ddaf574c5409988df6baf7f0467f482de7a98a6c4556f8c6a99b2a8d17cbf193001d8813aca4091306ec795a013d8b6754beb4098374f6"),
				Timestamp:    1547761478198393850,
				Nonce:        13835058055282220004,
				BlockHash:    convHexToByes("00000ed6ff9b58c6776793c44ad4caf0e10c680023cf615a079aa3f168e8c274b64bc386fb04ad51bed7a5e36358d1a2c49b7b378582fa460c4e794e2772dbfd"),
			},
			want: true,
		},
		{
			b: Block{
				PreviousHash: convHexToByes("00000ed6ff9b58c6776793c44ad4caf0e10c680023cf615a079aa3f168e8c274b64bc386fb04ad51bed7a5e36358d1a2c49b7b378582fa460c4e794e2772dbfd"),
				DataHash:     convHexToByes("a6e7426704cbf59dd5ddaf574c5409988df6baf7f0467f482de7a98a6c4556f8c6a99b2a8d17cbf193001d8813aca4091306ec795a013d8b6754beb4098374f6"),
				Timestamp:    1547761478234485475,
				Nonce:        4611686018428087474,
				BlockHash:    convHexToByes("00000d364651d8b2dc765c16d1ff56c8797ea6a51ceec9765a3dc6fc9050105d1e6b4de15ca6a3b3a0b0526d85f81d65929cbfac21e33aa964ad8cb90a0b3bf8"),
			},
			want: true,
		},


		// invalid, all should return false when checked as they contain modified values
		{	// wrong previous hash
			b: Block{
				PreviousHash: convHexToByes("010006ded5eda75721b4c3a01be20c0dd9b2f41e8469eaf321e8f52a83143df19e97b57e4258b3f164e0d2e606426a2f5b42dd673cd5b96d5d2b9277d3a6fbda"),
				DataHash:     convHexToByes("a6e7426704cbf59dd5ddaf574c5409988df6baf7f0467f482de7a98a6c4556f8c6a99b2a8d17cbf193001d8813aca4091306ec795a013d8b6754beb4098374f6"),
				Timestamp:    1547761477481446179,
				Nonce:        4611686018427630966,
				BlockHash:    convHexToByes("00000f6c489cb4b74bd189bb74d6a9856c98343a26d7a027d75597bba175e599a9851c84461cb8bd5273327fc680a0d828d68a36c95fb3458472f12718591566"),
			},
			want: false,
		},
		{	// wrong data hash
			b: Block{
				PreviousHash: convHexToByes("000006ded5eda75721b4c3a01be20c0dd9b2f41e8469eaf321e8f52a83143df19e97b57e4258b3f164e0d2e606426a2f5b42dd673cd5b96d5d2b9277d3a6fbda"),
				DataHash:     convHexToByes("a7e7426704cbf59dd5ddaf574c5409988df6baf7f0467f482de7a98a6c4556f8c6a99b2a8d17cbf193001d8813aca4091306ec795a013d8b6754beb4098374f6"),
				Timestamp:    1547761477481446179,
				Nonce:        4611686018427630966,
				BlockHash:    convHexToByes("00000f6c489cb4b74bd189bb74d6a9856c98343a26d7a027d75597bba175e599a9851c84461cb8bd5273327fc680a0d828d68a36c95fb3458472f12718591566"),
			},
			want: false,
		},
		{	// wrong timestamp
			b: Block{
				PreviousHash: convHexToByes("000006ded5eda75721b4c3a01be20c0dd9b2f41e8469eaf321e8f52a83143df19e97b57e4258b3f164e0d2e606426a2f5b42dd673cd5b96d5d2b9277d3a6fbda"),
				DataHash:     convHexToByes("a6e7426704cbf59dd5ddaf574c5409988df6baf7f0467f482de7a98a6c4556f8c6a99b2a8d17cbf193001d8813aca4091306ec795a013d8b6754beb4098374f6"),
				Timestamp:    1547761477481446180,
				Nonce:        4611686018427630966,
				BlockHash:    convHexToByes("00000f6c489cb4b74bd189bb74d6a9856c98343a26d7a027d75597bba175e599a9851c84461cb8bd5273327fc680a0d828d68a36c95fb3458472f12718591566"),
			},
			want: false,
		},
		{	// wrong nonce
			b: Block{
				PreviousHash: convHexToByes("000006ded5eda75721b4c3a01be20c0dd9b2f41e8469eaf321e8f52a83143df19e97b57e4258b3f164e0d2e606426a2f5b42dd673cd5b96d5d2b9277d3a6fbda"),
				DataHash:     convHexToByes("a6e7426704cbf59dd5ddaf574c5409988df6baf7f0467f482de7a98a6c4556f8c6a99b2a8d17cbf193001d8813aca4091306ec795a013d8b6754beb4098374f6"),
				Timestamp:    1547761477481446179,
				Nonce:        4611686018427630967,
				BlockHash:    convHexToByes("00000f6c489cb4b74bd189bb74d6a9856c98343a26d7a027d75597bba175e599a9851c84461cb8bd5273327fc680a0d828d68a36c95fb3458472f12718591566"),
			},
			want: false,
		},
		{	// wrong block hash
			b: Block{
				PreviousHash: convHexToByes("000006ded5eda75721b4c3a01be20c0dd9b2f41e8469eaf321e8f52a83143df19e97b57e4258b3f164e0d2e606426a2f5b42dd673cd5b96d5d2b9277d3a6fbda"),
				DataHash:     convHexToByes("a6e7426704cbf59dd5ddaf574c5409988df6baf7f0467f482de7a98a6c4556f8c6a99b2a8d17cbf193001d8813aca4091306ec795a013d8b6754beb4098374f6"),
				Timestamp:    1547761477481446179,
				Nonce:        4611686018427630966,
				BlockHash:    convHexToByes("00000f6c489cb4b74bd189bb74d6a9856c98343a26d7a027d75597bba175e599a9851c84461cb8bd5273327fc680a0d828d68a36c95fb3458472f12718591567"),
			},
			want: false,
		},
	}

	for index, test := range tests {
		if CheckHash(&test.b) != test.want {
			t.Errorf("test case %d failed. Got: %t, want: %t. hash: %x", index, !test.want, test.want, test.b.BlockHash)
		}
	}
}

func TestGenerateBlock(t *testing.T) {

	var tests = []struct {
		previousHash   []byte
		dataHash       []byte
		numPrefixZeros int
		err            bool
	}{
		{
			[]byte{},
			[]byte("f4478aa868071a0424ce4a90cd5b48d781e15971e383ad1a9044fc7c8318d5bd6cba5d9712a42723de9f1c2d3e797184f575282d21a614c5b6bdfdd0d5204aec"),
			0,
			false,
		},
		{
			[]byte{},
			[]byte("f4478aa868071a0424ce4a90cd5b48d781e15971e383ad1a9044fc7c8318d5bd6cba5d9712a42723de9f1c2d3e797184f575282d21a614c5b6bdfdd0d5204aec"),
			20,
			false,
		},
		{
			[]byte{},
			[]byte("f4478aa868071a0424ce4a90cd5b48d781e15971e383ad1a9044fc7c8318d5bd6cba5d9712a42723de9f1c2d3e797184f575282d21a614c5b6bdfdd0d5204aec"),
			65,
			true,
		},
		{
			[]byte{},
			[]byte("f4478aa868071a0424ce4a90cd5b48d781e15971e383ad1a9044fc7c8318d5bd6cba5d9712a42723de9f1c2d3e797184f575282d21a614c5b6bdfdd0d5204aec"),
			-1,
			true,
		},
		{
			[]byte{},
			[]byte{},
			20,
			true,
		},
	}

	for index, test := range tests {
		newHash, err := GenerateBlock(test.previousHash, test.dataHash, test.numPrefixZeros)
		if err != nil {
			if test.err == false {
				t.Error(err)
			}
		} else if CheckHash(&newHash) == false {
			t.Errorf("test case %d returned an invalid hash.", index)
		}
	}
}

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
