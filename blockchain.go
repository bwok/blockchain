package blockchain

// package blockchain is a library to generate and check 512 bit blockchain hashes.
// bytes that get hashed are appended in the following order before hashing:
// previous hash, hash of the data in the blockchain, timestamp bytes, nonce bytes.

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"math"
	"runtime"
	"sync"
	"time"
)

// A struct representing a "block" in the blockchain.
// Blockhash is a sha512 hash of PreviousHash+DataHash+Timestamp+Nonce
type Block struct {
	PreviousHash, BlockHash, DataHash []byte
	Timestamp                         int64
	Nonce                             uint64
}

// The struct that gets returned on the valid hash channel
type channelValue struct {
	hash  []byte
	nonce uint64
}

// checks the hash begins with the appropriate number of zero bits.
// numZeroBits must be less than the number of bits in the hash.
func hasHashPrefixBits(hash [64]byte, numZeroBits int) bool {
	var numZeroBytes = numZeroBits / 8

	// this many bytes should be all zero
	for i := 0; i < numZeroBytes; i++ {
		if hash[i] != 0x0 {
			return false
		}
	}

	var remainderBits = uint(8 - (numZeroBits % 8))

	// check the remaining bits, if any.
	if remainderBits == 0 {
		return true
	} else {
		return hash[numZeroBytes]>>remainderBits == 0x0
	}
}

// Make a byte slice holding the bytes to hash, excluding the nonce bytes.
func (b *Block) appendBytes() (bytesToHash []byte) {
	bytesToHash = append(bytesToHash, b.PreviousHash...)
	bytesToHash = append(bytesToHash, b.DataHash...)

	// add the timestamp bytes to the byte slice
	timeStampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeStampBytes, uint64(b.Timestamp))
	bytesToHash = append(bytesToHash, timeStampBytes...)
	return
}

// Checks that the block has a valid hash
func CheckHash(block *Block) bool {
	bytesToHash := block.appendBytes()

	nonceBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceBytes, block.Nonce)
	bytesToHash = append(bytesToHash, nonceBytes...)
	newBlockHash := sha512.Sum512(bytesToHash)

	return bytes.Equal(block.BlockHash, newBlockHash[:])
}

// calculates a new Block for the chain, returns a pointer to it
func GenerateBlock(previousHash []byte, dataHash []byte, numPrefixZeros int) (newBlock Block, err error) {
	newBlock = Block{}

	if numPrefixZeros < 0 || numPrefixZeros > 64 {
		err = errors.New("the number of prefix zero bits must be > 0 and <= 64")
		return
	}
	if len(dataHash) == 0 {
		err = errors.New("the data hash was empty")
		return
	}

	newBlock.PreviousHash = previousHash
	newBlock.Timestamp = time.Now().UnixNano()
	newBlock.DataHash = dataHash

	// Make a byte slice holding the bytes to hash, excluding the nonce bytes
	bytesToHash := newBlock.appendBytes()

	// start the goroutine hash calculations.
	var numHashRoutines = runtime.NumCPU()                                 // The number of goroutines calculating nonce that will be started
	var wg sync.WaitGroup                                                  // A waitgroup for all the hashing goroutines
	hashChan := make(chan channelValue, numHashRoutines*2)                 // A channel to recieve valid hashes on
	noncePartitionSize := uint64(math.MaxUint64 / uint64(numHashRoutines)) // split the nonce maximum value into sections, each goroutine gets a section to calculate.

	for i := 0; i < numHashRoutines; i++ {
		wg.Add(1)

		// start each hash routine at the start of a nonce partition
		go func(startNonce uint64, chanNum int) {
			defer wg.Done()
			var maxNonce = startNonce + noncePartitionSize
			var tempHashBytes = make([]byte, len(bytesToHash))
			var nonceBytes = make([]byte, 8)
			var newHash [64]byte

			for ; startNonce < maxNonce && newBlock.BlockHash == nil; startNonce++ {
				binary.BigEndian.PutUint64(nonceBytes, startNonce)

				tempHashBytes = tempHashBytes[:len(bytesToHash)]
				copy(tempHashBytes, bytesToHash)
				tempHashBytes = append(tempHashBytes, nonceBytes...)
				newHash = sha512.Sum512(tempHashBytes)

				if hasHashPrefixBits(newHash, numPrefixZeros) {
					hashChan <- channelValue{newHash[:], startNonce}
					break
				}
			}
		}(noncePartitionSize*uint64(i), i)
	}

	// close the hash channel when all goroutines are finished,
	// which lets the main goroutine exit its hashChan wait loop
	go func() {
		wg.Wait()
		close(hashChan)
	}()

	// wait for a hash to come back on the hash channel, after it does, discard any
	// subsequent hashes until the channel closes.
	for newHash := range hashChan {
		if newBlock.BlockHash == nil {
			newBlock.BlockHash = newHash.hash
			newBlock.Nonce = newHash.nonce
		}
	}

	// goroutines finished but no valid hash found
	if newBlock.BlockHash == nil {
		err = errors.New("no hash found")
	}

	return
}
