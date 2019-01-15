package blockchain

import (
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
func hasHashPrefixBits(hash []byte, numZeroBits int) bool {
	var numZeroBytes = numZeroBits/8
	var remainderBits = uint(8-(numZeroBits%8))

	// this many bytes should be all zero
	for i := 0; i < numZeroBytes; i++ {
		if hash[i] != 0x0 {
			return false
		}
	}

	// check the remaining bits, if any.
	if remainderBits == 0 {
		return true
	} else {
		return hash[numZeroBytes] >> remainderBits == 0x0
	}
}


// calculates a new Block for the chain, returns a pointer to it
func GenerateBlock(previousHash []byte, dataHash []byte, numPrefixZeros int) (newBlock Block, err error) {
	newBlock = Block{}

	if numPrefixZeros > 64 {
		err = errors.New("the number of prefix zero bits must be <= 64")
		return
	}

	newBlock.PreviousHash = previousHash
	newBlock.Timestamp = time.Now().UnixNano()
	newBlock.DataHash = dataHash

	// Make a byte slice holding the bytes to hash, excluding the nonce bytes
	var bytesToHash []byte
	bytesToHash = append(bytesToHash, previousHash...)
	bytesToHash = append(bytesToHash, newBlock.DataHash...)

	// add the timestamp bytes to the byte slice
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(newBlock.Timestamp))
	bytesToHash = append(bytesToHash, b...)

	// start the goroutine hash calculations.
	var numHashRoutines = runtime.NumCPU()                                 // The number of goroutines calculating nonce that will be started
	var wg sync.WaitGroup                                                  // A waitgroup for all the hashing goroutines
	hashChan := make(chan channelValue, numHashRoutines*2)                 // A channel to recieve valid hashes on
	noncePartitionSize := uint64(math.MaxUint64 / uint64(numHashRoutines)) // split the nonce maximum value into sections, each goroutine gets a section to calculate.

	for i := 0; i < numHashRoutines; i++ {
		wg.Add(1)

		// start each hash routine at the start of a nonce partition
		go func(startNonce uint64) {
			defer wg.Done()
			var maxNonce = startNonce + noncePartitionSize
			var tempHashBytes []byte
			nonceBytes := make([]byte, 8)

			for ; startNonce < maxNonce && newBlock.BlockHash == nil; startNonce++ {
				binary.BigEndian.PutUint64(nonceBytes, startNonce)
				tempHashBytes = append(bytesToHash, nonceBytes...)
				newBlockHash := sha512.Sum512(tempHashBytes)

				if hasHashPrefixBits(newBlockHash[:], numPrefixZeros) {
					hashChan <- channelValue{newBlockHash[:], startNonce}
					break
				}
			}
		}(noncePartitionSize * uint64(i))
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
