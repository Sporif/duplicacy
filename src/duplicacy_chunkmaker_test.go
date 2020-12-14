// Copyright (c) Acrosync LLC. All rights reserved.
// Free for personal use and commercial trial
// Commercial use requires per-user licenses available from https://duplicacy.com

package duplicacy

import (
	"bytes"
	crypto_rand "crypto/rand"
	"io"
	"math/rand"
	"sort"
	"testing"
)

func splitIntoChunks(content []byte, n, averageChunkSize, maxChunkSize, minChunkSize int) ([]string, int) {

	config := CreateConfig()

	config.CompressionLevel = DEFAULT_COMPRESSION_LEVEL
	config.AverageChunkSize = averageChunkSize
	config.MaximumChunkSize = maxChunkSize
	config.MinimumChunkSize = minChunkSize
	config.ChunkSeed = []byte("duplicacy")

	config.HashKey = DEFAULT_KEY
	config.IDKey = DEFAULT_KEY

	maker := CreateChunkMaker(config, false)

	var chunks []string
	totalChunkSize := 0
	totalFileSize := int64(0)

	buffers := make([]*bytes.Buffer, n)
	sizes := make([]int, n)
	sizes[0] = 0
	for i := 1; i < n; i++ {
		same := true
		for same {
			same = false
			sizes[i] = rand.Int() % n
			for j := 0; j < i; j++ {
				if sizes[i] == sizes[j] {
					same = true
					break
				}
			}
		}
	}

	sort.Sort(sort.IntSlice(sizes))

	for i := 0; i < n-1; i++ {
		buffers[i] = bytes.NewBuffer(content[sizes[i]:sizes[i+1]])
	}
	buffers[n-1] = bytes.NewBuffer(content[sizes[n-1]:])

	i := 0

	maker.ForEachChunk(buffers[0],
		func(chunk *Chunk, final bool) {
			//LOG_INFO("CHUNK_SPLIT", "i: %d, chunk: %s, size: %d", i, chunk.GetHash(), size)
			chunks = append(chunks, chunk.GetHash())
			totalChunkSize += chunk.GetLength()
		},
		func(size int64, hash string) (io.Reader, bool) {
			totalFileSize += size
			i++
			if i >= len(buffers) {
				return nil, false
			}
			return buffers[i], true
		})

	if totalFileSize != int64(totalChunkSize) {
		LOG_ERROR("CHUNK_SPLIT", "total chunk size: %d, total file size: %d", totalChunkSize, totalFileSize)
	}
	return chunks, totalChunkSize
}

func TestChunkMaker(t *testing.T) {
	sizes := [...]int{64, 256, 1024, 1024 * 10}

	for _, size := range sizes {

		content := make([]byte, size)
		_, err := crypto_rand.Read(content)
		if err != nil {
			t.Errorf("Error generating random content: %v", err)
			continue
		}

		chunks, _ := splitIntoChunks(content, 10, 256, 1024, 64)
		LOG_INFO("CHUNK_MAKE", "Buffer size: %d, Number of chunks: %d", size, len(chunks))
	}

}
