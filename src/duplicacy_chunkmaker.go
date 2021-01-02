// Copyright (c) Acrosync LLC. All rights reserved.
// Free for personal use and commercial trial
// Commercial use requires per-user licenses available from https://duplicacy.com

package duplicacy

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"

	"github.com/tigerwill90/fastcdc"
)

// ChunkMaker breaks data into chunks using FastCDC. To save memory, the chunk maker only uses a circular buffer
// whose size is the maximum chunk size.
type ChunkMaker struct {
	maximumChunkSize int
	minimumChunkSize int
	bufferCapacity   int

	buffer      []byte
	bufferSize  int
	bufferStart int

	config *Config

	hashOnly      bool
	hashOnlyChunk *Chunk
}

// CreateChunkMaker creates a chunk maker.  'randomSeed' is used to generate the character-to-integer table needed by
// buzhash.
func CreateChunkMaker(config *Config, hashOnly bool) *ChunkMaker {
	size := 1
	for size*2 <= config.AverageChunkSize {
		size *= 2
	}

	if size != config.AverageChunkSize {
		LOG_FATAL("CHUNK_SIZE", "Invalid average chunk size: %d is not a power of 2", config.AverageChunkSize)
		return nil
	}

	maker := &ChunkMaker{
		maximumChunkSize: config.MaximumChunkSize,
		minimumChunkSize: config.MinimumChunkSize,
		bufferCapacity:   config.MaximumChunkSize,
		config:           config,
		hashOnly:         hashOnly,
	}

	if hashOnly {
		maker.hashOnlyChunk = CreateChunk(config, false)
	}

	maker.buffer = make([]byte, maker.bufferCapacity)

	return maker
}

// ForEachChunk reads data from 'reader'.  If EOF is encountered, it will call 'nextReader' to ask for next file.  If
// 'nextReader' returns false, it will process remaining data in the buffer and then quit.  When a chunk is identified,
// it will call 'endOfChunk' to return the chunk size and a boolean flag indicating if it is the last chunk.
func (maker *ChunkMaker) ForEachChunk(reader io.Reader, endOfChunk func(chunk *Chunk, final bool),
	nextReader func(size int64, hash string) (io.Reader, bool)) {

	var chunk *Chunk
	var err error

	fileSize := int64(0)
	fileHasher := maker.config.NewFileHasher()

	startNewChunk := func() {
		maker.bufferSize = 0
		if maker.hashOnly {
			chunk = maker.hashOnlyChunk
			chunk.Reset(true)
		} else {
			chunk = maker.config.GetChunk()
			chunk.Reset(true)
		}
	}

	startNewChunk()

	isEOF := false
	if maker.minimumChunkSize == maker.maximumChunkSize {

		if maker.bufferCapacity < maker.minimumChunkSize {
			maker.buffer = make([]byte, maker.minimumChunkSize)
		}

		for {
			maker.bufferStart = 0
			for maker.bufferStart < maker.minimumChunkSize && !isEOF {
				count, err := reader.Read(maker.buffer[maker.bufferStart:maker.minimumChunkSize])

				if err != nil {
					if err != io.EOF {
						LOG_ERROR("CHUNK_MAKER", "Failed after reading %d bytes: %s", fileSize+int64(count), err.Error())
						return
					} else {
						isEOF = true
					}
				}
				maker.bufferStart += count
			}

			fileHasher.Write(maker.buffer[:maker.bufferStart])
			fileSize += int64(maker.bufferStart)
			chunk.Write(maker.buffer[:maker.bufferStart])

			if isEOF {
				var ok bool
				reader, ok = nextReader(fileSize, hex.EncodeToString(fileHasher.Sum(nil)))
				if !ok {
					endOfChunk(chunk, true)
					return
				} else {
					if chunk.GetLength() > 0 {
						endOfChunk(chunk, false)
						startNewChunk()
					}
					fileSize = 0
					fileHasher.Reset()
					isEOF = false
				}
			} else {
				endOfChunk(chunk, false)
				startNewChunk()
			}
		}

	}

	chunker, err := fastcdc.NewChunker(context.Background(), fastcdc.WithStreamMode(), fastcdc.WithChunksSize(uint(maker.minimumChunkSize), uint(maker.config.AverageChunkSize), uint(maker.maximumChunkSize)))

	if err != nil {
		LOG_ERROR("CHUNK_MAKER", "Failed to create new chunk: %v", err)
		return
	}

	for {
		// If the buffer still has some space left and EOF is not seen, read more data.
		for maker.bufferSize < maker.bufferCapacity {
			start := maker.bufferSize
			count := maker.bufferCapacity - start

			count, err = reader.Read(maker.buffer[start : start+count])
			if err != nil && err != io.EOF {
				LOG_ERROR("CHUNK_MAKER", "Failed after reading %d bytes: %s", fileSize+int64(count), err.Error())
				return
			}

			maker.bufferSize += count
			fileHasher.Write(maker.buffer[start : start+count])
			fileSize += int64(count)

			// if EOF is seen, try to switch to next file and continue
			if err == io.EOF {
				var ok bool
				reader, ok = nextReader(fileSize, hex.EncodeToString(fileHasher.Sum(nil)))
				if !ok {
					chunk.Write(maker.buffer[:maker.bufferSize])
					endOfChunk(chunk, true)
					return
				} else {
					fileSize = 0
					fileHasher.Reset()
				}

				// Make new chunk if minimum chunksize has been gathered
				if maker.bufferSize >= maker.minimumChunkSize {
					chunk.Write(maker.buffer[:maker.bufferSize])
					endOfChunk(chunk, false)
					startNewChunk()
				}
			}
		}

		err = chunker.Split(bytes.NewReader(maker.buffer), func(offset, length uint, newChunk []byte) error {
			if length == 0 {
				return errors.New("Empty chunk")
			} else if length < 0 {
				return errors.New("chunk size less than 0")
			}

			chunk.Write(newChunk)
			endOfChunk(chunk, false)
			startNewChunk()
			return nil
		})
		if err != nil {
			LOG_ERROR("CHUNK_MAKER", "Failed to split buffer: %v", err)
			return
		}

		err = chunker.Finalize(func(offset, length uint, newChunk []byte) error {
			if int(length) >= maker.minimumChunkSize {
				chunk.Write(newChunk)
				endOfChunk(chunk, false)
				startNewChunk()
			} else if length == 0 {
				return errors.New("Empty chunk")
			} else if length < 0 {
				return errors.New("chunk size less than 0")
			} else {
				maker.bufferSize = int(length)
				copy(maker.buffer, newChunk)
			}
			return nil
		})
		if err != nil {
			LOG_ERROR("CHUNK_MAKER", "Failed to finalize buffer: %v", err)
			return
		}
	}
}
