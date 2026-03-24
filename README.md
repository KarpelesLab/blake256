# blake256

[![Go Reference](https://pkg.go.dev/badge/github.com/KarpelesLab/blake256.svg)](https://pkg.go.dev/github.com/KarpelesLab/blake256)
[![Test](https://github.com/KarpelesLab/blake256/actions/workflows/test.yml/badge.svg)](https://github.com/KarpelesLab/blake256/actions/workflows/test.yml)
[![Coverage Status](https://coveralls.io/repos/github/KarpelesLab/blake256/badge.svg?branch=master)](https://coveralls.io/github/KarpelesLab/blake256?branch=master)

Go implementation of BLAKE-256 and BLAKE-224 hash functions (SHA-3 candidate).

## Install

```bash
go get github.com/KarpelesLab/blake256
```

## Usage

```go
package main

import (
	"fmt"

	"github.com/KarpelesLab/blake256"
)

func main() {
	// One-shot hash
	hash := blake256.Sum256([]byte("hello"))
	fmt.Printf("%x\n", hash)

	// Streaming hash
	h := blake256.New()
	h.Write([]byte("hello"))
	fmt.Printf("%x\n", h.Sum(nil))

	// With salt (16 bytes)
	h, err := blake256.NewSalt([]byte("0123456789abcdef"))
	if err != nil {
		panic(err)
	}
	h.Write([]byte("hello"))
	fmt.Printf("%x\n", h.Sum(nil))
}
```

### BLAKE-224

```go
hash := blake256.Sum224([]byte("hello"))
h := blake256.New224()
```

## Features

- BLAKE-256 and BLAKE-224 hash computation
- Implements `hash.Hash`, `encoding.BinaryMarshaler`, and `encoding.BinaryUnmarshaler`
- Optional 16-byte salt support via `NewSalt` / `New224Salt`
- Zero external dependencies

## License

MIT License. See [LICENSE](LICENSE) for details.
