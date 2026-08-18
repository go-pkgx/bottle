package bottle

import (
	"compress/gzip"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// decompressor wraps a bottle body in the decoder its extension names, and
// returns a close function for the decoders that hold resources.
//
// A bottle's compression is not a detail the installer may guess: a reader that
// assumes gzip and meets zstd fails with "invalid header", which reads like a
// corrupt download rather than a format it was never taught. Every extension we
// have ever published is handled here, and an unknown one says so by name.
//
// All three decoders stream, which matters now that the pull stages the tarball
// on disk: nothing here holds a bottle in memory.
func decompressor(ext string, body io.Reader) (io.Reader, func(), error) {
	switch ext {
	case ExtTarZst:
		z, err := zstdNewReader(body)
		if err != nil {
			return nil, nil, err
		}
		return z, z.Close, nil
	case ExtTarXz:
		x, err := xz.NewReader(body)
		if err != nil {
			return nil, nil, err
		}
		return x, func() {}, nil
	case ExtTarGz, "":
		// "" is the historical default: the static-HTTP dist path tried .tar.gz
		// first and reported nothing when it won.
		g, err := gzip.NewReader(body)
		if err != nil {
			return nil, nil, err
		}
		return g, func() { g.Close() }, nil
	default:
		return nil, nil, fmt.Errorf("bottle: unknown compression %q", ext)
	}
}

// zstdNewReader is a seam: the constructor fails only on a bad option, which
// this package never passes, and an error path that has never run is an error
// message nobody has read.
var zstdNewReader = func(r io.Reader) (*zstd.Decoder, error) { return zstd.NewReader(r) }
