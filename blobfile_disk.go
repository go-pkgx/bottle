//go:build !js

package bottle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// fetchBlobFile downloads desc's content into a temporary FILE, resuming with a
// Range request whenever the connection is cut short, and verifies the digest of
// the assembled bytes — the pieces come from separate responses, so nothing but
// the digest proves they belong together. The returned file is positioned at
// the start.
//
// A bottle is not a small object: llvm.org is ~1.7 GiB compressed. Assembling
// one in a []byte made the largest package in the catalogue the memory FLOOR of
// every consumer — and the old append-from-ReadAll held two copies at the peak,
// so ~3.4 GiB of anonymous memory to install a compiler. That is what killed a
// 2 GiB micro-VM: `Out of memory: Killed process (pkgx) total-vm:3329636kB`.
// Streaming to disk makes the floor the bottle's SIZE ON DISK, which the install
// needs anyway.
func (c *OCIClient) fetchBlobFile(ctx context.Context, project string, desc ocispec.Descriptor) (*BlobFile, error) {
	url := c.scheme() + "://" + c.host + "/v2/" + c.repoName(project) + "/blobs/" + desc.Digest.String()
	f, err := osCreateTemp("", "bottle-blob-*")
	if err != nil {
		return nil, fmt.Errorf("blob %s: temp file: %w", desc.Digest, err)
	}
	path := f.Name()
	fail := func(err error) (*BlobFile, error) {
		f.Close()
		osRemove(path)
		return nil, err
	}

	var got int64
	var lastErr error
	for attempt := 0; attempt <= blobRetries; attempt++ {
		if attempt > 0 {
			blobBackoff(attempt)
		}
		n, restarted, err := c.writeBlobFrom(ctx, url, got, f)
		if restarted {
			// The registry ignored the Range and replayed the whole blob, so
			// what we had is gone: the file was truncated and rewritten.
			got = n
		} else {
			got += n
		}
		if err == nil {
			lastErr = nil
			break
		}
		lastErr = err
		// No progress at all on this attempt: the failure is not a cut transfer
		// (a 404, an auth refusal, a dead host), so retrying is pointless.
		if n == 0 && attempt > 0 {
			return fail(err)
		}
	}
	if desc.Size > 0 && got != desc.Size {
		if lastErr == nil {
			lastErr = io.ErrUnexpectedEOF
		}
		return fail(fmt.Errorf("blob %s: got %d of %d bytes: %w", desc.Digest, got, desc.Size, lastErr))
	}

	// Hash from the file, not from a buffer we no longer keep. A resumed
	// transfer is several responses concatenated; only this proves they are the
	// blob the manifest names.
	if _, err := fSeek(f, 0, io.SeekStart); err != nil {
		return fail(fmt.Errorf("blob %s: rewind: %w", desc.Digest, err))
	}
	h := sha256.New()
	if _, err := ioCopy(h, f); err != nil {
		return fail(fmt.Errorf("blob %s: hash: %w", desc.Digest, err))
	}
	sum := "sha256:" + hex.EncodeToString(h.Sum(nil))
	if sum != desc.Digest.String() {
		return fail(fmt.Errorf("blob digest mismatch: got %s, want %s", sum, desc.Digest))
	}
	if _, err := fSeek(f, 0, io.SeekStart); err != nil {
		return fail(fmt.Errorf("blob %s: rewind: %w", desc.Digest, err))
	}
	return &BlobFile{ReadSeeker: f, Digest: sum, release: func() error {
		err := f.Close()
		if rmErr := osRemove(path); err == nil {
			err = rmErr
		}
		return err
	}}, nil
}
