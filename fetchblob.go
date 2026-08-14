package bottle

// fetchblob.go pulls a bottle's layer blob with retries and byte-range resume.
//
// A toolchain bottle is big — llvm.org's linux/aarch64 layer is 1.68 GiB — and a
// single interrupted transfer used to lose the whole download: ORAS fetches a
// blob in one shot, so a mid-stream cut surfaced as
//
//	read failed: expected content size of 1762228910, got 1247805440 … unexpected EOF
//
// and the install died after twenty minutes of progress. Registries, CDNs and
// container-VM networks all cut long transfers; a package manager that pulls
// gigabyte artefacts has to resume rather than restart.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// blobRetries is how many times a cut transfer is resumed before giving up, and
// blobBackoff paces the attempts. Vars so tests need no real waiting.
var (
	blobRetries = 5
	blobBackoff = func(attempt int) { time.Sleep(time.Duration(attempt) * 500 * time.Millisecond) }
)

// fetchBlob downloads desc's content, resuming with a Range request whenever the
// connection is cut short, and verifies the digest of the assembled bytes — the
// pieces come from separate responses, so nothing but the digest proves they
// belong together.
func (c *OCIClient) fetchBlob(ctx context.Context, project string, desc ocispec.Descriptor) ([]byte, error) {
	url := c.scheme() + "://" + c.host + "/v2/" + c.repoName(project) + "/blobs/" + desc.Digest.String()
	var buf []byte
	var lastErr error
	for attempt := 0; attempt <= blobRetries; attempt++ {
		if attempt > 0 {
			blobBackoff(attempt)
		}
		n, err := c.appendBlobFrom(ctx, url, len(buf), &buf)
		if err == nil {
			break
		}
		lastErr = err
		// No progress at all on this attempt: the failure is not a cut transfer
		// (a 404, an auth refusal, a dead host), so retrying is pointless.
		if n == 0 && attempt > 0 {
			return nil, err
		}
	}
	if desc.Size > 0 && int64(len(buf)) != desc.Size {
		if lastErr == nil {
			lastErr = io.ErrUnexpectedEOF
		}
		return nil, fmt.Errorf("blob %s: got %d of %d bytes: %w", desc.Digest, len(buf), desc.Size, lastErr)
	}
	sum := sha256.Sum256(buf)
	if got := "sha256:" + hex.EncodeToString(sum[:]); got != desc.Digest.String() {
		return nil, fmt.Errorf("blob digest mismatch: got %s, want %s", got, desc.Digest)
	}
	return buf, nil
}

// appendBlobFrom requests the blob from byte offset and appends what it manages
// to read to buf, returning how many bytes this attempt added. A registry that
// ignores the Range header (answering 200 with the whole blob) is handled by
// restarting the buffer.
func (c *OCIClient) appendBlobFrom(ctx context.Context, url string, offset int, buf *[]byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	if offset > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		*buf = (*buf)[:0] // the registry ignored Range: start over
	case http.StatusPartialContent:
	default:
		return 0, fmt.Errorf("blob request: unexpected status %s", resp.Status)
	}
	before := len(*buf)
	data, err := io.ReadAll(resp.Body)
	*buf = append(*buf, data...)
	return len(*buf) - before, err
}

// scheme is the URL scheme this client talks.
func (c *OCIClient) scheme() string {
	if c.plainHTTP {
		return "http"
	}
	return "https"
}
