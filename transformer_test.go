package netunnel

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNullTransformer(t *testing.T) {
	nt := NewNullTransformer()
	assert.NotNil(t, nt)

	var from, to bytes.Buffer
	from.WriteString("test-payload")
	n, e := nt.Wrap(&from, &to)
	assert.Nil(t, e)
	assert.True(t, n > 0)
	t.Logf("NullTransformer.Wrap %v bytes, to %v, err=%v", n, to.String(), e)

	var dst bytes.Buffer
	n, e = nt.Unwrap(&to, &dst)
	assert.Nil(t, e)
	assert.True(t, n > 0)
	t.Logf("NullTransformer.Unwrap %v bytes, dst %v, err=%v", n, dst.String(), e)
}

func TestAEADTransformer(t *testing.T) {
	key := []byte(strings.Repeat("ab", 16))
	at, err := NewAEADTransformer(AEADNameCHACHA20, key)
	assert.Nil(t, err)
	assert.NotNil(t, at)

	at, err = NewAEADTransformerPassword(AEADNameCHACHA20, "123456")
	assert.Nil(t, err)
	assert.NotNil(t, at)

	var from, to bytes.Buffer
	from.WriteString("test-payload")
	n, e := at.Wrap(&from, &to)
	assert.Nil(t, e)
	assert.True(t, n > 0)
	t.Logf("AEADTransformer.Wrap %v bytes, to %x, err=%v", n, to.Bytes(), e)

	var dst bytes.Buffer
	n, e = at.Unwrap(&to, &dst)
	assert.Nil(t, e)
	assert.True(t, n > 0)
	t.Logf("AEADTransformer.Unwrap %v bytes, dst %v, err=%v", n, dst.String(), e)
}
