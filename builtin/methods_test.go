package builtin

import (
	"testing"

	"github.com/post-quantumqoin/core-types/abi"
	"github.com/stretchr/testify/require"
)

func TestGenerateMethodNum(t *testing.T) {

	methodNum, err := GenerateFRCMethodNum("Receive")
	require.NoError(t, err)
	require.Equal(t, methodNum, abi.MethodNum(3726118371))
}
