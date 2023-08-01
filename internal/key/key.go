package key

const (
	DelimiterString = "."
)

var (
	Delimiter = []byte(DelimiterString)
)

type Prefix []byte

var (
	RootPrefix = []byte("RK-")
	APIPrefix  = []byte("AK-")
)
