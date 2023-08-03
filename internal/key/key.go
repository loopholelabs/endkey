package key

const (
	DelimiterString = "."
)

var (
	Delimiter = []byte(DelimiterString)
)

const (
	RootPrefixString = "RK-"
	UserPrefixString = "UK-"
	APIPrefixString  = "AK-"
)

var (
	RootPrefix = []byte(RootPrefixString)
	UserPrefix = []byte(UserPrefixString)
	APIPrefix  = []byte(APIPrefixString)
)
