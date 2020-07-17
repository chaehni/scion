package transfer

import "github.com/scionproto/scion/go/sig/zoning/types"

// MockFetcher implements the Fetcher interface for testing
type MockFetcher struct {
	subs  types.Subnets
	trans types.Transfers
}

var _ = Fetcher(&MockFetcher{})

func NewMockFetcher(subnets types.Subnets, transfers types.Transfers) *MockFetcher {
	return &MockFetcher{
		subs:  subnets,
		trans: transfers,
	}
}

func (f *MockFetcher) FetchSubnets() (types.Subnets, error) {
	return f.subs, nil
}

func (f *MockFetcher) FetchTransfers() (types.Transfers, error) {
	return f.trans, nil
}
