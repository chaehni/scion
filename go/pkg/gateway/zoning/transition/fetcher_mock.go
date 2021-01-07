package transition

import "github.com/scionproto/scion/go/pkg/gateway/zoning/types"

// MockFetcher implements the Fetcher interface for testing
type MockFetcher struct {
	subs  types.Subnets
	trans types.Transitions
}

var _ = Fetcher(&MockFetcher{})

func NewMockFetcher(subnets types.Subnets, transitions types.Transitions) *MockFetcher {
	return &MockFetcher{
		subs:  subnets,
		trans: transitions,
	}
}

func (f *MockFetcher) FetchSubnets() (types.Subnets, error) {
	return f.subs, nil
}

func (f *MockFetcher) FetchTransitions() (types.Transitions, error) {
	return f.trans, nil
}
