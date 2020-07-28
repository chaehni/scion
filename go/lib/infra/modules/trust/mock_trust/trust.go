// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/scionproto/scion/go/lib/infra/modules/trust (interfaces: CryptoProvider,DB,KeyRing,Inserter,Recurser,Resolver,Router,RPC)

// Package mock_trust is a generated GoMock package.
package mock_trust

import (
	context "context"
	sql "database/sql"
	net "net"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	addr "github.com/scionproto/scion/go/lib/addr"
	infra "github.com/scionproto/scion/go/lib/infra"
	trust "github.com/scionproto/scion/go/lib/infra/modules/trust"
	decoded "github.com/scionproto/scion/go/lib/infra/modules/trust/internal/decoded"
	keyconf "github.com/scionproto/scion/go/lib/keyconf"
	scrypto "github.com/scionproto/scion/go/lib/scrypto"
	trc "github.com/scionproto/scion/go/lib/scrypto/trc"
)

// MockCryptoProvider is a mock of CryptoProvider interface
type MockCryptoProvider struct {
	ctrl     *gomock.Controller
	recorder *MockCryptoProviderMockRecorder
}

// MockCryptoProviderMockRecorder is the mock recorder for MockCryptoProvider
type MockCryptoProviderMockRecorder struct {
	mock *MockCryptoProvider
}

// NewMockCryptoProvider creates a new mock instance
func NewMockCryptoProvider(ctrl *gomock.Controller) *MockCryptoProvider {
	mock := &MockCryptoProvider{ctrl: ctrl}
	mock.recorder = &MockCryptoProviderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockCryptoProvider) EXPECT() *MockCryptoProviderMockRecorder {
	return m.recorder
}

// AnnounceTRC mocks base method
func (m *MockCryptoProvider) AnnounceTRC(arg0 context.Context, arg1 trust.TRCID, arg2 infra.TRCOpts) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AnnounceTRC", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// AnnounceTRC indicates an expected call of AnnounceTRC
func (mr *MockCryptoProviderMockRecorder) AnnounceTRC(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AnnounceTRC", reflect.TypeOf((*MockCryptoProvider)(nil).AnnounceTRC), arg0, arg1, arg2)
}

// GetASKey mocks base method
func (m *MockCryptoProvider) GetASKey(arg0 context.Context, arg1 trust.ChainID, arg2 infra.ChainOpts) (scrypto.KeyMeta, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetASKey", arg0, arg1, arg2)
	ret0, _ := ret[0].(scrypto.KeyMeta)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetASKey indicates an expected call of GetASKey
func (mr *MockCryptoProviderMockRecorder) GetASKey(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetASKey", reflect.TypeOf((*MockCryptoProvider)(nil).GetASKey), arg0, arg1, arg2)
}

// GetRawChain mocks base method
func (m *MockCryptoProvider) GetRawChain(arg0 context.Context, arg1 trust.ChainID, arg2 infra.ChainOpts) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRawChain", arg0, arg1, arg2)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRawChain indicates an expected call of GetRawChain
func (mr *MockCryptoProviderMockRecorder) GetRawChain(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRawChain", reflect.TypeOf((*MockCryptoProvider)(nil).GetRawChain), arg0, arg1, arg2)
}

// GetRawTRC mocks base method
func (m *MockCryptoProvider) GetRawTRC(arg0 context.Context, arg1 trust.TRCID, arg2 infra.TRCOpts) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRawTRC", arg0, arg1, arg2)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRawTRC indicates an expected call of GetRawTRC
func (mr *MockCryptoProviderMockRecorder) GetRawTRC(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRawTRC", reflect.TypeOf((*MockCryptoProvider)(nil).GetRawTRC), arg0, arg1, arg2)
}

// GetTRC mocks base method
func (m *MockCryptoProvider) GetTRC(arg0 context.Context, arg1 trust.TRCID, arg2 infra.TRCOpts) (*trc.TRC, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTRC", arg0, arg1, arg2)
	ret0, _ := ret[0].(*trc.TRC)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetTRC indicates an expected call of GetTRC
func (mr *MockCryptoProviderMockRecorder) GetTRC(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTRC", reflect.TypeOf((*MockCryptoProvider)(nil).GetTRC), arg0, arg1, arg2)
}

// MockDB is a mock of DB interface
type MockDB struct {
	ctrl     *gomock.Controller
	recorder *MockDBMockRecorder
}

// MockDBMockRecorder is the mock recorder for MockDB
type MockDBMockRecorder struct {
	mock *MockDB
}

// NewMockDB creates a new mock instance
func NewMockDB(ctrl *gomock.Controller) *MockDB {
	mock := &MockDB{ctrl: ctrl}
	mock.recorder = &MockDBMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockDB) EXPECT() *MockDBMockRecorder {
	return m.recorder
}

// BeginTransaction mocks base method
func (m *MockDB) BeginTransaction(arg0 context.Context, arg1 *sql.TxOptions) (trust.Transaction, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "BeginTransaction", arg0, arg1)
	ret0, _ := ret[0].(trust.Transaction)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// BeginTransaction indicates an expected call of BeginTransaction
func (mr *MockDBMockRecorder) BeginTransaction(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BeginTransaction", reflect.TypeOf((*MockDB)(nil).BeginTransaction), arg0, arg1)
}

// ChainExists mocks base method
func (m *MockDB) ChainExists(arg0 context.Context, arg1 decoded.Chain) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ChainExists", arg0, arg1)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ChainExists indicates an expected call of ChainExists
func (mr *MockDBMockRecorder) ChainExists(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ChainExists", reflect.TypeOf((*MockDB)(nil).ChainExists), arg0, arg1)
}

// Close mocks base method
func (m *MockDB) Close() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Close")
	ret0, _ := ret[0].(error)
	return ret0
}

// Close indicates an expected call of Close
func (mr *MockDBMockRecorder) Close() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockDB)(nil).Close))
}

// GetIssuingGrantKeyInfo mocks base method
func (m *MockDB) GetIssuingGrantKeyInfo(arg0 context.Context, arg1 addr.IA, arg2 scrypto.Version) (trust.KeyInfo, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetIssuingGrantKeyInfo", arg0, arg1, arg2)
	ret0, _ := ret[0].(trust.KeyInfo)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetIssuingGrantKeyInfo indicates an expected call of GetIssuingGrantKeyInfo
func (mr *MockDBMockRecorder) GetIssuingGrantKeyInfo(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetIssuingGrantKeyInfo", reflect.TypeOf((*MockDB)(nil).GetIssuingGrantKeyInfo), arg0, arg1, arg2)
}

// GetRawChain mocks base method
func (m *MockDB) GetRawChain(arg0 context.Context, arg1 trust.ChainID) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRawChain", arg0, arg1)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRawChain indicates an expected call of GetRawChain
func (mr *MockDBMockRecorder) GetRawChain(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRawChain", reflect.TypeOf((*MockDB)(nil).GetRawChain), arg0, arg1)
}

// GetRawTRC mocks base method
func (m *MockDB) GetRawTRC(arg0 context.Context, arg1 trust.TRCID) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRawTRC", arg0, arg1)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRawTRC indicates an expected call of GetRawTRC
func (mr *MockDBMockRecorder) GetRawTRC(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRawTRC", reflect.TypeOf((*MockDB)(nil).GetRawTRC), arg0, arg1)
}

// GetTRC mocks base method
func (m *MockDB) GetTRC(arg0 context.Context, arg1 trust.TRCID) (*trc.TRC, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTRC", arg0, arg1)
	ret0, _ := ret[0].(*trc.TRC)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetTRC indicates an expected call of GetTRC
func (mr *MockDBMockRecorder) GetTRC(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTRC", reflect.TypeOf((*MockDB)(nil).GetTRC), arg0, arg1)
}

// GetTRCInfo mocks base method
func (m *MockDB) GetTRCInfo(arg0 context.Context, arg1 trust.TRCID) (trust.TRCInfo, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTRCInfo", arg0, arg1)
	ret0, _ := ret[0].(trust.TRCInfo)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetTRCInfo indicates an expected call of GetTRCInfo
func (mr *MockDBMockRecorder) GetTRCInfo(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTRCInfo", reflect.TypeOf((*MockDB)(nil).GetTRCInfo), arg0, arg1)
}

// InsertChain mocks base method
func (m *MockDB) InsertChain(arg0 context.Context, arg1 decoded.Chain) (bool, bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InsertChain", arg0, arg1)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(bool)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// InsertChain indicates an expected call of InsertChain
func (mr *MockDBMockRecorder) InsertChain(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InsertChain", reflect.TypeOf((*MockDB)(nil).InsertChain), arg0, arg1)
}

// InsertTRC mocks base method
func (m *MockDB) InsertTRC(arg0 context.Context, arg1 decoded.TRC) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InsertTRC", arg0, arg1)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// InsertTRC indicates an expected call of InsertTRC
func (mr *MockDBMockRecorder) InsertTRC(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InsertTRC", reflect.TypeOf((*MockDB)(nil).InsertTRC), arg0, arg1)
}

// SetMaxIdleConns mocks base method
func (m *MockDB) SetMaxIdleConns(arg0 int) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetMaxIdleConns", arg0)
}

// SetMaxIdleConns indicates an expected call of SetMaxIdleConns
func (mr *MockDBMockRecorder) SetMaxIdleConns(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetMaxIdleConns", reflect.TypeOf((*MockDB)(nil).SetMaxIdleConns), arg0)
}

// SetMaxOpenConns mocks base method
func (m *MockDB) SetMaxOpenConns(arg0 int) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetMaxOpenConns", arg0)
}

// SetMaxOpenConns indicates an expected call of SetMaxOpenConns
func (mr *MockDBMockRecorder) SetMaxOpenConns(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetMaxOpenConns", reflect.TypeOf((*MockDB)(nil).SetMaxOpenConns), arg0)
}

// TRCExists mocks base method
func (m *MockDB) TRCExists(arg0 context.Context, arg1 decoded.TRC) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "TRCExists", arg0, arg1)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// TRCExists indicates an expected call of TRCExists
func (mr *MockDBMockRecorder) TRCExists(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "TRCExists", reflect.TypeOf((*MockDB)(nil).TRCExists), arg0, arg1)
}

// MockKeyRing is a mock of KeyRing interface
type MockKeyRing struct {
	ctrl     *gomock.Controller
	recorder *MockKeyRingMockRecorder
}

// MockKeyRingMockRecorder is the mock recorder for MockKeyRing
type MockKeyRingMockRecorder struct {
	mock *MockKeyRing
}

// NewMockKeyRing creates a new mock instance
func NewMockKeyRing(ctrl *gomock.Controller) *MockKeyRing {
	mock := &MockKeyRing{ctrl: ctrl}
	mock.recorder = &MockKeyRingMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockKeyRing) EXPECT() *MockKeyRingMockRecorder {
	return m.recorder
}

// PrivateKey mocks base method
func (m *MockKeyRing) PrivateKey(arg0 keyconf.Usage, arg1 scrypto.KeyVersion) (keyconf.Key, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PrivateKey", arg0, arg1)
	ret0, _ := ret[0].(keyconf.Key)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PrivateKey indicates an expected call of PrivateKey
func (mr *MockKeyRingMockRecorder) PrivateKey(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PrivateKey", reflect.TypeOf((*MockKeyRing)(nil).PrivateKey), arg0, arg1)
}

// MockInserter is a mock of Inserter interface
type MockInserter struct {
	ctrl     *gomock.Controller
	recorder *MockInserterMockRecorder
}

// MockInserterMockRecorder is the mock recorder for MockInserter
type MockInserterMockRecorder struct {
	mock *MockInserter
}

// NewMockInserter creates a new mock instance
func NewMockInserter(ctrl *gomock.Controller) *MockInserter {
	mock := &MockInserter{ctrl: ctrl}
	mock.recorder = &MockInserterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockInserter) EXPECT() *MockInserterMockRecorder {
	return m.recorder
}

// InsertChain mocks base method
func (m *MockInserter) InsertChain(arg0 context.Context, arg1 decoded.Chain, arg2 trust.TRCProviderFunc) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InsertChain", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// InsertChain indicates an expected call of InsertChain
func (mr *MockInserterMockRecorder) InsertChain(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InsertChain", reflect.TypeOf((*MockInserter)(nil).InsertChain), arg0, arg1, arg2)
}

// InsertTRC mocks base method
func (m *MockInserter) InsertTRC(arg0 context.Context, arg1 decoded.TRC, arg2 trust.TRCProviderFunc) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InsertTRC", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// InsertTRC indicates an expected call of InsertTRC
func (mr *MockInserterMockRecorder) InsertTRC(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InsertTRC", reflect.TypeOf((*MockInserter)(nil).InsertTRC), arg0, arg1, arg2)
}

// MockRecurser is a mock of Recurser interface
type MockRecurser struct {
	ctrl     *gomock.Controller
	recorder *MockRecurserMockRecorder
}

// MockRecurserMockRecorder is the mock recorder for MockRecurser
type MockRecurserMockRecorder struct {
	mock *MockRecurser
}

// NewMockRecurser creates a new mock instance
func NewMockRecurser(ctrl *gomock.Controller) *MockRecurser {
	mock := &MockRecurser{ctrl: ctrl}
	mock.recorder = &MockRecurserMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockRecurser) EXPECT() *MockRecurserMockRecorder {
	return m.recorder
}

// AllowRecursion mocks base method
func (m *MockRecurser) AllowRecursion(arg0 net.Addr) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AllowRecursion", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// AllowRecursion indicates an expected call of AllowRecursion
func (mr *MockRecurserMockRecorder) AllowRecursion(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AllowRecursion", reflect.TypeOf((*MockRecurser)(nil).AllowRecursion), arg0)
}

// MockResolver is a mock of Resolver interface
type MockResolver struct {
	ctrl     *gomock.Controller
	recorder *MockResolverMockRecorder
}

// MockResolverMockRecorder is the mock recorder for MockResolver
type MockResolverMockRecorder struct {
	mock *MockResolver
}

// NewMockResolver creates a new mock instance
func NewMockResolver(ctrl *gomock.Controller) *MockResolver {
	mock := &MockResolver{ctrl: ctrl}
	mock.recorder = &MockResolverMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockResolver) EXPECT() *MockResolverMockRecorder {
	return m.recorder
}

// Chain mocks base method
func (m *MockResolver) Chain(arg0 context.Context, arg1 trust.ChainReq, arg2 net.Addr) (decoded.Chain, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Chain", arg0, arg1, arg2)
	ret0, _ := ret[0].(decoded.Chain)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Chain indicates an expected call of Chain
func (mr *MockResolverMockRecorder) Chain(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Chain", reflect.TypeOf((*MockResolver)(nil).Chain), arg0, arg1, arg2)
}

// TRC mocks base method
func (m *MockResolver) TRC(arg0 context.Context, arg1 trust.TRCReq, arg2 net.Addr) (decoded.TRC, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "TRC", arg0, arg1, arg2)
	ret0, _ := ret[0].(decoded.TRC)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// TRC indicates an expected call of TRC
func (mr *MockResolverMockRecorder) TRC(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "TRC", reflect.TypeOf((*MockResolver)(nil).TRC), arg0, arg1, arg2)
}

// MockRouter is a mock of Router interface
type MockRouter struct {
	ctrl     *gomock.Controller
	recorder *MockRouterMockRecorder
}

// MockRouterMockRecorder is the mock recorder for MockRouter
type MockRouterMockRecorder struct {
	mock *MockRouter
}

// NewMockRouter creates a new mock instance
func NewMockRouter(ctrl *gomock.Controller) *MockRouter {
	mock := &MockRouter{ctrl: ctrl}
	mock.recorder = &MockRouterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockRouter) EXPECT() *MockRouterMockRecorder {
	return m.recorder
}

// ChooseServer mocks base method
func (m *MockRouter) ChooseServer(arg0 context.Context, arg1 addr.ISD) (net.Addr, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ChooseServer", arg0, arg1)
	ret0, _ := ret[0].(net.Addr)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ChooseServer indicates an expected call of ChooseServer
func (mr *MockRouterMockRecorder) ChooseServer(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ChooseServer", reflect.TypeOf((*MockRouter)(nil).ChooseServer), arg0, arg1)
}

// MockRPC is a mock of RPC interface
type MockRPC struct {
	ctrl     *gomock.Controller
	recorder *MockRPCMockRecorder
}

// MockRPCMockRecorder is the mock recorder for MockRPC
type MockRPCMockRecorder struct {
	mock *MockRPC
}

// NewMockRPC creates a new mock instance
func NewMockRPC(ctrl *gomock.Controller) *MockRPC {
	mock := &MockRPC{ctrl: ctrl}
	mock.recorder = &MockRPCMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockRPC) EXPECT() *MockRPCMockRecorder {
	return m.recorder
}

// GetCertChain mocks base method
func (m *MockRPC) GetCertChain(arg0 context.Context, arg1 trust.ChainReq, arg2 net.Addr) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetCertChain", arg0, arg1, arg2)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetCertChain indicates an expected call of GetCertChain
func (mr *MockRPCMockRecorder) GetCertChain(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetCertChain", reflect.TypeOf((*MockRPC)(nil).GetCertChain), arg0, arg1, arg2)
}

// GetTRC mocks base method
func (m *MockRPC) GetTRC(arg0 context.Context, arg1 trust.TRCReq, arg2 net.Addr) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTRC", arg0, arg1, arg2)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetTRC indicates an expected call of GetTRC
func (mr *MockRPCMockRecorder) GetTRC(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTRC", reflect.TypeOf((*MockRPC)(nil).GetTRC), arg0, arg1, arg2)
}

// SendCertChain mocks base method
func (m *MockRPC) SendCertChain(arg0 context.Context, arg1 []byte, arg2 net.Addr) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendCertChain", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendCertChain indicates an expected call of SendCertChain
func (mr *MockRPCMockRecorder) SendCertChain(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendCertChain", reflect.TypeOf((*MockRPC)(nil).SendCertChain), arg0, arg1, arg2)
}

// SendTRC mocks base method
func (m *MockRPC) SendTRC(arg0 context.Context, arg1 []byte, arg2 net.Addr) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendTRC", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendTRC indicates an expected call of SendTRC
func (mr *MockRPCMockRecorder) SendTRC(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendTRC", reflect.TypeOf((*MockRPC)(nil).SendTRC), arg0, arg1, arg2)
}
