// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/scionproto/scion/go/sig/egress/iface (interfaces: Session)

// Package mock_iface is a generated GoMock package.
package mock_iface

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	addr "github.com/scionproto/scion/go/lib/addr"
	sig_mgmt "github.com/scionproto/scion/go/lib/ctrl/sig_mgmt"
	log "github.com/scionproto/scion/go/lib/log"
	ringbuf "github.com/scionproto/scion/go/lib/ringbuf"
	snet "github.com/scionproto/scion/go/lib/snet"
	iface "github.com/scionproto/scion/go/sig/egress/iface"
)

// MockSession is a mock of Session interface
type MockSession struct {
	ctrl     *gomock.Controller
	recorder *MockSessionMockRecorder
}

// MockSessionMockRecorder is the mock recorder for MockSession
type MockSessionMockRecorder struct {
	mock *MockSession
}

// NewMockSession creates a new mock instance
func NewMockSession(ctrl *gomock.Controller) *MockSession {
	mock := &MockSession{ctrl: ctrl}
	mock.recorder = &MockSessionMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockSession) EXPECT() *MockSessionMockRecorder {
	return m.recorder
}

// AnnounceWorkerStopped mocks base method
func (m *MockSession) AnnounceWorkerStopped() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "AnnounceWorkerStopped")
}

// AnnounceWorkerStopped indicates an expected call of AnnounceWorkerStopped
func (mr *MockSessionMockRecorder) AnnounceWorkerStopped() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AnnounceWorkerStopped", reflect.TypeOf((*MockSession)(nil).AnnounceWorkerStopped))
}

// Cleanup mocks base method
func (m *MockSession) Cleanup() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Cleanup")
	ret0, _ := ret[0].(error)
	return ret0
}

// Cleanup indicates an expected call of Cleanup
func (mr *MockSessionMockRecorder) Cleanup() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Cleanup", reflect.TypeOf((*MockSession)(nil).Cleanup))
}

// Conn mocks base method
func (m *MockSession) Conn() *snet.Conn {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Conn")
	ret0, _ := ret[0].(*snet.Conn)
	return ret0
}

// Conn indicates an expected call of Conn
func (mr *MockSessionMockRecorder) Conn() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Conn", reflect.TypeOf((*MockSession)(nil).Conn))
}

// Healthy mocks base method
func (m *MockSession) Healthy() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Healthy")
	ret0, _ := ret[0].(bool)
	return ret0
}

// Healthy indicates an expected call of Healthy
func (mr *MockSessionMockRecorder) Healthy() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Healthy", reflect.TypeOf((*MockSession)(nil).Healthy))
}

// IA mocks base method
func (m *MockSession) IA() addr.IA {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IA")
	ret0, _ := ret[0].(addr.IA)
	return ret0
}

// IA indicates an expected call of IA
func (mr *MockSessionMockRecorder) IA() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IA", reflect.TypeOf((*MockSession)(nil).IA))
}

// ID mocks base method
func (m *MockSession) ID() sig_mgmt.SessionType {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ID")
	ret0, _ := ret[0].(sig_mgmt.SessionType)
	return ret0
}

// ID indicates an expected call of ID
func (mr *MockSessionMockRecorder) ID() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ID", reflect.TypeOf((*MockSession)(nil).ID))
}

// Logger mocks base method
func (m *MockSession) Logger() log.Logger {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Logger")
	ret0, _ := ret[0].(log.Logger)
	return ret0
}

// Logger indicates an expected call of Logger
func (mr *MockSessionMockRecorder) Logger() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Logger", reflect.TypeOf((*MockSession)(nil).Logger))
}

// PathPool mocks base method
func (m *MockSession) PathPool() iface.PathPool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PathPool")
	ret0, _ := ret[0].(iface.PathPool)
	return ret0
}

// PathPool indicates an expected call of PathPool
func (mr *MockSessionMockRecorder) PathPool() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PathPool", reflect.TypeOf((*MockSession)(nil).PathPool))
}

// Remote mocks base method
func (m *MockSession) Remote() *iface.RemoteInfo {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Remote")
	ret0, _ := ret[0].(*iface.RemoteInfo)
	return ret0
}

// Remote indicates an expected call of Remote
func (mr *MockSessionMockRecorder) Remote() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Remote", reflect.TypeOf((*MockSession)(nil).Remote))
}

// Ring mocks base method
func (m *MockSession) Ring() *ringbuf.Ring {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Ring")
	ret0, _ := ret[0].(*ringbuf.Ring)
	return ret0
}

// Ring indicates an expected call of Ring
func (mr *MockSessionMockRecorder) Ring() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Ring", reflect.TypeOf((*MockSession)(nil).Ring))
}
