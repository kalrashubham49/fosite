// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/kalrashubham49/fosite (interfaces: TokenEndpointHandler)

// Package internal is a generated GoMock package.
package internal

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"

	fosite "github.com/kalrashubham49/fosite"
)

// MockTokenEndpointHandler is a mock of TokenEndpointHandler interface
type MockTokenEndpointHandler struct {
	ctrl     *gomock.Controller
	recorder *MockTokenEndpointHandlerMockRecorder
}

// MockTokenEndpointHandlerMockRecorder is the mock recorder for MockTokenEndpointHandler
type MockTokenEndpointHandlerMockRecorder struct {
	mock *MockTokenEndpointHandler
}

// NewMockTokenEndpointHandler creates a new mock instance
func NewMockTokenEndpointHandler(ctrl *gomock.Controller) *MockTokenEndpointHandler {
	mock := &MockTokenEndpointHandler{ctrl: ctrl}
	mock.recorder = &MockTokenEndpointHandlerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockTokenEndpointHandler) EXPECT() *MockTokenEndpointHandlerMockRecorder {
	return m.recorder
}

// HandleTokenEndpointRequest mocks base method
func (m *MockTokenEndpointHandler) HandleTokenEndpointRequest(arg0 context.Context, arg1 fosite.AccessRequester) error {
	ret := m.ctrl.Call(m, "HandleTokenEndpointRequest", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// HandleTokenEndpointRequest indicates an expected call of HandleTokenEndpointRequest
func (mr *MockTokenEndpointHandlerMockRecorder) HandleTokenEndpointRequest(arg0, arg1 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HandleTokenEndpointRequest", reflect.TypeOf((*MockTokenEndpointHandler)(nil).HandleTokenEndpointRequest), arg0, arg1)
}

// PopulateTokenEndpointResponse mocks base method
func (m *MockTokenEndpointHandler) PopulateTokenEndpointResponse(arg0 context.Context, arg1 fosite.AccessRequester, arg2 fosite.AccessResponder) error {
	ret := m.ctrl.Call(m, "PopulateTokenEndpointResponse", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// PopulateTokenEndpointResponse indicates an expected call of PopulateTokenEndpointResponse
func (mr *MockTokenEndpointHandlerMockRecorder) PopulateTokenEndpointResponse(arg0, arg1, arg2 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PopulateTokenEndpointResponse", reflect.TypeOf((*MockTokenEndpointHandler)(nil).PopulateTokenEndpointResponse), arg0, arg1, arg2)
}
