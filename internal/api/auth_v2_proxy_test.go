package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTransformAuthV2ProxyResponseOAuthPassthrough(t *testing.T) {
	body := []byte(`{"error":"invalid_grant","error_description":"Invalid Refresh Token: Session Not Found"}`)
	request := httptest.NewRequest(http.MethodPost, "/token?grant_type=refresh_token", nil)

	transformed, statusCode := transformAuthV2ProxyResponse(request, http.StatusBadRequest, body)

	assert.Equal(t, http.StatusBadRequest, statusCode)
	assert.JSONEq(t, string(body), string(transformed))
}

func TestTransformAuthV2ProxyResponseLegacyHTTPError(t *testing.T) {
	body := []byte(`{"status_code":403,"error":"Forbidden","message":"Invalid or expired OTP."}`)
	request := httptest.NewRequest(http.MethodPost, "/verify", nil)

	transformed, statusCode := transformAuthV2ProxyResponse(request, http.StatusForbidden, body)

	assert.Equal(t, http.StatusForbidden, statusCode)
	assert.JSONEq(t, `{"code":403,"error_code":"otp_expired","msg":"Token has expired or is invalid"}`, string(transformed))
}

func TestTransformAuthV2ProxyResponseAPIVersion20240101(t *testing.T) {
	body := []byte(`{"status_code":429,"error":"Too Many Requests","message":"Too many OTP requests. Please try again later."}`)
	request := httptest.NewRequest(http.MethodPost, "/otp", nil)
	request.Header.Set(APIVersionHeaderName, FormatAPIVersion(APIVersion20240101))

	transformed, statusCode := transformAuthV2ProxyResponse(request, http.StatusTooManyRequests, body)

	assert.Equal(t, http.StatusTooManyRequests, statusCode)
	assert.JSONEq(t, `{"code":"over_sms_send_rate_limit","message":"Too many OTP requests. Please try again later."}`, string(transformed))
}

func TestMapAuthV2ErrorToGoBannedUser(t *testing.T) {
	errorCode, message := mapAuthV2ErrorToGo(authV2FlatErrorResponse{
		StatusCode: http.StatusForbidden,
		Message:    "You are not allowed to request an OTP.",
	})

	assert.Equal(t, ErrorCodeUserBanned, errorCode)
	assert.Equal(t, "You are not allowed to request an OTP.", message)
}

func TestApplyDefaultOtpChannelUsesZaloWhenMissing(t *testing.T) {
	proxy := &AuthV2Proxy{defaultOtpChannel: "zalo"}

	transformed, err := proxy.applyDefaultOtpChannel([]byte(`{"phone":"+84901234567"}`))
	require.NoError(t, err)
	assert.JSONEq(t, `{"phone":"+84901234567","channel":"zalo"}`, string(transformed))
}

func TestApplyDefaultOtpChannelPreservesExplicitChannel(t *testing.T) {
	proxy := &AuthV2Proxy{defaultOtpChannel: "zalo"}

	body := []byte(`{"phone":"+84901234567","channel":"sms"}`)
	transformed, err := proxy.applyDefaultOtpChannel(body)
	require.NoError(t, err)
	assert.Equal(t, body, transformed)
}

func TestAuthV2ProxyDisabledByDefault(t *testing.T) {
	_, config, err := setupAPIForTest()
	require.NoError(t, err)

	assert.False(t, config.AuthV2.Enabled)
	assert.Nil(t, newAuthV2Proxy(config))
}
