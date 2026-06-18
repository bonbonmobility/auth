package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/utilities"
)

const authV2ProxyTimeout = 30 * time.Second

// AuthV2Proxy forwards selected auth endpoints to fastify-auth.
type AuthV2Proxy struct {
	client            *http.Client
	baseURL           string
	apiKey            string
	defaultOtpChannel string
}

func newAuthV2Proxy(config *conf.GlobalConfiguration) *AuthV2Proxy {
	if !config.AuthV2.Enabled {
		return nil
	}
	timeout := authV2ProxyTimeout
	if config.API.MaxRequestDuration > 0 {
		timeout = config.API.MaxRequestDuration
	}
	defaultOtpChannel := strings.ToLower(strings.TrimSpace(config.AuthV2.DefaultOtpChannel))
	if defaultOtpChannel == "" {
		defaultOtpChannel = "zalo"
	}
	return &AuthV2Proxy{
		client: &http.Client{
			Timeout: timeout,
		},
		baseURL:           strings.TrimRight(strings.TrimSpace(config.AuthV2.BaseURL), "/"),
		apiKey:            strings.TrimSpace(config.AuthV2.APIKey),
		defaultOtpChannel: defaultOtpChannel,
	}
}

func (a *API) shouldProxyPhoneOtp(params *OtpParams) bool {
	return a.authV2Proxy != nil && params.Phone != "" && params.Email == ""
}

func (a *API) shouldProxySmsVerify(r *http.Request, verifyType string) bool {
	return a.authV2Proxy != nil && r.Method == http.MethodPost && verifyType == smsVerification
}

func (a *API) shouldProxyRefreshToken(grantType string) bool {
	return a.authV2Proxy != nil && grantType == "refresh_token"
}

// Forward relays the incoming request to fastify-auth and writes the transformed response.
func (p *AuthV2Proxy) Forward(w http.ResponseWriter, r *http.Request, path string) error {
	bodyBytes, err := getBodyBytes(r)
	if err != nil {
		return internalServerError("failed to read auth v2 proxy request body").WithInternalError(err)
	}
	if path == "/otp" {
		bodyBytes, err = p.applyDefaultOtpChannel(bodyBytes)
		if err != nil {
			return internalServerError("failed to prepare auth v2 otp request").WithInternalError(err)
		}
	}

	upstreamURL := p.baseURL + path
	if r.URL.RawQuery != "" {
		upstreamURL += "?" + r.URL.RawQuery
	}

	upstreamRequest, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return internalServerError("failed to create auth v2 proxy request").WithInternalError(err)
	}

	upstreamRequest.Header.Set("Content-Type", "application/json")
	upstreamRequest.Header.Set("Accept", "application/json")
	upstreamRequest.Header.Set("x-api-key", p.apiKey)
	copyAuthV2ProxyRequestHeaders(r, upstreamRequest)

	logrus.WithFields(logrus.Fields{
		"path":   path,
		"method": r.Method,
		"url":    upstreamURL,
	}).Info("proxying auth request to auth v2")

	upstreamResponse, err := p.client.Do(upstreamRequest)
	if err != nil {
		return internalServerError("auth v2 proxy request failed").WithInternalError(err)
	}
	defer upstreamResponse.Body.Close()

	responseBody, err := io.ReadAll(upstreamResponse.Body)
	if err != nil {
		return internalServerError("failed to read auth v2 proxy response").WithInternalError(err)
	}

	transformedBody, statusCode := transformAuthV2ProxyResponse(r, upstreamResponse.StatusCode, responseBody)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if _, err := w.Write(transformedBody); err != nil {
		return internalServerError("failed to write auth v2 proxy response").WithInternalError(err)
	}
	return nil
}

func (p *AuthV2Proxy) applyDefaultOtpChannel(bodyBytes []byte) ([]byte, error) {
	if len(bodyBytes) == 0 {
		return json.Marshal(map[string]string{
			"channel": p.defaultOtpChannel,
		})
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		return bodyBytes, nil
	}
	channelValue, hasChannel := payload["channel"]
	channel, _ := channelValue.(string)
	if !hasChannel || strings.TrimSpace(channel) == "" {
		payload["channel"] = p.defaultOtpChannel
		return json.Marshal(payload)
	}
	return bodyBytes, nil
}

func copyAuthV2ProxyRequestHeaders(source *http.Request, target *http.Request) {
	if requestID := utilities.GetRequestID(source.Context()); requestID != "" {
		target.Header.Set("X-Request-ID", requestID)
	}
	if forwardedFor := source.Header.Get("X-Forwarded-For"); forwardedFor != "" {
		target.Header.Set("X-Forwarded-For", forwardedFor)
	}
	if realIP := source.Header.Get("X-Real-IP"); realIP != "" {
		target.Header.Set("X-Real-IP", realIP)
	}
	if userAgent := source.Header.Get("User-Agent"); userAgent != "" {
		target.Header.Set("User-Agent", userAgent)
	}
}

type authV2FlatErrorResponse struct {
	StatusCode int    `json:"status_code"`
	Error      string `json:"error"`
	Message    string `json:"message"`
}

type authV2OAuthErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func transformAuthV2ProxyResponse(r *http.Request, statusCode int, body []byte) ([]byte, int) {
	if len(body) == 0 {
		return body, statusCode
	}

	var flatError authV2FlatErrorResponse
	if err := json.Unmarshal(body, &flatError); err == nil && flatError.StatusCode > 0 && flatError.Message != "" {
		errorCode, message := mapAuthV2ErrorToGo(flatError)
		apiVersion, _ := DetermineClosestAPIVersion(r.Header.Get(APIVersionHeaderName))
		if apiVersion.Compare(APIVersion20240101) >= 0 {
			encoded, err := json.Marshal(HTTPErrorResponse20240101{
				Code:    errorCode,
				Message: message,
			})
			if err != nil {
				return body, statusCode
			}
			return encoded, flatError.StatusCode
		}

		encoded, err := json.Marshal(HTTPError{
			HTTPStatus: flatError.StatusCode,
			ErrorCode:  errorCode,
			Message:    message,
		})
		if err != nil {
			return body, statusCode
		}
		return encoded, flatError.StatusCode
	}

	var oauthError authV2OAuthErrorResponse
	if err := json.Unmarshal(body, &oauthError); err == nil && oauthError.Error != "" && oauthError.ErrorDescription != "" {
		return body, statusCode
	}

	return body, statusCode
}

func mapAuthV2ErrorToGo(flatError authV2FlatErrorResponse) (ErrorCode, string) {
	message := flatError.Message
	lowerMessage := strings.ToLower(message)

	switch flatError.StatusCode {
	case http.StatusTooManyRequests:
		return ErrorCodeOverSMSSendRateLimit, message
	case http.StatusForbidden:
		if strings.Contains(lowerMessage, "banned") || strings.Contains(lowerMessage, "not allowed") {
			return ErrorCodeUserBanned, message
		}
		if strings.Contains(lowerMessage, "invalid or expired otp") || strings.Contains(lowerMessage, "sign in") {
			return ErrorCodeOTPExpired, "Token has expired or is invalid"
		}
		return ErrorCodeOTPExpired, message
	case http.StatusUnprocessableEntity:
		if strings.Contains(lowerMessage, "signup") {
			return ErrorCodeOTPDisabled, "Signups not allowed for otp"
		}
		if strings.Contains(lowerMessage, "sms") || strings.Contains(lowerMessage, "provider") {
			return ErrorCodeSMSSendFailed, message
		}
		return ErrorCodeValidationFailed, message
	case http.StatusBadRequest:
		if strings.Contains(lowerMessage, "phone") || strings.Contains(lowerMessage, "channel") {
			return ErrorCodeValidationFailed, message
		}
		return ErrorCodeValidationFailed, message
	default:
		if flatError.StatusCode >= http.StatusInternalServerError {
			return ErrorCodeUnexpectedFailure, "Unexpected failure, please check server logs for more information"
		}
		return ErrorCodeValidationFailed, message
	}
}
