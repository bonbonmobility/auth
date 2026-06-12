package sms_provider

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/supabase/auth/internal/conf"
)

const (
	vietGuysSmsUrl = "https://cloudsms4.vietguys.biz:4438/api/index.php"
)

type VietguysProvider struct {
	Config        *conf.VietguysProviderConfiguration
	authToken     string
	refreshToken  string
	authExpiredAt int64
	mu            sync.Mutex
}

type VietguysReponse struct {
	Error   int                    `json:"error"`
	Message string                 `json:"message"`
	Data    map[string]interface{} `json:"data"`
	Msgid   string                 `json:"msgid"`
	Carrier string                 `json:"carrier"`
}

type bookingSmsTokensResponse struct {
	Success bool              `json:"success"`
	Data    []bookingSmsToken `json:"data"`
}

type bookingSmsToken struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiredAt    string `json:"expired_at"`
}

func NewVietguysProvider(config conf.VietguysProviderConfiguration) (SmsProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return &VietguysProvider{
		Config: &config,
	}, nil
}

func (t *VietguysProvider) SendMessage(phone, message, channel, otp string) (string, error) {
	switch channel {
	case SMSProvider:
		return t.SendSms(phone, message)
	default:
		return "", fmt.Errorf("channel type %q is not supported for Vietguys", channel)
	}
}

func (t *VietguysProvider) SendSms(phone string, message string) (string, error) {
	token, err := t.getToken()
	if err != nil {
		return "", err
	}

	body := url.Values{
		"from":  {t.Config.From},
		"u":     {t.Config.Username},
		"pwd":   {token},
		"phone": {phone},
		"sms":   {message},
		"bid":   {fmt.Sprintf("%d", rand.Intn(1000000000))},
		"type":  {"0"},
		"json":  {"1"},
	}

	client := &http.Client{Timeout: defaultTimeout}
	r, err := http.NewRequest("POST", vietGuysSmsUrl, strings.NewReader(body.Encode()))
	if err != nil {
		return "", err
	}
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	res, err := client.Do(r)
	if err != nil {
		return "", err
	}

	respBody, err := readBody(res.Body)
	if err != nil {
		return "", err
	}
	if res.StatusCode != http.StatusOK {
		return "", errors.New(string(respBody))
	}

	resp := &VietguysReponse{}
	derr := json.Unmarshal(respBody, resp)
	if derr != nil {
		return "", derr
	}

	if resp.Error != 0 {
		return "", fmt.Errorf(string(respBody))
	}

	return resp.Msgid, nil
}

func (t *VietguysProvider) getToken() (string, error) {
	if t.Config.BookingApiHost == "" {
		return t.Config.Token, nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now().Unix()
	if t.authToken != "" && t.authExpiredAt > now+300 {
		return t.authToken, nil
	}

	token, err := t.fetchTokenFromBookingAPI()
	if err != nil {
		return "", err
	}

	return token, nil
}

func (t *VietguysProvider) fetchTokenFromBookingAPI() (string, error) {
	apiURL := strings.TrimSuffix(t.Config.BookingApiHost, "/") + "/api/v1/sms-tokens"

	client := &http.Client{Timeout: defaultTimeout}
	r, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return "", err
	}
	r.Header.Set("x-api-key", t.Config.AdminApiKey)

	res, err := client.Do(r)
	if err != nil {
		return "", err
	}

	respBody, err := readBody(res.Body)
	if err != nil {
		return "", err
	}
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("booking API returned status %d: %s", res.StatusCode, string(respBody))
	}

	resp := &bookingSmsTokensResponse{}
	if err := json.Unmarshal(respBody, resp); err != nil {
		return "", err
	}
	if !resp.Success {
		return "", errors.New("booking API returned unsuccessful response")
	}
	if len(resp.Data) == 0 {
		return "", errors.New("booking API returned no SMS tokens")
	}

	token := resp.Data[0]
	if token.AccessToken == "" {
		return "", errors.New("booking API returned empty access token")
	}

	expiredAtMs, err := strconv.ParseInt(token.ExpiredAt, 10, 64)
	if err != nil {
		return "", fmt.Errorf("invalid expired_at from booking API: %w", err)
	}

	t.authToken = token.AccessToken
	t.refreshToken = token.RefreshToken
	t.authExpiredAt = expiredAtMs / 1000

	return t.authToken, nil
}

func readBody(rc io.ReadCloser) ([]byte, error) {
	defer rc.Close()
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(rc)
	if err != nil {
		return []byte{}, err
	}
	return buf.Bytes(), nil
}
