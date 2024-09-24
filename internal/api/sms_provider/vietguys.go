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
	"strings"

	"github.com/supabase/auth/internal/conf"
)

const (
	vietGuysSmsUrl = "https://cloudsms4.vietguys.biz:4438/api/index.php"
	// vietGuysAuthUrl = "https://api-v2.vietguys.biz:4438/token/v1/refresh"
)

type VietguysProvider struct {
	Config        *conf.VietguysProviderConfiguration
	authToken     string
	refreshToken  string
	authExpiredAt int
}

type VietguysReponse struct {
	Error   int                    `json:"error"`
	Message string                 `json:"message"`
	Data    map[string]interface{} `json:"data"`
	Msgid   string                 `json:"msgid"`
	Carrier string                 `json:"carrier"`
}

// Creates a SmsProvider with the Messagebird Config
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

// Send an SMS containing the OTP with Messagebird's API
func (t *VietguysProvider) SendSms(phone string, message string) (string, error) {
	body := url.Values{
		"from":  {t.Config.From},
		"u":     {t.Config.Username},
		"pwd":   {t.Config.Token},
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

	// validate sms status
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

// func (t *VietguysProvider) auth() (string, error) {
// 	if t.authExpiredAt > int(time.Now().Unix())-300 {
// 		return t.authToken, nil
// 	}

// 	body := map[string]string{
// 		"username": t.Config.Username,
// 		"type":     "refresh_token",
// 	}

// 	data, err := json.Marshal(body)
// 	if err != nil {
// 		return "", err
// 	}

// 	client := &http.Client{Timeout: defaultTimeout}
// 	r, err := http.NewRequest("POST", vietGuysAuthUrl, bytes.NewReader(data))
// 	if err != nil {
// 		return "", err
// 	}
// 	r.Header.Add("Content-Type", "application/json")
// 	token := t.refreshToken
// 	if len(token) == 0 {
// 		token = t.Config.Token
// 	}
// 	r.Header.Add("Refresh-Token", token)
// 	res, err := client.Do(r)
// 	if err != nil {
// 		return "", err
// 	}

// 	respBody, err := readBody(res.Body)
// 	if err != nil {
// 		return "", err
// 	}
// 	if res.StatusCode != http.StatusOK {
// 		return "", errors.New(string(respBody))
// 	}

// 	// validate sms status
// 	resp := &VietguysReponse{}
// 	derr := json.Unmarshal(respBody, resp)
// 	if derr != nil {
// 		return "", derr
// 	}

// 	if resp.Error != 0 {
// 		return "", fmt.Errorf(string(respBody))
// 	}

// 	fmt.Println("----------------------------", resp.Data)
// 	t.authToken = resp.Data["access_token"].(string)
// 	t.refreshToken = resp.Data["refresh_token"].(string)
// 	t.authExpiredAt = int(resp.Data["expired_at"].(float64) / 1000)
// 	fmt.Println("----------------------------", t.authToken, t.authExpiredAt)

// 	return t.authToken, nil
// }

func readBody(rc io.ReadCloser) ([]byte, error) {
	defer rc.Close()
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(rc)
	if err != nil {
		return []byte{}, err
	}
	return buf.Bytes(), nil
}
