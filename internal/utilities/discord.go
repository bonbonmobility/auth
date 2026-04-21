package utilities

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

type DiscordMessage struct {
	Content string `json:"content"`
}

func SendDiscordNotification(webhookURL string, message string) {
	if webhookURL == "" {
		return
	}

	go func() {
		msg := DiscordMessage{
			Content: fmt.Sprintf("[%s] %s", time.Now().Format("2006-01-02 15:04:05"), message),
		}

		body, err := json.Marshal(msg)
		if err != nil {
			logrus.WithError(err).Error("Error marshaling discord message")
			return
		}

		resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(body))
		if err != nil {
			logrus.WithError(err).Error("Error sending discord notification")
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 400 {
			logrus.WithField("status", resp.Status).Error("Discord webhook returned error status")
		}
	}()
}
