package util

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/corbaltcode/kion/cmd/kion/config"
	"github.com/corbaltcode/kion/internal/client"
	"github.com/zalando/go-keyring"
)

const AppAPIKeyName = "Kion Tool"

func NewClient(cfg *config.Config, keyCfg *config.KeyConfig) (*client.Client, error) {
	host, err := cfg.StringErr("host")
	if err != nil {
		return nil, err
	}

	if keyCfg.Key != "" {
		if cfg.Bool("rotate-app-api-keys") {
			duration, err := cfg.DurationErr("app-api-key-duration")
			if err != nil {
				return nil, err
			}

			// rotate if expiring within three days
			if keyCfg.Created.Add(duration).Before(time.Now().Add(time.Hour * 72)) {
				kion := client.NewWithAppAPIKey(host, keyCfg.Key)
				key, err := kion.RotateAppAPIKey(keyCfg.Key)
				if err != nil {
					return nil, err
				}
				kion = client.NewWithAppAPIKey(host, key.Key)
				keyMetadata, err := kion.GetAppAPIKeyMetadata(key.ID)
				if err != nil {
					return nil, err
				}

				keyCfg.Key = key.Key
				keyCfg.Created = keyMetadata.Created
				err = keyCfg.Save()
				if err != nil {
					return nil, err
				}
			}
		}

		return client.NewWithAppAPIKey(host, keyCfg.Key), nil
	}

	idms, err := cfg.IntErr("idms")
	if err != nil {
		return nil, err
	}
	username, err := cfg.StringErr("username")
	if err != nil {
		return nil, err
	}

	// TODO: better error if no creds
	password, err := keyring.Get(KeyringService(host, idms), username)
	if err != nil {
		return nil, err
	}

	return client.Login(host, idms, username, password)
}

func KeyringService(host string, idms int) string {
	return fmt.Sprintf("%s/%d", host, idms)
}

func GetAWSSigninToken(accessKeyID string, secretAccessKey string, sessionToken string) (string, error) {
	session := map[string]string{
		"sessionId":    accessKeyID,
		"sessionKey":   secretAccessKey,
		"sessionToken": sessionToken,
	}
	sessionJSON, err := json.Marshal(session)
	if err != nil {
		return "", err
	}

	v := url.Values{}
	v.Add("Action", "getSigninToken")
	v.Add("Session", string(sessionJSON))
	url := "https://signin.aws.amazon.com/federation?" + v.Encode()

	resp, err := http.DefaultClient.Get(url)
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", errors.New(resp.Status)
	}

	out := struct {
		SigninToken string
	}{}

	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&out)
	if err != nil {
		return "", err
	}

	return out.SigninToken, nil
}
