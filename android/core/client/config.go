package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	kcrypto "github.com/kankipro/klink/internal/crypto"
	"github.com/kankipro/klink/internal/obfuscation"
)

const MaxSubscriptionBytes = 2 << 20

type TransportConfig struct {
	Network  string `json:"network"`
	Endpoint string `json:"endpoint"`
}

type Config struct {
	Version              int               `json:"klink_version"`
	Name                 string            `json:"name"`
	ClientPrivateKey     string            `json:"client_private_key"`
	ClientPublicKey      string            `json:"client_public_key"`
	ServerPublicKey      string            `json:"server_public_key"`
	Transports           []TransportConfig `json:"transports"`
	Obfuscation          string            `json:"obfuscation"`
	RekeyIntervalSeconds int64             `json:"rekey_interval_seconds"`
	RekeyPackets         uint64            `json:"rekey_packets"`
	SessionIDBits        int               `json:"session_id_bits"`
}

func (c *Config) RekeyInterval() time.Duration {
	if c.RekeyIntervalSeconds <= 0 {
		return 15 * time.Minute
	}
	return time.Duration(c.RekeyIntervalSeconds) * time.Second
}

func ParseSubscription(data []byte) (*Config, error) {
	var cfg Config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("فرمت اشتراک معتبر نیست: %w", err)
	}
	if cfg.Version != 1 || cfg.SessionIDBits != 128 {
		return nil, errors.New("نسخه‌ی پروتکل اشتراک پشتیبانی نمی‌شود")
	}
	key, err := kcrypto.KeyFromBase64(cfg.ClientPrivateKey)
	if err != nil {
		return nil, errors.New("کلید خصوصی کلاینت معتبر نیست")
	}
	if cfg.ClientPublicKey != "" {
		provided, err := base64.StdEncoding.DecodeString(cfg.ClientPublicKey)
		if err != nil || !bytes.Equal(provided, key.Public[:]) {
			return nil, errors.New("کلیدهای عمومی و خصوصی کلاینت مطابقت ندارند")
		}
	}
	if _, err := kcrypto.PublicFromBase64(cfg.ServerPublicKey); err != nil {
		return nil, errors.New("کلید عمومی سرور معتبر نیست")
	}
	if _, err := obfuscation.ByName(cfg.Obfuscation); err != nil {
		return nil, errors.New("پروفایل مخفی‌سازی پشتیبانی نمی‌شود")
	}
	if len(cfg.Transports) == 0 {
		return nil, errors.New("هیچ آدرس سروری در اشتراک وجود ندارد")
	}
	seen := make(map[string]bool)
	for _, t := range cfg.Transports {
		if t.Network != "udp" && t.Network != "tcp" {
			return nil, errors.New("نوع انتقال باید udp یا tcp باشد")
		}
		if seen[t.Network] {
			return nil, fmt.Errorf("آدرس تکراری برای %s", t.Network)
		}
		seen[t.Network] = true
		if _, _, err := net.SplitHostPort(t.Endpoint); err != nil {
			return nil, fmt.Errorf("آدرس %s معتبر نیست", t.Network)
		}
	}
	if cfg.Name == "" {
		cfg.Name = "KLINK"
	}
	if cfg.RekeyPackets == 0 {
		cfg.RekeyPackets = 1 << 20
	}
	return &cfg, nil
}

func (c *Config) CanonicalJSON() (string, error) {
	data, err := json.Marshal(c)
	return string(data), err
}

func FetchSubscription(ctx context.Context, input string) (string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", errors.New("لینک اشتراک خالی است")
	}
	var data []byte
	if strings.HasPrefix(input, "{") {
		data = []byte(input)
	} else {
		if !strings.HasPrefix(input, "https://") && !strings.HasPrefix(input, "http://") {
			return "", errors.New("لینک باید با https:// یا http:// شروع شود")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, input, nil)
		if err != nil {
			return "", errors.New("آدرس اشتراک معتبر نیست")
		}
		req.Header.Set("User-Agent", "KLINK-Android/1")
		req.Header.Set("Accept", "application/json")
		client := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return nil
		}}
		resp, err := client.Do(req)
		if err != nil {
			return "", fmt.Errorf("دریافت اشتراک ناموفق بود: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("سرور اشتراک با کد %d پاسخ داد", resp.StatusCode)
		}
		data, err = io.ReadAll(io.LimitReader(resp.Body, MaxSubscriptionBytes+1))
		if err != nil {
			return "", fmt.Errorf("خواندن اشتراک ناموفق بود: %w", err)
		}
	}
	if len(data) == 0 || len(data) > MaxSubscriptionBytes {
		return "", errors.New("حجم پاسخ اشتراک مجاز نیست")
	}
	cfg, err := ParseSubscription(data)
	if err != nil {
		return "", err
	}
	return cfg.CanonicalJSON()
}
