package main

// 最小 HTTP 客户端：模拟浏览器的 cookie 行为（按名存取、随请求回带），
// 并把每次响应的 Set-Cookie 暴露给断言（验收标准 2：依赖方响应里绝不出现
// arauth 的会话 cookie）。另含 PoW 求解（与 web/pow-worker.js 同口径）。

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// maxRespBody 是响应体读取上限（本链路的响应都是数 KB 的 JSON）。
const maxRespBody = 1 << 20

type client struct {
	hc      *http.Client
	base    string
	cookies map[string]string // 模拟浏览器 cookie jar（按名存储）
}

// newClient 构建客户端。caFile 非空时把该 PEM（如 Caddy 内网 CA 根证书）
// 追加进系统根证书——信任自签 CA 的正确姿势，不是 InsecureSkipVerify。
func newClient(base, caFile string) (*client, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("读 CA 文件失败: %w", err)
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA 文件 %q 不含有效 PEM 证书", caFile)
		}
	}
	return &client{
		hc: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}},
			// 不自动跟随重定向：cookie 语义逐步断言，重定向交给链路代码。
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		base:    strings.TrimRight(base, "/"),
		cookies: make(map[string]string),
	}, nil
}

// response 是一次调用的结果：状态码、响应体、本次新收到的 cookie 名列表。
type response struct {
	status     int
	body       []byte
	setCookies []string
}

// do 发起一次调用：自动回带已存 cookie，登记新 cookie，返回响应。
// body 为 nil 时无请求体；为 []byte 时作为已编码的 JSON 原样发送
// （attestation/assertion 由虚拟验证器自行编码）；其余 JSON 编码。
func (c *client) do(method, path string, body any, headers map[string]string) (*response, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if b, ok := body.([]byte); ok {
			raw = b
		} else if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, c.base+path, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if len(c.cookies) > 0 {
		pairs := make([]string, 0, len(c.cookies))
		for name, value := range c.cookies {
			pairs = append(pairs, name+"="+value)
		}
		req.Header.Set("Cookie", strings.Join(pairs, "; "))
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxRespBody))
	if err != nil {
		return nil, err
	}

	r := &response{status: resp.StatusCode, body: respBody}
	for _, cookie := range resp.Cookies() {
		r.setCookies = append(r.setCookies, cookie.Name)
		if cookie.Value == "" {
			delete(c.cookies, cookie.Name) // 空值 = 清除（与浏览器语义一致）
		} else {
			c.cookies[cookie.Name] = cookie.Value
		}
	}
	return r, nil
}

// hasCookie 报告本次响应是否种了指定名字的 cookie。
func (r *response) hasCookie(name string) bool {
	for _, n := range r.setCookies {
		if n == name {
			return true
		}
	}
	return false
}

// json 把响应体解码进 v。
func (r *response) json(v any) error {
	return json.Unmarshal(r.body, v)
}

// solvePoW 求解 arauth 的 PoW：找 nonce 使 SHA-256(challenge ‖ nonce) 的
// 前 difficulty 位为零。nonce 取 8 字节大端计数器（与 web/pow-worker.js
// 及 internal/pow 的校验口径一致）。
func solvePoW(challenge []byte, difficulty int) []byte {
	nonce := make([]byte, 8)
	buf := make([]byte, 0, len(challenge)+len(nonce))
	buf = append(buf, challenge...)
	for i := uint64(0); ; i++ {
		binary.BigEndian.PutUint64(nonce, i)
		sum := sha256.Sum256(append(buf, nonce...))
		if leadingZeroBits(sum[:]) >= difficulty {
			return nonce
		}
	}
}

// leadingZeroBits 数哈希值的前导零位数（逐位，支持非整字节难度）。
func leadingZeroBits(b []byte) int {
	n := 0
	for n < len(b)*8 && b[n/8]&(0x80>>(n%8)) == 0 {
		n++
	}
	return n
}
