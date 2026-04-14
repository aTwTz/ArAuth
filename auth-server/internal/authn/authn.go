package authn

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/arithmaton/arauth/internal/config"
	"github.com/arithmaton/arauth/internal/store"
)

// ErrInvalidCeremony 表示 ceremony 验证失败。涵盖解析失败、challenge
// 不存在/过期/已消费、origin 不符、签名不合法等一切客户端侧失败——
// 对外不区分具体是哪一步（保密红线第 6 条），由 server 统一映射为 400。
var ErrInvalidCeremony = errors.New("authn: ceremony 验证未通过")

// ErrIdentityPending 表示凭据有效但 identity 尚未确认激活（恢复码未
// 确认）。能走到这一步的前提是持有真私钥并通过验签，对外由 server
// 单独映射为 403（响应体仍是不可区分的 invalid）。
var ErrIdentityPending = errors.New("authn: identity 未激活")

// CredentialStore 是 authn 对数据层的最小依赖：注册闭环要求 identity、
// 首条 credential 与恢复码哈希原子写入；登录闭环要求按 credential 定位、
// 身份激活态查询与登录信号落库；找回闭环要求挂新凭据与轮换恢复码同事务。
type CredentialStore interface {
	InsertRegistration(ctx context.Context, userHandle []byte, c *store.Credential, codeHash []byte) error
	GetCredential(ctx context.Context, credentialID []byte) (*store.Credential, error)
	GetIdentity(ctx context.Context, userHandle []byte) (*store.Identity, error)
	ActivateIdentity(ctx context.Context, userHandle []byte) error
	UpdateLoginSignals(ctx context.Context, credentialID []byte, backedUp, backupState bool, signCount *int64) error
	AttachCredentialAndRotate(ctx context.Context, c *store.Credential, newCodeHash []byte) error
}

// RecoveryGate 是 authn 对 internal/recovery 的最小依赖：恢复码的生成
// （注册发放与找回轮换）与恢复凭证（一次性 token）的查询/消费。
type RecoveryGate interface {
	// Generate 生成新恢复码，返回分组展示串（原文，仅此一次）与 SHA-256。
	Generate() (display string, hash []byte, err error)
	// LookupToken 查询恢复凭证对应的 user handle，不消费（options 阶段）。
	LookupToken(token []byte) (userHandle []byte, ok bool)
	// ConsumeToken 取出恢复凭证对应的 user handle 并作废（verify 一次性）。
	ConsumeToken(token []byte) (userHandle []byte, ok bool)
}

// Service 是 WebAuthn ceremony 的唯一裁决点（数据分级第 4 条）。
type Service struct {
	wa         *webauthn.WebAuthn
	challenges *challengeStore
	st         CredentialStore
	rec        RecoveryGate
	pendingTTL time.Duration
	// attestationStrict 是可选加固开关（默认关）：打开时注册只接受
	// attestation statement format 为 apple / android-key / packed
	// （带证书链），none 直接拒绝。
	attestationStrict bool
	now               func() time.Time // 可注入时钟，测试用
}

// New 从 config 构建 WebAuthn 实例。rp.id 显式取 config.RPID，绝不省略
// （省略时浏览器静默取当前完整主机名，DESIGN.md 第 8 节）；
// RPOrigins 为显式白名单，origin 校验失败即拒绝（由库裁决）。
func New(cfg *config.Config, st CredentialStore, rec RecoveryGate) (*Service, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPID,
		RPOrigins:     cfg.RPOrigins,
	})
	if err != nil {
		return nil, fmt.Errorf("authn: 构建 WebAuthn 实例失败: %w", err)
	}
	return &Service{
		wa:                wa,
		challenges:        newChallengeStore(cfg.ChallengeTTL),
		st:                st,
		rec:               rec,
		pendingTTL:        cfg.PendingTTL,
		attestationStrict: cfg.AttestationStrict,
		now:               time.Now,
	}, nil
}

// strictAttestationFormats 是加固开关打开时接受的 attestation statement
// format 白名单：三种带证书链的格式，none 不在其中。
var strictAttestationFormats = []protocol.AttestationFormat{
	protocol.AttestationFormatApple,
	protocol.AttestationFormatAndroidKey,
	protocol.AttestationFormatPacked,
}

// checkAttestationFormat 在加固开关打开时校验库解析出的格式是否在白名单
// 内——检查对象是 CreateCredential 验证通过后库给出的格式标识，不自行
// 解析 attestation 字节（数据分级第 4 条）。开关关闭时恒放行。
func (s *Service) checkAttestationFormat(cred *webauthn.Credential) error {
	if !s.attestationStrict {
		return nil
	}
	for _, f := range strictAttestationFormats {
		if cred.AttestationFormat == string(f) {
			return nil
		}
	}
	return fmt.Errorf("%w: attestation 格式 %q 不在白名单", ErrInvalidCeremony, cred.AttestationFormat)
}

// BeginRegistration 为全新身份生成 creation options：每次调用生成新的
// 64 字节随机 user handle，要求 discoverable 凭据与强制用户验证，
// challenge 连同会话暂存进内存（TTL 一次性）。
func (s *Service) BeginRegistration() (*protocol.CredentialCreation, error) {
	handle := make([]byte, userHandleLen)
	if _, err := rand.Read(handle); err != nil {
		return nil, fmt.Errorf("authn: 生成 user handle 失败: %w", err)
	}
	return s.beginRegistration(handle)
}

// beginRegistration 为指定 user handle 生成 creation options（注册与
// 找回挂新密钥共用，DESIGN.md 第 4 节两条流程的 options 形态一致）。
func (s *Service) beginRegistration(handle []byte) (*protocol.CredentialCreation, error) {
	requireResidentKey := true
	opts := []webauthn.RegistrationOption{
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			RequireResidentKey: &requireResidentKey,
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			UserVerification:   protocol.VerificationRequired,
		}),
	}
	// 加固开关打开时：options 里向客户端声明只接受带证书链的格式并请求
	// direct conveyance（库的配置层，WithAttestationFormats 只是客户端
	// 提示，强制校验在 verify 侧由 checkAttestationFormat 完成）。
	if s.attestationStrict {
		opts = append(opts,
			webauthn.WithConveyancePreference(protocol.PreferDirectAttestation),
			webauthn.WithAttestationFormats(strictAttestationFormats),
		)
	}
	creation, session, err := s.wa.BeginRegistration(newAnonUser(handle), opts...)
	if err != nil {
		return nil, fmt.Errorf("authn: 生成 creation options 失败: %w", err)
	}

	s.challenges.put(*session)
	return creation, nil
}

// Registration 是 verify 成功后交给会话层与客户端的信息。
// RecoveryCode 是恢复码原文（分组展示串），只在本响应里出现一次——
// 服务器只存 SHA-256，此后任何接口都无法再取到原文。
// UserHandle 仅供服务器内部签发 pending 会话用，不下发给客户端
// （响应白名单见 server.registerVerify，保密红线第 7 条）。
type Registration struct {
	CredentialID []byte
	BackedUp     bool   // BE flag
	RecoveryCode string // 恢复码原文，仅此一次
	UserHandle   []byte // 内部字段，不下发
}

// FinishRegistration 验证 attestation 并落库：解析响应 → 按 challenge
// 一次性消费会话 → CreateCredential 完成全部验证（challenge、origin、
// RP ID hash、flags、签名均由 go-webauthn 裁决）→ 提取 credential ID、
// COSE 公钥、AAGUID、attachment、transports、BE/BS → 生成恢复码 →
// 事务写入 identity(pending) + credential + 恢复码哈希。
// BE/BS 只存为提示元数据，平台信号策略在登录模块生效（DESIGN.md 第 5 节）。
func (s *Service) FinishRegistration(ctx context.Context, r *http.Request) (*Registration, error) {
	pcc, err := protocol.ParseCredentialCreationResponse(r)
	if err != nil {
		return nil, fmt.Errorf("%w: 解析 attestation 响应: %v", ErrInvalidCeremony, err)
	}

	session, ok := s.challenges.consume(pcc.Response.CollectedClientData.Challenge)
	if !ok {
		return nil, fmt.Errorf("%w: challenge 无效", ErrInvalidCeremony)
	}

	cred, err := s.wa.CreateCredential(newAnonUser(session.UserID), session, pcc)
	if err != nil {
		return nil, fmt.Errorf("%w: attestation 验证: %v", ErrInvalidCeremony, err)
	}
	if err := s.checkAttestationFormat(cred); err != nil {
		return nil, err
	}

	display, codeHash, err := s.rec.Generate()
	if err != nil {
		return nil, fmt.Errorf("authn: 生成恢复码失败: %w", err)
	}

	record := credentialRecord(cred, session.UserID)
	if err := s.st.InsertRegistration(ctx, session.UserID, record, codeHash); err != nil {
		return nil, fmt.Errorf("authn: 注册落库失败: %w", err)
	}

	return &Registration{
		CredentialID: cred.ID,
		BackedUp:     record.BackedUp,
		RecoveryCode: display,
		UserHandle:   session.UserID,
	}, nil
}

// ConfirmRegistration 确认"已保存恢复码"，把 pending identity 置为已激活。
// 已激活幂等成功；pending 超过 PendingTTL（默认 24 小时）拒绝——归一为
// ErrInvalidCeremony，对外不泄露原因（未确认的 pending
// identity 超 24 小时拒绝）。
func (s *Service) ConfirmRegistration(ctx context.Context, userHandle []byte) error {
	id, err := s.st.GetIdentity(ctx, userHandle)
	if err != nil {
		return fmt.Errorf("%w: identity 查询: %v", ErrInvalidCeremony, err)
	}
	if id.ActivatedAt != nil {
		return nil // 幂等：重复确认不是错误
	}
	if s.now().After(id.CreatedAt.Add(s.pendingTTL)) {
		return fmt.Errorf("%w: pending 已超宽限", ErrInvalidCeremony)
	}
	if err := s.st.ActivateIdentity(ctx, userHandle); err != nil {
		return fmt.Errorf("authn: 激活 identity 失败: %w", err)
	}
	return nil
}

// credentialRecord 把库验证通过的 webauthn.Credential 展平为存储记录。
func credentialRecord(cred *webauthn.Credential, userHandle []byte) *store.Credential {
	transports := make([]string, 0, len(cred.Transport))
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}
	return &store.Credential{
		CredentialID: cred.ID,
		UserHandle:   userHandle,
		PublicKey:    cred.PublicKey,
		BackedUp:     cred.Flags.BackupEligible,
		BackupState:  cred.Flags.BackupState,
		AAGUID:       cred.Authenticator.AAGUID,
		Attachment:   string(cred.Authenticator.Attachment),
		Transports:   transports,
		SignCount:    int64(cred.Authenticator.SignCount),
	}
}
