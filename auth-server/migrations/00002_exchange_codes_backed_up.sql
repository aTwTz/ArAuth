-- +goose Up
-- exchange_codes 记录签发该 code 的那次登录观察到的 BE flag：
-- POST /exchange 的响应白名单含 backed_up，
-- 值必须与登录当下一致，不能事后从 credentials 表反推（一身份可有多凭据）。
ALTER TABLE exchange_codes ADD COLUMN backed_up BOOLEAN NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE exchange_codes DROP COLUMN backed_up;
