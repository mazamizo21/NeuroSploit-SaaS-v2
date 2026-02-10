-- Add subscription token storage for Claude setup-token
ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS subscription_token_encrypted TEXT;

-- If a legacy TOKEN: value was stored in api_key_encrypted, migrate it
UPDATE tenants
SET subscription_token_encrypted = substring(api_key_encrypted from 7),
    api_key_encrypted = NULL
WHERE api_key_encrypted LIKE 'TOKEN:%'
  AND subscription_token_encrypted IS NULL;
