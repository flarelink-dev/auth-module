-- Flarelink Auth Module — D1 schema for customer apps.
-- Applied once at deploy time via Cloudflare's /query endpoint.
--
-- Session table is intentionally absent: sessions live in KV only.
--
-- `flarelink_config` holds every runtime knob the Worker needs (BETTER_AUTH_SECRET,
-- TRUSTED_ORIGINS, FLARELINK_PROJECT_ID, OAuth client ids/secrets). The Worker
-- reads it at boot with a 60s in-memory cache. Flarelink writes to it via the
-- CF /query API when the dashboard makes changes. Owning the secrets in
-- the customer's own D1 means Flarelink stores zero keys — if Flarelink dies, all
-- config still lives on the customer's account.

CREATE TABLE "user" (
  "id" TEXT PRIMARY KEY NOT NULL,
  "name" TEXT NOT NULL,
  "email" TEXT NOT NULL,
  "email_verified" INTEGER NOT NULL DEFAULT 0,
  "image" TEXT,
  "created_at" INTEGER NOT NULL,
  "updated_at" INTEGER NOT NULL
);

CREATE UNIQUE INDEX "user_email_unique" ON "user" ("email");

CREATE TABLE "account" (
  "id" TEXT PRIMARY KEY NOT NULL,
  "account_id" TEXT NOT NULL,
  "provider_id" TEXT NOT NULL,
  "user_id" TEXT NOT NULL REFERENCES "user"("id") ON DELETE CASCADE,
  "access_token" TEXT,
  "refresh_token" TEXT,
  "id_token" TEXT,
  "access_token_expires_at" INTEGER,
  "refresh_token_expires_at" INTEGER,
  "scope" TEXT,
  "password" TEXT,
  "created_at" INTEGER NOT NULL,
  "updated_at" INTEGER NOT NULL
);

CREATE TABLE "verification" (
  "id" TEXT PRIMARY KEY NOT NULL,
  "identifier" TEXT NOT NULL,
  "value" TEXT NOT NULL,
  "expires_at" INTEGER NOT NULL,
  "created_at" INTEGER,
  "updated_at" INTEGER
);

CREATE TABLE "flarelink_config" (
  "key" TEXT PRIMARY KEY NOT NULL,
  "value" TEXT NOT NULL,
  "updated_at" INTEGER NOT NULL
);
