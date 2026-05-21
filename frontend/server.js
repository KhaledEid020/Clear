const express = require('express');
const path = require('path');
const crypto = require('crypto');
const net = require('net');
const { Pool } = require('pg');
const { Client } = require('@opensearch-project/opensearch');
const { Client: SshClient } = require('ssh2');

require('dotenv').config();

const app = express();
const port = Number(process.env.PORT || 3000);

app.use(express.json({ limit: '8mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const mockRuns = new Map();
const realRuns = new Map();
const authSessions = new Map();

const APP_AUTH_TTL_HOURS = Math.max(Number(process.env.APP_AUTH_TTL_HOURS || 12), 1);
const APP_LOGIN_USERNAME = String(process.env.APP_LOGIN_USERNAME || 'admin').trim();
const APP_LOGIN_EMAIL = String(process.env.APP_LOGIN_EMAIL || 'admin@clear.siem').trim().toLowerCase();
const APP_LOGIN_PASSWORD = String(process.env.APP_LOGIN_PASSWORD || 'admin123');
const DB_SCHEMA_RAW = String(process.env.APP_DB_SCHEMA || 'ai').trim();
const DB_SCHEMA = /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(DB_SCHEMA_RAW) ? DB_SCHEMA_RAW : 'ai';
const APP_USERS_TABLE = `${DB_SCHEMA}.app_users`;
const APP_USER_SESSIONS_TABLE = `${DB_SCHEMA}.app_user_sessions`;
const APP_WORKFLOW_RUNS_TABLE = `${DB_SCHEMA}.app_workflow_runs`;
const APP_USER_SETUP_TABLE = `${DB_SCHEMA}.app_user_setup`;

const dbPool = new Pool({
  host: process.env.DB_HOST || '127.0.0.1',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'ai',
  password: process.env.DB_PASS || 'ai',
  database: process.env.DB_DATABASE || 'ai'
});

function cleanupExpiredAuthSessions() {
  const now = Date.now();
  for (const [token, session] of authSessions.entries()) {
    if (!session || Number(session.expiresAt || 0) <= now) {
      authSessions.delete(token);
    }
  }
}

function getBearerToken(req) {
  const authHeader = String(req.headers.authorization || '');
  if (!authHeader.toLowerCase().startsWith('bearer ')) {
    return '';
  }
  return authHeader.slice(7).trim();
}

function getAuthSessionFromRequest(req) {
  cleanupExpiredAuthSessions();
  const token = getBearerToken(req);
  if (!token) {
    return null;
  }
  const session = authSessions.get(token);
  if (!session) {
    return null;
  }
  if (Number(session.expiresAt || 0) <= Date.now()) {
    authSessions.delete(token);
    return null;
  }
  return { token, ...session };
}

async function dbQuery(text, params = []) {
  return dbPool.query(text, params);
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `scrypt$${salt}$${hash}`;
}

function verifyPassword(password, storedHash) {
  const raw = String(storedHash || '');
  const parts = raw.split('$');
  if (parts.length !== 3 || parts[0] !== 'scrypt') {
    return false;
  }
  const salt = parts[1];
  const expectedHex = parts[2];
  const actual = crypto.scryptSync(password, salt, 64).toString('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(actual, 'hex'), Buffer.from(expectedHex, 'hex'));
  } catch (_error) {
    return false;
  }
}

async function ensureAppTables() {
  await dbQuery(`CREATE SCHEMA IF NOT EXISTS ${DB_SCHEMA}`);
  await dbQuery(`
    CREATE TABLE IF NOT EXISTS ${APP_USERS_TABLE} (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      job_title TEXT,
      avatar_data_url TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await dbQuery(`ALTER TABLE ${APP_USERS_TABLE} ADD COLUMN IF NOT EXISTS job_title TEXT`);
  await dbQuery(`ALTER TABLE ${APP_USERS_TABLE} ADD COLUMN IF NOT EXISTS avatar_data_url TEXT`);
  await dbQuery(`
    CREATE TABLE IF NOT EXISTS ${APP_USER_SESSIONS_TABLE} (
      id BIGSERIAL PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES ${APP_USERS_TABLE}(id) ON DELETE CASCADE,
      workflow_id TEXT NOT NULL,
      agno_session_id TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (user_id, workflow_id)
    )
  `);
  await dbQuery(`
    CREATE TABLE IF NOT EXISTS ${APP_WORKFLOW_RUNS_TABLE} (
      id BIGSERIAL PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES ${APP_USERS_TABLE}(id) ON DELETE CASCADE,
      workflow_id TEXT NOT NULL,
      agno_run_id TEXT NOT NULL UNIQUE,
      agno_session_id TEXT NOT NULL,
      rule_id TEXT,
      rule_name TEXT,
      status TEXT NOT NULL DEFAULT 'running',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await dbQuery(`
    CREATE TABLE IF NOT EXISTS ${APP_USER_SETUP_TABLE} (
      user_id TEXT PRIMARY KEY REFERENCES ${APP_USERS_TABLE}(id) ON DELETE CASCADE,
      ai_provider TEXT,
      ai_api_key TEXT,
      ai_model_id TEXT,
      web_provider TEXT,
      web_api_key TEXT,
      siem_provider TEXT,
      siem_indexer_url TEXT,
      siem_indexer_user TEXT,
      siem_indexer_pass TEXT,
      siem_manager_url TEXT,
      siem_ssh_user TEXT,
      siem_ssh_port INTEGER,
      siem_ssh_auth TEXT,
      siem_ssh_auth_mode TEXT,
      onboarding_completed BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await dbQuery(`ALTER TABLE ${APP_USER_SETUP_TABLE} ADD COLUMN IF NOT EXISTS ai_model_id TEXT`);
  await dbQuery(
    `ALTER TABLE ${APP_USER_SETUP_TABLE} ADD COLUMN IF NOT EXISTS siem_ssh_auth_mode TEXT`
  );
  await dbQuery(
    `UPDATE ${APP_USER_SETUP_TABLE}
     SET siem_ssh_auth_mode = 'password'
     WHERE siem_ssh_auth_mode IS NULL OR btrim(siem_ssh_auth_mode) = ''`
  );
  await dbQuery(
    `UPDATE ${APP_USERS_TABLE}
     SET job_title = 'Security Analyst'
     WHERE job_title IS NULL OR btrim(job_title) = ''`
  );
}

async function ensureBootstrapUser() {
  if (!APP_LOGIN_EMAIL || !APP_LOGIN_PASSWORD || !APP_LOGIN_USERNAME) {
    return;
  }
  const existing = await dbQuery(
    `SELECT id FROM ${APP_USERS_TABLE} WHERE lower(email) = lower($1) LIMIT 1`,
    [APP_LOGIN_EMAIL]
  );
  if (existing.rows.length) {
    return;
  }
  await dbQuery(
    `INSERT INTO ${APP_USERS_TABLE} (id, username, email, password_hash, job_title, created_at, updated_at)
     VALUES ($1, $2, $3, $4, $5, NOW(), NOW())`,
    [crypto.randomUUID(), APP_LOGIN_USERNAME, APP_LOGIN_EMAIL, hashPassword(APP_LOGIN_PASSWORD), 'Security Analyst']
  );
}

function requireAuth(req, res, next) {
  const session = getAuthSessionFromRequest(req);
  if (!session) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  req.authUser = session.user;
  return next();
}

async function getOrCreateUserWorkflowSession(userId, workflowId) {
  const result = await dbQuery(
    `INSERT INTO ${APP_USER_SESSIONS_TABLE} (user_id, workflow_id, agno_session_id, created_at, updated_at)
     VALUES ($1, $2, $3, NOW(), NOW())
     ON CONFLICT (user_id, workflow_id)
     DO UPDATE SET updated_at = NOW()
     RETURNING agno_session_id`,
    [userId, workflowId, crypto.randomUUID()]
  );
  return String(result.rows?.[0]?.agno_session_id || '');
}

async function saveWorkflowRun({
  userId,
  workflowId,
  runId,
  sessionId,
  ruleId = '',
  ruleName = '',
  status = 'running'
}) {
  if (!runId || !sessionId || !userId || !workflowId) {
    return;
  }
  await dbQuery(
    `INSERT INTO ${APP_WORKFLOW_RUNS_TABLE}
      (user_id, workflow_id, agno_run_id, agno_session_id, rule_id, rule_name, status, created_at, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
     ON CONFLICT (agno_run_id)
     DO UPDATE SET
       agno_session_id = EXCLUDED.agno_session_id,
       rule_id = EXCLUDED.rule_id,
       rule_name = EXCLUDED.rule_name,
       status = EXCLUDED.status,
       updated_at = NOW()`,
    [userId, workflowId, runId, sessionId, ruleId || null, ruleName || null, status]
  );
}

async function getRunMeta(runId) {
  const result = await dbQuery(
    `SELECT user_id, workflow_id, agno_session_id, status
     FROM ${APP_WORKFLOW_RUNS_TABLE}
     WHERE agno_run_id = $1
     LIMIT 1`,
    [runId]
  );
  return result.rows?.[0] || null;
}

async function getUserById(userId) {
  const result = await dbQuery(
    `SELECT id, username, email, job_title, avatar_data_url
     FROM ${APP_USERS_TABLE}
     WHERE id = $1
     LIMIT 1`,
    [userId]
  );
  return result.rows?.[0] || null;
}

async function updateUserProfile(userId, payload = {}) {
  const nextUsername = String(payload.username || '').trim();
  const nextJobTitle = String(payload.jobTitle || '').trim();
  const nextAvatarDataUrl =
    payload.avatarDataUrl === null || payload.avatarDataUrl === undefined
      ? undefined
      : String(payload.avatarDataUrl || '').trim();

  const fields = [];
  const values = [];
  let index = 1;

  if (nextUsername) {
    fields.push(`username = $${index}`);
    values.push(nextUsername);
    index += 1;
  }
  if (payload.jobTitle !== undefined) {
    fields.push(`job_title = $${index}`);
    values.push(nextJobTitle || null);
    index += 1;
  }
  if (payload.avatarDataUrl !== undefined) {
    fields.push(`avatar_data_url = $${index}`);
    values.push(nextAvatarDataUrl || null);
    index += 1;
  }

  if (!fields.length) {
    return getUserById(userId);
  }

  fields.push('updated_at = NOW()');
  values.push(userId);
  const whereIndex = index;

  const result = await dbQuery(
    `UPDATE ${APP_USERS_TABLE}
     SET ${fields.join(', ')}
     WHERE id = $${whereIndex}
     RETURNING id, username, email, job_title, avatar_data_url`,
    values
  );
  return result.rows?.[0] || null;
}

async function getUserSetup(userId) {
  const result = await dbQuery(
    `SELECT
      user_id,
      ai_provider, ai_api_key, ai_model_id,
      web_provider, web_api_key,
      siem_provider,
      siem_indexer_url, siem_indexer_user, siem_indexer_pass,
      siem_manager_url, siem_ssh_user, siem_ssh_port, siem_ssh_auth, siem_ssh_auth_mode,
      onboarding_completed
     FROM ${APP_USER_SETUP_TABLE}
     WHERE user_id = $1
     LIMIT 1`,
    [userId]
  );
  return result.rows?.[0] || null;
}

function onboardingPathFromSetup(setupRow) {
  const row = setupRow || {};
  const hasAi = Boolean(
    String(row.ai_provider || '').trim() &&
      String(row.ai_api_key || '').trim() &&
      String(row.ai_model_id || '').trim()
  );
  if (!hasAi) {
    return '/aiprovider';
  }
  const hasWeb = Boolean(String(row.web_provider || '').trim() && String(row.web_api_key || '').trim());
  if (!hasWeb) {
    return '/webprovider';
  }
  const hasSiemProvider = Boolean(String(row.siem_provider || '').trim());
  if (!hasSiemProvider) {
    return '/siemprovider';
  }
  const hasSiemConfig = Boolean(
    String(row.siem_indexer_url || '').trim() &&
      String(row.siem_indexer_user || '').trim() &&
      String(row.siem_indexer_pass || '').trim() &&
      String(row.siem_manager_url || '').trim() &&
      String(row.siem_ssh_user || '').trim() &&
      String(row.siem_ssh_auth || '').trim() &&
      Number(row.siem_ssh_port || 0) > 0
  );
  if (!hasSiemConfig) {
    return '/siemconfig';
  }
  return '/';
}

function setupToPayload(setupRow) {
  const row = setupRow || {};
  return {
    aiProvider: row.ai_provider || '',
    aiApiKey: row.ai_api_key || '',
    aiModelId: row.ai_model_id || '',
    webProvider: row.web_provider || '',
    webApiKey: row.web_api_key || '',
    siemProvider: row.siem_provider || '',
    siemConfig: {
      indexerUrl: row.siem_indexer_url || '',
      indexerUser: row.siem_indexer_user || '',
      indexerPass: row.siem_indexer_pass || '',
      managerUrl: row.siem_manager_url || '',
      sshUser: row.siem_ssh_user || '',
      sshPort: Number(row.siem_ssh_port || 22),
      sshAuth: row.siem_ssh_auth || '',
      sshAuthMode: row.siem_ssh_auth_mode || 'password'
    }
  };
}

function normalizeSshAuthMode(value) {
  return String(value || '').trim().toLowerCase() === 'key_file' ? 'key_file' : 'password';
}

function normalizeSshPrivateKeyText(value) {
  let key = String(value || '');
  if (!key) {
    return '';
  }
  key = key.replace(/\r\n/g, '\n').replace(/\r/g, '\n').trim();
  if (!key.includes('\n') && key.includes('\\n')) {
    key = key.replace(/\\n/g, '\n');
  }
  if (!key.includes('\n')) {
    const inlineMatch = key.match(
      /^(-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----)(.+)(-----END [A-Z0-9 ]*PRIVATE KEY-----)$/
    );
    if (inlineMatch) {
      const header = inlineMatch[1];
      const body = inlineMatch[2].replace(/\s+/g, '');
      const footer = inlineMatch[3];
      const wrappedBody = body.match(/.{1,70}/g)?.join('\n') || '';
      key = `${header}\n${wrappedBody}\n${footer}`;
    }
  }
  return key;
}

function isLikelyPemPrivateKey(value) {
  const key = normalizeSshPrivateKeyText(value);
  if (!key) {
    return false;
  }
  return /^-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----\n[\s\S]+\n-----END [A-Z0-9 ]*PRIVATE KEY-----$/m.test(key);
}

async function upsertUserSetup(userId, updates = {}) {
  const payload = {
    ai_provider: updates.ai_provider,
    ai_api_key: updates.ai_api_key,
    ai_model_id: updates.ai_model_id,
    web_provider: updates.web_provider,
    web_api_key: updates.web_api_key,
    siem_provider: updates.siem_provider,
    siem_indexer_url: updates.siem_indexer_url,
    siem_indexer_user: updates.siem_indexer_user,
    siem_indexer_pass: updates.siem_indexer_pass,
    siem_manager_url: updates.siem_manager_url,
    siem_ssh_user: updates.siem_ssh_user,
    siem_ssh_port: updates.siem_ssh_port,
    siem_ssh_auth: updates.siem_ssh_auth,
    siem_ssh_auth_mode: updates.siem_ssh_auth_mode
  };

  const fields = Object.keys(payload).filter((key) => payload[key] !== undefined);
  if (!fields.length) {
    return getUserSetup(userId);
  }

  const values = [userId];
  const insertColumns = ['user_id'];
  const insertPlaceholders = ['$1'];
  const setExpressions = [];

  fields.forEach((column, idx) => {
    const bindIndex = idx + 2;
    insertColumns.push(column);
    insertPlaceholders.push(`$${bindIndex}`);
    setExpressions.push(`${column} = EXCLUDED.${column}`);
    values.push(payload[column]);
  });

  await dbQuery(
    `INSERT INTO ${APP_USER_SETUP_TABLE} (${insertColumns.join(', ')}, created_at, updated_at)
     VALUES (${insertPlaceholders.join(', ')}, NOW(), NOW())
     ON CONFLICT (user_id)
     DO UPDATE SET
       ${setExpressions.join(', ')},
       updated_at = NOW()`,
    values
  );

  const fresh = await getUserSetup(userId);
  const nextPath = onboardingPathFromSetup(fresh);
  await dbQuery(
    `UPDATE ${APP_USER_SETUP_TABLE}
     SET onboarding_completed = $2, updated_at = NOW()
     WHERE user_id = $1`,
    [userId, nextPath === '/']
  );
  return getUserSetup(userId);
}

async function getOnboardingStatus(userId) {
  const setup = await getUserSetup(userId);
  const nextPath = onboardingPathFromSetup(setup);
  return {
    completed: nextPath === '/',
    nextPath,
    setup: setupToPayload(setup)
  };
}

function normalizeModelRows(rows = []) {
  const unique = new Map();
  for (const row of rows) {
    const id = String(row?.id || '').trim();
    if (!id) {
      continue;
    }
    const name = String(row?.name || row?.display_name || id).trim() || id;
    unique.set(id, { id, name });
  }
  return Array.from(unique.values()).sort((a, b) => a.name.localeCompare(b.name));
}

const DISALLOWED_MODEL_PARTS = [
  'mini',
  'nano',
  'haiku',
  'embedding',
  'embed',
  'image',
  'audio',
  'realtime',
  'search',
  'transcribe',
  'tts',
  'whisper',
  'moderation',
  'dall-e'
];

function modelText(model) {
  return `${model?.id || ''} ${model?.name || ''}`.toLowerCase();
}

function hasDisallowedModelPart(model) {
  const text = modelText(model);
  return DISALLOWED_MODEL_PARTS.some((part) => text.includes(part));
}

function openAIModelName(model) {
  const id = String(model?.id || '').toLowerCase();
  return id.includes('/') ? id.split('/').pop() : id;
}

function isAllowedOpenAIModel(model) {
  const name = openAIModelName(model);
  if (!name || hasDisallowedModelPart(model)) {
    return false;
  }
  return (
    name === 'gpt-4' ||
    name.startsWith('gpt-4o') ||
    name.startsWith('gpt-4.1') ||
    name.startsWith('gpt-4-turbo') ||
    name.startsWith('gpt-5')
  );
}

function isAllowedAnthropicModel(model) {
  const text = modelText(model);
  return text.includes('claude') && (text.includes('sonnet') || text.includes('opus')) && !hasDisallowedModelPart(model);
}

function isAllowedOpenRouterModel(model) {
  const id = String(model?.id || '').toLowerCase();
  if (id === 'qwen/qwen3.5-397b-a17b' || id === 'deepseek/deepseek-v4-pro') {
    return true;
  }
  if (id.includes('openai/gpt-')) {
    return isAllowedOpenAIModel(model);
  }
  if (id.includes('anthropic/claude')) {
    return isAllowedAnthropicModel(model);
  }
  return false;
}

function filterModelsForProvider(aiProvider, models = []) {
  if (aiProvider === 'openai') {
    return models.filter(isAllowedOpenAIModel);
  }
  if (aiProvider === 'anthropic') {
    return models.filter(isAllowedAnthropicModel);
  }
  if (aiProvider === 'openrouter') {
    return models.filter(isAllowedOpenRouterModel);
  }
  return [];
}

async function fetchJsonWithTimeout(url, options = {}, timeoutMs = 12000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    return response;
  } finally {
    clearTimeout(timer);
  }
}

async function listOpenAIModels(apiKey) {
  const response = await fetchJsonWithTimeout('https://api.openai.com/v1/models', {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${apiKey}`
    }
  });
  if (!response.ok) {
    const raw = await response.text();
    throw new Error(`OpenAI models request failed (${response.status}): ${clipText(raw, 400)}`);
  }
  const payload = await response.json().catch(() => ({}));
  return normalizeModelRows(Array.isArray(payload?.data) ? payload.data : []);
}

async function listAnthropicModels(apiKey) {
  const response = await fetchJsonWithTimeout('https://api.anthropic.com/v1/models', {
    method: 'GET',
    headers: {
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01'
    }
  });
  if (!response.ok) {
    const raw = await response.text();
    throw new Error(`Anthropic models request failed (${response.status}): ${clipText(raw, 400)}`);
  }
  const payload = await response.json().catch(() => ({}));
  return normalizeModelRows(Array.isArray(payload?.data) ? payload.data : []);
}

async function listOpenRouterModels(apiKey) {
  const response = await fetchJsonWithTimeout('https://openrouter.ai/api/v1/models', {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${apiKey}`
    }
  });
  if (!response.ok) {
    const raw = await response.text();
    throw new Error(`OpenRouter models request failed (${response.status}): ${clipText(raw, 400)}`);
  }
  const payload = await response.json().catch(() => ({}));
  return normalizeModelRows(Array.isArray(payload?.data) ? payload.data : []);
}

async function listModelsForProvider(aiProvider, aiApiKey) {
  let models = [];
  if (aiProvider === 'openai') {
    models = await listOpenAIModels(aiApiKey);
  } else if (aiProvider === 'anthropic') {
    models = await listAnthropicModels(aiApiKey);
  } else if (aiProvider === 'openrouter') {
    models = await listOpenRouterModels(aiApiKey);
  } else {
    throw new Error('Unsupported AI provider');
  }
  return filterModelsForProvider(aiProvider, models);
}

function normalizeIndexerNodeUrl(rawUrl) {
  const input = String(rawUrl || '').trim();
  if (!input) {
    return '';
  }
  if (/^https?:\/\//i.test(input)) {
    return input;
  }
  return `https://${input}`;
}

function parseManagerTarget(rawManagerUrl, rawPort) {
  const managerInput = String(rawManagerUrl || '').trim();
  let host = '';
  let port = Math.round(Number(rawPort || 22));

  if (managerInput) {
    const candidate = /^[a-z][a-z0-9+.-]*:\/\//i.test(managerInput)
      ? managerInput
      : `ssh://${managerInput}`;
    try {
      const parsed = new URL(candidate);
      host = String(parsed.hostname || '').trim();
      if (parsed.port) {
        port = Math.round(Number(parsed.port));
      }
    } catch (_error) {
      host = managerInput;
    }
  }

  if (host.startsWith('[') && host.endsWith(']')) {
    host = host.slice(1, -1).trim();
  }
  if (host.includes('/') && !host.includes(':')) {
    host = host.split('/')[0].trim();
  }
  if (!host && managerInput) {
    host = managerInput.split(':')[0].trim();
  }
  if (!Number.isFinite(port) || port <= 0) {
    port = 22;
  }
  return { host, port };
}

function testTcpConnection(host, port, timeoutMs = 4000) {
  return new Promise((resolve, reject) => {
    const socket = new net.Socket();
    let done = false;
    const finish = (error) => {
      if (done) {
        return;
      }
      done = true;
      socket.destroy();
      if (error) {
        reject(error);
        return;
      }
      resolve(true);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish());
    socket.once('timeout', () => finish(new Error('Connection timed out')));
    socket.once('error', (error) => finish(error));
    socket.connect(port, host);
  });
}

function testSshConnection({ host, port, username, authMode, authValue }, timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    const client = new SshClient();
    let done = false;
    let connected = false;
    const timer = setTimeout(() => {
      finish(new Error('SSH connection timed out'));
    }, timeoutMs);

    const finish = (error) => {
      if (done) {
        return;
      }
      done = true;
      clearTimeout(timer);
      client.end();
      if (typeof client.destroy === 'function') {
        client.destroy();
      }
      if (error) {
        reject(error);
        return;
      }
      resolve(true);
    };

    const connectOptions = {
      host,
      port,
      username,
      readyTimeout: timeoutMs,
      tryKeyboard: false
    };

    if (authMode === 'key_file') {
      connectOptions.privateKey = authValue;
    } else {
      connectOptions.password = authValue;
    }

    client
      .once('ready', () => {
        connected = true;
        client.end();
      })
      .once('close', () => finish(connected ? null : new Error('SSH connection closed before authentication completed')))
      .once('error', (error) => finish(error))
      .connect(connectOptions);
  });
}

const workflowSteps = [
  { name: 'research_threat_hunting', title: 'Rule Hunting Agent', kind: 'tool_call' },
  { name: 'research_web_intel', title: 'Web Searcher Agent', kind: 'tool_result' },
  { name: 'final_report', title: 'Retrieval Agent', kind: 'synthesis' },
  { name: 'apply_detection_changes', title: 'Detection Engineer agent', kind: 'tool_call' }
];

const workflowStepIndex = new Map(workflowSteps.map((step, index) => [step.name, index]));

const fallbackRules = [
  {
    id: 'RUL-4921',
    name: 'Transaction Validation Threshold',
    status: 'Active',
    severity: 'info',
    description:
      'Determines the risk score required to flag a transaction for manual review. Currently set to baseline heuristics with a 0.85 confidence threshold.'
  },
  {
    id: 'RUL-8832',
    name: 'User Authentication Timeout',
    status: 'Active',
    severity: 'normal',
    description: 'Controls inactivity timeout for privileged user sessions.'
  },
  {
    id: 'RUL-1045',
    name: 'Data Sync Conflict Resolution',
    status: 'Warning',
    severity: 'warning',
    description: 'Handles merge strategy when conflicting records arrive from multiple sources.'
  },
  {
    id: 'RUL-3390',
    name: 'API Rate Limiting Tier 2',
    status: 'Active',
    severity: 'normal',
    description: 'Applies second-tier throttling for burst traffic on protected endpoints.'
  }
];

async function getOpenSearchClientForUser(userId) {
  const setup = await getUserSetup(String(userId || '').trim());
  const hostsRaw = String(setup?.siem_indexer_url || '').trim();
  const username = String(setup?.siem_indexer_user || '').trim();
  const password = String(setup?.siem_indexer_pass || '').trim();
  const verifyCertsRaw = String(
    process.env.VERIFY_CERTS || process.env.WAZUH_OPENSEARCH_SSL_VERIFY || 'false'
  )
    .trim()
    .toLowerCase();

  if (!hostsRaw || !username || !password) {
    return null;
  }

  const hosts = hostsRaw
    .split(',')
    .map((item) => normalizeIndexerNodeUrl(item))
    .filter(Boolean);
  const rejectUnauthorized = verifyCertsRaw === 'true' || verifyCertsRaw === '1';

  return new Client({
    node: hosts[0],
    auth: { username, password },
    ssl: { rejectUnauthorized }
  });
}

function clipText(value, maxLen = 4000) {
  const text = String(value ?? '');
  return text.length > maxLen ? `${text.slice(0, maxLen)}...` : text;
}

function getBackendConfig() {
  return {
    baseUrl: String(process.env.AGENT_BACKEND_URL || '').replace(/\/$/, ''),
    workflowId: process.env.AGENT_WORKFLOW_ID || 'wazuh-fine-tuning-pipeline',
    apiKey: process.env.AGENT_BACKEND_API_KEY || '',
    bearerToken: process.env.AGENT_BACKEND_BEARER_TOKEN || ''
  };
}

function backendHeaders(contentType = '') {
  const { apiKey, bearerToken } = getBackendConfig();
  const headers = {};

  if (contentType) {
    headers['Content-Type'] = contentType;
  }
  if (apiKey) {
    headers['x-api-key'] = apiKey;
  }
  if (bearerToken) {
    headers.Authorization = `Bearer ${bearerToken}`;
  }

  return headers;
}

function normalizeRuleId(ruleId) {
  return String(ruleId || '').replace(/^RUL-/i, '');
}

function buildWorkflowMessage(ruleId, ruleName) {
  const numericRuleId = normalizeRuleId(ruleId);
  return [
    `Rule ID: ${numericRuleId}`,
    `Rule Name: ${ruleName}`,
    'Generate fine-tuning report and wait for my apply confirmation.'
  ].join('\n');
}

function writeNdjson(res, payload) {
  res.write(`${JSON.stringify(payload)}\n`);
}

function maybeJsonParse(value) {
  if (!value) {
    return null;
  }
  try {
    return JSON.parse(value);
  } catch (_error) {
    return null;
  }
}

function getIdsFromBackendPayload(payload) {
  const workflowRunId = payload?.workflow_run_id || payload?.workflowRunId || '';
  const directRunId = payload?.run_id || payload?.runId || payload?.id || '';
  return {
    runId: workflowRunId || directRunId,
    sessionId: payload?.session_id || payload?.sessionId || ''
  };
}

async function* iterateBackendStreamPayloads(stream) {
  if (!stream || typeof stream.getReader !== 'function') {
    return;
  }

  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let sseDataLines = [];

  const flushSseData = () => {
    if (!sseDataLines.length) {
      return null;
    }
    const payload = sseDataLines.join('\n').trim();
    sseDataLines = [];
    if (!payload || payload === '[DONE]') {
      return null;
    }
    return maybeJsonParse(payload);
  };

  while (true) {
    const { value, done } = await reader.read();
    buffer += decoder.decode(value || new Uint8Array(), { stream: !done });

    let lineBreakIndex = buffer.indexOf('\n');
    while (lineBreakIndex >= 0) {
      const rawLine = buffer.slice(0, lineBreakIndex);
      buffer = buffer.slice(lineBreakIndex + 1);
      const line = rawLine.replace(/\r$/, '');
      const trimmed = line.trim();

      if (line.startsWith('data:')) {
        sseDataLines.push(line.slice(5).trim());
      } else if (
        trimmed === '' ||
        line.startsWith('event:') ||
        line.startsWith('id:') ||
        line.startsWith('retry:') ||
        line.startsWith(':')
      ) {
        const ssePayload = flushSseData();
        if (ssePayload) {
          yield ssePayload;
        }
      } else if (sseDataLines.length) {
        sseDataLines.push(trimmed);
      } else {
        const jsonPayload = maybeJsonParse(trimmed);
        if (jsonPayload) {
          yield jsonPayload;
        }
      }

      lineBreakIndex = buffer.indexOf('\n');
    }

    if (done) {
      break;
    }
  }

  if (buffer.trim()) {
    const trailing = maybeJsonParse(buffer.trim());
    if (trailing) {
      yield trailing;
    }
  }

  const finalSsePayload = flushSseData();
  if (finalSsePayload) {
    yield finalSsePayload;
  }
}

async function drainBackendStream(stream, label = 'backend stream') {
  try {
    for await (const _payload of iterateBackendStreamPayloads(stream)) {
      // Intentionally drain without retaining payloads; AgentOS already buffers
      // resumable events, and keeping them here can balloon memory/log volume.
    }
  } catch (error) {
    console.warn(`Failed to drain ${label}:`, error.message);
  }
}

function normalizeBackendStatus(status) {
  const normalized = String(status || '').toUpperCase();
  if (normalized === 'COMPLETED') {
    return 'completed';
  }
  if (['ERROR', 'FAILED', 'CANCELLED', 'STOPPED'].includes(normalized)) {
    return 'error';
  }
  if (normalized === 'PAUSED') {
    return 'paused';
  }
  return 'running';
}

function summarizeStepContent(content, fallback = 'Step completed.') {
  const text = clipText(content, 1200).replace(/\r/g, '').trim();
  if (!text) {
    return fallback;
  }

  const line = text
    .split('\n')
    .map((part) => part.trim())
    .find((part) => part.length > 0 && !part.startsWith('#') && !part.startsWith('```'));
  return clipText(line || text, 180);
}

function compactPayload(value, maxLen = 1600) {
  if (value === undefined || value === null) {
    return null;
  }
  if (typeof value === 'string') {
    return clipText(value, maxLen);
  }
  try {
    return clipText(JSON.stringify(value, null, 2), maxLen);
  } catch (_error) {
    return clipText(String(value), maxLen);
  }
}

function mapToolsFromExecutorRun(executorRun) {
  const tools = Array.isArray(executorRun?.tools) ? executorRun.tools : [];
  return tools.map((tool, index) => {
    const metrics = tool?.metrics || {};
    const requiresConfirmation = Boolean(tool?.requires_confirmation);
    const isUnresolvedConfirmation =
      requiresConfirmation && (tool?.confirmed === null || tool?.confirmed === undefined);
    const status = tool?.tool_call_error
      ? 'error'
      : tool?.confirmed === false
      ? 'rejected'
      : isUnresolvedConfirmation
      ? 'running'
      : 'done';
    return {
      id: tool?.tool_call_id || `${executorRun?.run_id || 'executor'}-tool-${index + 1}`,
      name: tool?.tool_name || executorRun?.agent_name || 'tool_call',
      input: tool?.tool_args || null,
      result: tool?.result ?? null,
      status,
      latencyMs:
        metrics?.duration && Number.isFinite(Number(metrics.duration))
          ? Math.round(Number(metrics.duration) * 1000)
          : null
    };
  });
}

function mergeToolCalls(existingToolCalls, nextToolCalls) {
  const merged = Array.isArray(existingToolCalls) ? [...existingToolCalls] : [];
  const indexById = new Map();
  merged.forEach((item, index) => {
    if (item?.id) {
      indexById.set(item.id, index);
    }
  });
  (Array.isArray(nextToolCalls) ? nextToolCalls : []).forEach((toolCall) => {
    if (!toolCall) {
      return;
    }
    if (!toolCall.id) {
      merged.push(toolCall);
      return;
    }

    if (indexById.has(toolCall.id)) {
      const existingIndex = indexById.get(toolCall.id);
      const prev = merged[existingIndex] || {};
      merged[existingIndex] = {
        ...prev,
        ...toolCall,
        input: toolCall.input ?? prev.input ?? null,
        result: toolCall.result ?? prev.result ?? null
      };
      return;
    }

    indexById.set(toolCall.id, merged.length);
    merged.push(toolCall);
  });
  return merged;
}

function normalizeWorkflowEventName(value) {
  return String(value || '').replace(/[^A-Za-z0-9]/g, '').toLowerCase();
}

function workflowEventNameMatches(eventName, baseName) {
  const normalizedEventName = normalizeWorkflowEventName(eventName);
  const normalizedBaseName = normalizeWorkflowEventName(baseName);
  return (
    normalizedEventName === normalizedBaseName ||
    normalizedEventName === `${normalizedBaseName}event`
  );
}

function extractToolArgsFromAny(tool) {
  if (!tool || typeof tool !== 'object') {
    return null;
  }
  return tool.tool_args || tool.toolArgs || tool.arguments || tool.args || null;
}

function getRunRequirements(run = {}) {
  const candidates = [run?.step_requirements, run?.requirements, run?.active_requirements];
  for (const list of candidates) {
    if (Array.isArray(list) && list.length) {
      return list;
    }
  }
  return [];
}

function isPendingConfirmedValue(value) {
  if (value === null || value === undefined) {
    return true;
  }
  const normalized = String(value).trim().toLowerCase();
  return normalized === '' || normalized === 'pending';
}

function resolveStepNameFromWorkflowEvent(event, stepIdToName, lastKnownStepName = '') {
  const directName =
    event?.step_name ||
    event?.stepName ||
    event?.step_output?.step_name ||
    event?.step_response?.step_name ||
    '';
  if (directName && workflowStepIndex.has(directName)) {
    return directName;
  }

  const stepId = event?.step_id || event?.stepId || '';
  if (stepId && stepIdToName?.has(stepId)) {
    return stepIdToName.get(stepId);
  }

  if (lastKnownStepName && workflowStepIndex.has(lastKnownStepName)) {
    return lastKnownStepName;
  }

  return '';
}

function mapToolsFromWorkflowEvents(events = [], stepIdToName = new Map()) {
  const toolTracesByStepName = new Map();
  const stepProgressByName = new Map();
  let lastStepName = '';

  (Array.isArray(events) ? events : []).forEach((event, index) => {
    if (!event || typeof event !== 'object') {
      return;
    }

    const eventName = normalizeWorkflowEventName(event.event);
    const stepName = resolveStepNameFromWorkflowEvent(event, stepIdToName, lastStepName);
    if (stepName) {
      lastStepName = stepName;
    }
    if (!stepName || !workflowStepIndex.has(stepName)) {
      return;
    }

    if (workflowEventNameMatches(eventName, 'stepstarted')) {
      stepProgressByName.set(stepName, 'running');
    } else if (workflowEventNameMatches(eventName, 'stepcompleted') || workflowEventNameMatches(eventName, 'stepoutput')) {
      stepProgressByName.set(stepName, 'done');
    }

    if (!workflowEventNameMatches(eventName, 'toolcallstarted') && !workflowEventNameMatches(eventName, 'toolcallcompleted')) {
      return;
    }

    const tool = event?.tool || {};
    const toolId =
      tool?.tool_call_id ||
      tool?.approval_id ||
      event?.tool_call_id ||
      event?.approval_id ||
      `${stepName}-tool-${index + 1}`;
    const toolName = tool?.tool_name || tool?.name || 'tool_call';
    const toolInput = extractToolArgsFromAny(tool);
    const toolResult = tool?.result ?? event?.result ?? event?.content ?? null;
    const toolStatus =
      workflowEventNameMatches(eventName, 'toolcallstarted')
        ? 'running'
        : tool?.tool_call_error
        ? 'error'
        : 'done';
    const toolLatencyMs =
      tool?.metrics?.duration && Number.isFinite(Number(tool.metrics.duration))
        ? Math.round(Number(tool.metrics.duration) * 1000)
        : null;

    const previousToolCalls = toolTracesByStepName.get(stepName) || [];
    toolTracesByStepName.set(
      stepName,
      mergeToolCalls(previousToolCalls, [
        {
          id: toolId,
          name: toolName,
          input: toolInput,
          result: toolResult,
          status: toolStatus,
          latencyMs: toolLatencyMs
        }
      ])
    );
  });

  return { toolTracesByStepName, stepProgressByName };
}

function extractPendingToolCall(run) {
  const runStatus = normalizeBackendStatus(run?.status);
  if (runStatus === 'completed' || runStatus === 'error') {
    return null;
  }

  // 1. Check step_executor_runs (for agent= steps)
  const executorRuns = Array.isArray(run?.step_executor_runs) ? run.step_executor_runs : [];

  for (let runIndex = executorRuns.length - 1; runIndex >= 0; runIndex -= 1) {
    const executorRun = executorRuns[runIndex];
    const tools = Array.isArray(executorRun?.tools) ? executorRun.tools : [];

    for (let toolIndex = tools.length - 1; toolIndex >= 0; toolIndex -= 1) {
      const tool = tools[toolIndex];
      const toolName = String(tool?.tool_name || tool?.name || tool?.toolName || '').trim();
      const confirmed = tool?.confirmed;
      const isPendingConfirmedState = isPendingConfirmedValue(confirmed);
      const requiresConfirmation = tool?.requires_confirmation;
      const shouldTreatAsPending =
        Boolean(toolName) &&
        isPendingConfirmedState &&
        (requiresConfirmation === undefined || Boolean(requiresConfirmation));
      if (shouldTreatAsPending) {
        return {
          toolName: toolName || 'tool_call',
          toolArgs: extractToolArgsFromAny(tool),
          approvalId: tool.approval_id || null,
          toolCallId: tool.tool_call_id || null,
          agentName: executorRun?.agent_name || '',
          stepName: executorRun?.step_name || ''
        };
      }
    }
  }

  // 2. Check step_requirements executor_requirements (for executor= steps with nested agents)
  const requirements = getRunRequirements(run);
  for (let i = requirements.length - 1; i >= 0; i -= 1) {
    const requirement = requirements[i];
    if (!requirement || !isPendingConfirmedValue(requirement.confirmed)) {
      continue;
    }

    const directToolExecution = requirement?.tool_execution && typeof requirement.tool_execution === 'object'
      ? requirement.tool_execution
      : null;
    if (directToolExecution) {
      const directToolName = String(
        directToolExecution.tool_name || directToolExecution.name || directToolExecution.toolName || ''
      ).trim();
      const directRequiresConfirmation = directToolExecution?.requires_confirmation;
      const directShouldTreatAsPending =
        Boolean(directToolName) &&
        isPendingConfirmedValue(directToolExecution?.confirmed) &&
        (directRequiresConfirmation === undefined || Boolean(directRequiresConfirmation));
      if (directShouldTreatAsPending) {
        return {
          toolName: directToolName || 'tool_call',
          toolArgs: extractToolArgsFromAny(directToolExecution),
          approvalId: directToolExecution.approval_id || null,
          toolCallId: directToolExecution.tool_call_id || null,
          agentName: '',
          stepName: requirement?.step_name || ''
        };
      }
    }

    const executorReqs = Array.isArray(requirement?.executor_requirements)
      ? requirement.executor_requirements
      : [];
    for (let j = executorReqs.length - 1; j >= 0; j -= 1) {
      const te = executorReqs[j]?.tool_execution;
      const toolName = String(te?.tool_name || te?.name || te?.toolName || '').trim();
      const confirmed = te?.confirmed;
      const isPendingConfirmedState = isPendingConfirmedValue(confirmed);
      const requiresConfirmation = te?.requires_confirmation;
      const shouldTreatAsPending =
        Boolean(toolName) &&
        isPendingConfirmedState &&
        (requiresConfirmation === undefined || Boolean(requiresConfirmation));
      if (shouldTreatAsPending) {
        return {
          toolName: toolName || 'tool_call',
          toolArgs: extractToolArgsFromAny(te),
          approvalId: te.approval_id || null,
          toolCallId: te.tool_call_id || null,
          agentName: '',
          stepName: requirement?.step_name || ''
        };
      }
    }
  }

  return null;
}

function getUnresolvedRequirement(run) {
  const runStatus = normalizeBackendStatus(run?.status);
  if (runStatus === 'completed' || runStatus === 'error') {
    return null;
  }

  const requirements = getRunRequirements(run);
  for (let i = requirements.length - 1; i >= 0; i -= 1) {
    if (requirements[i] && isPendingConfirmedValue(requirements[i].confirmed)) {
      return requirements[i];
    }
  }
  return null;
}

function buildGate(run, pendingTool) {
  const unresolved = getUnresolvedRequirement(run);
  if (!unresolved) {
    return null;
  }

  const requiresUserInput = Boolean(unresolved?.requires_user_input);
  const pausedStepName = run?.paused_step_name || unresolved?.step_name || '';
  const defaultMessage =
    requiresUserInput
      ? unresolved?.user_input_message || 'Input is required to continue.'
      : pausedStepName === 'apply_detection_changes'
      ? 'Do you approve applying detection changes in Wazuh now?'
      : 'Approval is required to continue.';
  const confirmationMessage =
    requiresUserInput
      ? unresolved?.user_input_message || unresolved?.confirmation_message || defaultMessage
      : unresolved?.confirmation_message ||
        unresolved?.output_review_message ||
        (pendingTool?.toolName ? `Approve tool execution: ${pendingTool.toolName}` : '') ||
        defaultMessage;

  return {
    pending: true,
    mode: pendingTool?.toolName ? 'tool_confirmation' : requiresUserInput ? 'step_user_input' : 'step_confirmation',
    message: confirmationMessage,
    stepName: unresolved?.step_name || pausedStepName || null,
    requirementStepId: unresolved?.step_id || null,
    commandPreview: pendingTool?.toolArgs?.command || '',
    toolName: pendingTool?.toolName || '',
    toolArgs: pendingTool?.toolArgs || null,
    approvalId: pendingTool?.approvalId || null,
    toolCallId: pendingTool?.toolCallId || null,
    userInputMessage: unresolved?.user_input_message || '',
    userInputSchema: Array.isArray(unresolved?.user_input_schema) ? unresolved.user_input_schema : []
  };
}

function mapRunToFrontendPayload(run, metadata = {}, options = {}) {
  const includeExecutorRunsRaw = options?.includeExecutorRunsRaw === true;
  const status = normalizeBackendStatus(run?.status);
  const pausedStepName = run?.paused_step_name || '';
  const stepResults = Array.isArray(run?.step_results) ? run.step_results : [];
  const workflowEvents = Array.isArray(run?.events) ? run.events : [];
  const stepRequirements = getRunRequirements(run);
  const resultByName = new Map(stepResults.map((result) => [result?.step_name, result]));
  const stepIdToName = new Map(
    stepResults
      .filter((result) => result?.step_id && result?.step_name)
      .map((result) => [result.step_id, result.step_name])
  );
  stepRequirements.forEach((requirement) => {
    if (!requirement?.step_id || !requirement?.step_name) {
      return;
    }
    if (!stepIdToName.has(requirement.step_id)) {
      stepIdToName.set(requirement.step_id, requirement.step_name);
    }
  });
  const executorRuns = Array.isArray(run?.step_executor_runs) ? run.step_executor_runs : [];
  const toolTracesByStepName = new Map();
  const isTerminalRun = status === 'completed' || status === 'error';
  const pendingTool = isTerminalRun ? null : extractPendingToolCall(run);
  let gate = isTerminalRun ? null : buildGate(run, pendingTool);
  if (options?.ignoreStaleUserInputGate && gate?.mode === 'step_user_input') {
    gate = null;
  }
  const workflowGate = gate && gate?.mode !== 'tool_confirmation' ? gate : null;
  const commandGate = gate?.mode === 'tool_confirmation' ? gate : null;

  const executorRunByStepName = new Map();

  executorRuns.forEach((executorRun) => {
    const stepName =
      stepIdToName.get(executorRun?.workflow_step_id) ||
      executorRun?.step_name ||
      executorRun?.metadata?.step_name ||
      '';
    if (!stepName) {
      return;
    }
    
    executorRunByStepName.set(stepName, executorRun);

    const toolCalls = mapToolsFromExecutorRun(executorRun);
    if (!toolCalls.length) {
      return;
    }
    const previousToolCalls = toolTracesByStepName.get(stepName) || [];
    toolTracesByStepName.set(stepName, mergeToolCalls(previousToolCalls, toolCalls));
  });

  // Supplement tool traces and running-step hints from stored workflow events.
  // This keeps polling UI informative even when step_executor_runs is sparse.
  const { toolTracesByStepName: eventToolTraces, stepProgressByName } = mapToolsFromWorkflowEvents(
    workflowEvents,
    stepIdToName
  );
  eventToolTraces.forEach((eventTools, stepName) => {
    const previousToolCalls = toolTracesByStepName.get(stepName) || [];
    toolTracesByStepName.set(stepName, mergeToolCalls(previousToolCalls, eventTools));
  });

  let currentStepIndex = 0;
  workflowSteps.forEach((step, index) => {
    if (resultByName.has(step.name)) {
      currentStepIndex = Math.max(currentStepIndex, index + 1); // next step is running
    } else if (stepProgressByName.get(step.name) === 'done') {
      currentStepIndex = Math.max(currentStepIndex, index + 1);
    } else if (stepProgressByName.get(step.name) === 'running') {
      currentStepIndex = Math.max(currentStepIndex, index);
    } else if (executorRunByStepName.has(step.name)) {
      currentStepIndex = Math.max(currentStepIndex, index); // this step is running
    }
  });

  if (pausedStepName && workflowStepIndex.has(pausedStepName)) {
    currentStepIndex = workflowStepIndex.get(pausedStepName);
  }

  const activity = workflowSteps
    .map((step, index) => {
      const result = resultByName.get(step.name);
      const isDone = Boolean(result) || (status === 'completed') || (index < currentStepIndex && status !== 'error');
      const toolTraces = toolTracesByStepName.get(step.name) || [];
      const latestToolTrace = toolTraces[toolTraces.length - 1] || null;
      const metrics = result?.metrics || {};

      if (isDone) {
        return {
          id: step.name,
          kind: step.kind,
          title: step.title,
          detail:
            step.name === 'final_report'
              ? summarizeStepContent(result?.content || '', 'Final report generated.')
              : `${step.title} completed.`,
          status: 'done',
          toolName: latestToolTrace?.name || result?.executor_name || result?.executor_type || '',
          toolCalls: toolTraces.map((toolCall) => ({
            id: toolCall.id,
            name: toolCall.name,
            input: compactPayload(toolCall.input),
            result:
              compactPayload(toolCall.result, 2000),
            status: toolCall.status,
            latencyMs: toolCall.latencyMs
          })),
          input: compactPayload(latestToolTrace?.input || null),
          result: compactPayload(latestToolTrace?.result ?? result?.content ?? '', 2000),
          latencyMs:
            latestToolTrace?.latencyMs ||
            (metrics?.duration && Number.isFinite(Number(metrics.duration))
              ? Math.round(Number(metrics.duration) * 1000)
              : null),
          tokensIn:
            metrics?.input_tokens && Number.isFinite(Number(metrics.input_tokens))
              ? Number(metrics.input_tokens)
              : null,
          tokensOut:
            metrics?.output_tokens && Number.isFinite(Number(metrics.output_tokens))
              ? Number(metrics.output_tokens)
              : null
        };
      }

      const shouldRun =
        status !== 'completed' &&
        status !== 'error' &&
        (step.name === pausedStepName || (!pausedStepName && index === currentStepIndex));

      const isApplyStep = step.name === 'apply_detection_changes';
      const waitingText = isApplyStep
        ? 'Waiting for confirmation to continue.'
        : `${step.title} is waiting for execution.`;
      const runningText = isApplyStep
        ? commandGate
          ? 'Pending command approval in Detection Rule Apply.'
          : workflowGate
          ? 'Pending workflow approval in Final Report window.'
          : 'Detection Rule Apply is executing.'
        : `${step.title} is executing.`;

      let activeToolName = '';
      let activeToolArgs = null;
      let activeToolCalls = toolTraces.map((toolCall) => ({
        id: toolCall.id,
        name: toolCall.name,
        input: compactPayload(toolCall.input),
        result:
          compactPayload(toolCall.result, 2000),
        status: toolCall.status,
        latencyMs: toolCall.latencyMs
      }));

      if (isApplyStep && pendingTool?.toolName) {
        activeToolName = pendingTool.toolName;
        activeToolArgs = pendingTool.toolArgs;
        if (!activeToolCalls.length) {
          activeToolCalls = [
            {
              id: pendingTool.toolCallId || pendingTool.approvalId || `${step.name}-pending-tool`,
              name: pendingTool.toolName,
              input: compactPayload(pendingTool.toolArgs || null),
              result: null,
              status: 'running',
              latencyMs: null
            }
          ];
        }
      } else if (shouldRun && latestToolTrace?.name) {
        activeToolName = latestToolTrace.name;
        activeToolArgs = latestToolTrace.input;
      }

      return {
        id: step.name,
        kind: step.kind,
        title: step.title,
        detail: shouldRun ? runningText : waitingText,
        status: shouldRun ? 'running' : 'pending',
        toolName: activeToolName,
        toolCalls: activeToolCalls,
        input: activeToolArgs,
        result: null
      };
    })
    .filter((step, index) => step.status !== 'pending' || index <= currentStepIndex);

  const finalReportStep = resultByName.get('final_report');
  const reportContent = String(finalReportStep?.content || '').trim();
  const reportReady = Boolean(reportContent);

  let stage = 'planning';
  if (status === 'completed' || currentStepIndex >= 2) {
    stage = 'synthesis';
  } else if (currentStepIndex >= 1) {
    stage = 'tooling';
  }

  const phaseLabelByStage = {
    planning: 'Collecting rule context and baseline syntax...',
    tooling: 'Running SIEM research and external intelligence collection...',
    synthesis:
      status === 'completed'
        ? 'Workflow completed.'
        : 'Building final synthesis and waiting for next action...'
  };

  if (status === 'paused' && workflowGate?.message) {
    phaseLabelByStage.synthesis = workflowGate.message;
  } else if (status === 'paused' && commandGate?.message) {
    phaseLabelByStage.synthesis = 'Waiting for command approval in Detection Rule Apply.';
  }

  const enrichedExecutorRuns = includeExecutorRunsRaw
    ? executorRuns.map((executorRun) => {
        const resolvedStepName =
          stepIdToName.get(executorRun?.workflow_step_id) ||
          executorRun?.step_name ||
          executorRun?.metadata?.step_name ||
          '';
        return { ...executorRun, step_name: resolvedStepName };
      })
    : [];

  return {
    runId: run?.run_id || metadata?.runId || '',
    run_id: run?.run_id || metadata?.runId || '',
    sessionId: run?.session_id || metadata?.sessionId || '',
    session_id: run?.session_id || metadata?.sessionId || '',
    status,
    stage,
    phaseLabel: phaseLabelByStage[stage],
    reportReady,
    report_ready: reportReady,
    report: reportReady
      ? {
          title: 'Final Fine-Tuning Report',
          summary: summarizeStepContent(reportContent, 'Final report generated.'),
          markdown: clipText(reportContent, 25000)
        }
      : null,
    activity,
    gate: workflowGate,
    workflowGate,
    commandGate,
    stepExecutorRuns: includeExecutorRunsRaw ? enrichedExecutorRuns : []
  };
}

async function fetchRulesFromOpenSearch(userId) {
  const client = await getOpenSearchClientForUser(userId);
  if (!client) {
    return {
      source: 'opensearch',
      rules: [],
      warning: 'Enter valid SIEM indexer URL, username, and password to load rules.'
    };
  }

  const index =
    process.env.WAZUH_OPENSEARCH_INDEX ||
    process.env.OPENSEARCH_INDEX ||
    'wazuh-alerts-4.x-*';
  const topN = Math.min(Math.max(Number(process.env.WAZUH_TOP_RULES_SIZE || 10), 1), 50);
  const lookback = process.env.WAZUH_TOP_RULES_LOOKBACK || '24h';
  const timeField = process.env.WAZUH_TOP_RULES_TIME_FIELD || 'timestamp';
  const alternateTimeField = timeField === '@timestamp' ? 'timestamp' : '@timestamp';
  const lookbackCandidates = Array.from(new Set([lookback, '7d', '30d']));

  const fetchBuckets = async (queryTimeField, queryLookback) => {
    const response = await client.search({
      index,
      body: {
        size: 0,
        query: {
          bool: {
            filter: [
              { exists: { field: 'rule.id' } },
              { range: { [queryTimeField]: { gte: `now-${queryLookback}`, lte: 'now' } } }
            ]
          }
        },
        aggs: {
          top_rules: {
            terms: {
              field: 'rule.id',
              size: topN,
              order: { _count: 'desc' }
            },
            aggs: {
              latest: {
                top_hits: {
                  size: 1,
                  sort: [{ [queryTimeField]: { order: 'desc' } }],
                  _source: {
                    includes: ['rule.id', 'rule.description', 'rule.level', 'timestamp', '@timestamp']
                  }
                }
              },
              max_level: {
                max: { field: 'rule.level' }
              }
            }
          }
        }
      }
    });

    const responseBody = response?.body || response || {};
    return responseBody?.aggregations?.top_rules?.buckets || [];
  };

  let buckets = [];
  let selectedLookback = lookback;
  for (const candidateLookback of lookbackCandidates) {
    buckets = await fetchBuckets(timeField, candidateLookback);
    if (buckets.length) {
      selectedLookback = candidateLookback;
      break;
    }
    buckets = await fetchBuckets(alternateTimeField, candidateLookback);
    if (buckets.length) {
      selectedLookback = candidateLookback;
      break;
    }
  }

  const rules = buckets.map((bucket) => {
    const topHit = bucket?.latest?.hits?.hits?.[0]?._source || {};
    const ruleId = topHit?.rule?.id || bucket?.key;
    const description = topHit?.rule?.description || `Rule ${ruleId}`;
    const level = Number(topHit?.rule?.level ?? bucket?.max_level?.value ?? 0);
    const severity = level >= 10 ? 'warning' : 'normal';
    const alertsCount = Number(bucket?.doc_count || 0);

    return {
      id: `RUL-${ruleId}`,
      name: description,
      status: level >= 10 ? 'Warning' : 'Active',
      severity,
      description: `${alertsCount.toLocaleString()} alerts in last ${selectedLookback}`
    };
  });

  return {
    source: 'opensearch',
    rules,
    warning: rules.length ? '' : 'No SIEM rules were found for the configured index and time range.'
  };
}

async function fetchRuleByIdFromOpenSearch(rawRuleId, userId) {
  const normalizedRuleId = normalizeRuleId(rawRuleId);
  if (!normalizedRuleId) {
    return null;
  }

  const localRule =
    fallbackRules.find((rule) => normalizeRuleId(rule.id) === normalizedRuleId) || null;
  const client = await getOpenSearchClientForUser(userId);
  if (!client) {
    return localRule;
  }

  const index =
    process.env.WAZUH_OPENSEARCH_INDEX ||
    process.env.OPENSEARCH_INDEX ||
    'wazuh-alerts-4.x-*';
  const numericRuleId = Number(normalizedRuleId);
  const shouldClauses = [{ term: { 'rule.id': normalizedRuleId } }, { term: { 'rule.id.keyword': normalizedRuleId } }];
  if (Number.isFinite(numericRuleId) && !Number.isNaN(numericRuleId)) {
    shouldClauses.push({ term: { 'rule.id': numericRuleId } });
  }

  // Direct lookup by rule ID across index history. This avoids missing rules that
  // did not fire in the recent lookback windows.
  const response = await client.search({
    index,
    body: {
      size: 1,
      track_total_hits: false,
      query: {
        bool: {
          should: shouldClauses,
          minimum_should_match: 1
        }
      },
      sort: [
        { '@timestamp': { order: 'desc', unmapped_type: 'date' } },
        { timestamp: { order: 'desc', unmapped_type: 'date' } }
      ],
      _source: ['rule.id', 'rule.description', 'rule.level', 'timestamp', '@timestamp']
    }
  });
  const responseBody = response?.body || response || {};
  const hit = responseBody?.hits?.hits?.[0]?._source || null;
  if (hit?.rule?.id) {
    const hitRuleId = String(hit.rule.id);
    const level = Number(hit.rule.level || 0);
    return {
      id: `RUL-${hitRuleId}`,
      name: hit.rule.description || `Rule ${hitRuleId}`,
      status: level >= 10 ? 'Warning' : 'Active',
      severity: level >= 10 ? 'warning' : 'normal',
      description: hit.rule.description || `Rule ${hitRuleId}`
    };
  }

  return localRule;
}

function createMockRun(ruleId, ruleName) {
  const runId = crypto.randomUUID();
  const startedAt = Date.now();
  const durationMs = 11200;

  const events = [
    {
      id: 'plan',
      at: 500,
      kind: 'planning',
      title: 'Assembling fine-tune plan',
      detail: 'Mapped objective, guardrails, and rollback criteria.'
    },
    {
      id: 'search_call',
      at: 1600,
      kind: 'tool_call',
      title: 'Calling historical search tool',
      toolName: 'vector_rule_search',
      detail: 'Querying similar incidents and related rule clusters.',
      input: { rule_id: ruleId, window: '30d', limit: 1200, include_anomalies: true }
    },
    {
      id: 'search_result',
      at: 2800,
      kind: 'tool_result',
      title: 'Historical search completed',
      toolName: 'vector_rule_search',
      detail: '1,284 similar events grouped into 7 behavioral clusters.',
      result: { clusters: 7, events: 1284, high_risk_ratio: '18.4%' },
      latencyMs: 428,
      tokensIn: 214,
      tokensOut: 79
    },
    {
      id: 'edge_call',
      at: 3900,
      kind: 'tool_call',
      title: 'Calling edge-case miner',
      toolName: 'edge_case_miner',
      detail: 'Scanning false-positive pockets around active threshold.',
      input: { threshold_floor: 0.79, threshold_ceiling: 0.9, sample_size: 35000 }
    },
    {
      id: 'edge_result',
      at: 5300,
      kind: 'tool_result',
      title: 'Edge-case analysis completed',
      toolName: 'edge_case_miner',
      detail: 'Detected 3 collision pockets near 0.82 and 0.84.',
      result: { pockets: ['0.81-0.82', '0.83-0.84', '0.86'], expected_false_positives: 41 },
      latencyMs: 612,
      tokensIn: 311,
      tokensOut: 122
    },
    {
      id: 'sim_call',
      at: 6600,
      kind: 'tool_call',
      title: 'Calling threshold simulator',
      toolName: 'policy_simulator',
      detail: 'Executing multi-slice precision/recall simulation.',
      input: { candidates: [0.85, 0.86, 0.87, 0.88], validation_slices: ['A', 'B', 'C'] }
    },
    {
      id: 'sim_result',
      at: 8300,
      kind: 'tool_result',
      title: 'Simulation run completed',
      toolName: 'policy_simulator',
      detail: '0.87 produced strongest precision gain with low recall impact.',
      result: { recommended_threshold: 0.87, precision_gain: '+4.2%', recall_impact: '-0.6%' },
      latencyMs: 951,
      tokensIn: 402,
      tokensOut: 141
    },
    {
      id: 'synthesis',
      at: 9600,
      kind: 'synthesis',
      title: 'Synthesizing recommendation',
      detail: 'Drafting final recommendation package.',
      doneDetail: 'Recommendation package completed with deployment guardrails.'
    }
  ];

  mockRuns.set(runId, {
    runId,
    startedAt,
    ruleId,
    ruleName,
    durationMs,
    events
  });

  return runId;
}

function getMockRunState(runId) {
  const run = mockRuns.get(runId);
  if (!run) {
    return null;
  }

  const elapsed = Date.now() - run.startedAt;
  const completed = elapsed >= run.durationMs;
  const reportReady = completed;
  const progressPct = Math.min(100, Math.max(2, Math.round((elapsed / run.durationMs) * 100)));

  let stage = 'planning';
  if (elapsed >= 3200 && elapsed < 9000) {
    stage = 'tooling';
  } else if (elapsed >= 9000) {
    stage = 'synthesis';
  }

  const phaseLabelMap = {
    planning: 'Planning execution path...',
    tooling: 'Calling tools and validating signals...',
    synthesis: completed ? 'Run completed. Preparing final packet.' : 'Composing final recommendation...'
  };

  const visibleSteps = run.events
    .filter((step) => step.at <= elapsed)
    .map((step, index, arr) => {
      const isLatest = index === arr.length - 1;
      const status = completed ? 'done' : isLatest ? 'running' : 'done';
      const detail = status === 'done' && step.doneDetail ? step.doneDetail : step.detail;

      return {
        id: step.id,
        kind: step.kind,
        title: step.title,
        detail,
        status,
        toolName: step.toolName,
        input: step.input,
        result: step.result,
        latencyMs: step.latencyMs,
        tokensIn: step.tokensIn,
        tokensOut: step.tokensOut
      };
    });

  return {
    runId: run.runId,
    status: completed ? 'completed' : 'running',
    stage,
    phaseLabel: phaseLabelMap[stage],
    progressPct,
    reportReady,
    report: reportReady
      ? {
          title: 'Fine-tuning report is ready',
          summary: `Rule ${run.ruleId} (${run.ruleName}) simulation completed with guarded recommendation.`,
          recommendedThreshold: '0.87',
          precisionGain: '4.2%',
          recallImpact: '-0.6%'
        }
      : null,
    activity: visibleSteps
  };
}

app.use('/api', (req, res, next) => {
  if (req.path === '/auth/login' || req.path === '/auth/signup') {
    return next();
  }
  return requireAuth(req, res, next);
});

app.post('/api/auth/login', async (req, res) => {
  const identity = String(req.body?.identity || '').trim();
  const password = String(req.body?.password || '');
  if (!identity || !password) {
    return res.status(400).json({ error: 'email and password are required' });
  }

  try {
    const result = await dbQuery(
      `SELECT id, username, email, password_hash, job_title, avatar_data_url FROM ${APP_USERS_TABLE}
       WHERE lower(email) = lower($1)
       LIMIT 1`,
      [identity]
    );
    const userRow = result.rows?.[0] || null;
    if (!userRow || !verifyPassword(password, userRow.password_hash)) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    cleanupExpiredAuthSessions();
    const token = `${crypto.randomUUID()}-${crypto.randomBytes(12).toString('hex')}`;
    const expiresAt = Date.now() + APP_AUTH_TTL_HOURS * 60 * 60 * 1000;
    const user = {
      id: userRow.id,
      username: userRow.username,
      email: userRow.email,
      jobTitle: userRow.job_title || '',
      avatarDataUrl: userRow.avatar_data_url || ''
    };
    const onboarding = await getOnboardingStatus(user.id);

    authSessions.set(token, { user, expiresAt });

    return res.json({
      token,
      tokenType: 'Bearer',
      expiresAt,
      user,
      onboarding
    });
  } catch (error) {
    return res.status(500).json({ error: 'Login failed', details: error.message });
  }
});

app.post('/api/auth/signup', async (req, res) => {
  const fullName = String(req.body?.fullName || '').trim();
  const email = String(req.body?.email || '').trim().toLowerCase();
  const password = String(req.body?.password || '');
  const confirmPassword = String(req.body?.confirmPassword || '');
  const jobTitleRaw = String(req.body?.jobTitle || '').trim();
  const jobTitle = jobTitleRaw || 'Security Analyst';

  if (!fullName || !email || !password || !confirmPassword) {
    return res.status(400).json({ error: 'fullName, email, password and confirmPassword are required' });
  }
  if (password !== confirmPassword) {
    return res.status(400).json({ error: 'Passwords do not match' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }

  try {
    const existingEmail = await dbQuery(
      `SELECT id FROM ${APP_USERS_TABLE} WHERE lower(email) = lower($1) LIMIT 1`,
      [email]
    );
    if (existingEmail.rows.length) {
      return res.status(409).json({ error: 'Email already exists' });
    }

    const userId = crypto.randomUUID();
    const baseUsername = fullName.replace(/\s+/g, ' ').trim();
    let username = baseUsername;
    let suffix = 1;
    // Keep username unique while preserving the entered full name when possible.
    while (true) {
      const existingUserName = await dbQuery(
        `SELECT id FROM ${APP_USERS_TABLE} WHERE lower(username) = lower($1) LIMIT 1`,
        [username]
      );
      if (!existingUserName.rows.length) {
        break;
      }
      suffix += 1;
      username = `${baseUsername} ${suffix}`;
    }

    await dbQuery(
      `INSERT INTO ${APP_USERS_TABLE}
        (id, username, email, password_hash, job_title, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, NOW(), NOW())`,
      [userId, username, email, hashPassword(password), jobTitle]
    );

    cleanupExpiredAuthSessions();
    const token = `${crypto.randomUUID()}-${crypto.randomBytes(12).toString('hex')}`;
    const expiresAt = Date.now() + APP_AUTH_TTL_HOURS * 60 * 60 * 1000;
    const user = {
      id: userId,
      username,
      email,
      jobTitle,
      avatarDataUrl: ''
    };
    authSessions.set(token, { user, expiresAt });
    const onboarding = await getOnboardingStatus(userId);

    return res.status(201).json({
      success: true,
      token,
      tokenType: 'Bearer',
      expiresAt,
      user,
      onboarding
    });
  } catch (error) {
    return res.status(500).json({ error: 'Signup failed', details: error.message });
  }
});

app.get('/api/auth/session', async (req, res) => {
  const user = req.authUser || null;
  const session = getAuthSessionFromRequest(req);
  const onboarding = await getOnboardingStatus(String(user?.id || ''));
  return res.json({
    authenticated: true,
    user,
    expiresAt: session.expiresAt,
    onboarding
  });
});

app.get('/api/onboarding/status', async (req, res) => {
  try {
    const userId = String(req.authUser?.id || '');
    const status = await getOnboardingStatus(userId);
    return res.json(status);
  } catch (error) {
    return res.status(500).json({ error: 'Failed to load onboarding status', details: error.message });
  }
});

app.post('/api/onboarding/ai-models', async (req, res) => {
  const aiProvider = String(req.body?.aiProvider || '').trim().toLowerCase();
  const aiApiKey = String(req.body?.aiApiKey || '').trim();
  if (!aiProvider || !aiApiKey) {
    return res.status(400).json({ error: 'aiProvider and aiApiKey are required' });
  }
  if (!['openai', 'anthropic', 'openrouter'].includes(aiProvider)) {
    return res.status(400).json({ error: 'Invalid aiProvider' });
  }
  try {
    const models = await listModelsForProvider(aiProvider, aiApiKey);
    if (!models.length) {
      return res.status(400).json({ error: 'No models found for this provider/key.' });
    }
    return res.json({ success: true, models });
  } catch (error) {
    return res.status(502).json({ error: 'Failed to fetch models from provider', details: error.message });
  }
});

app.put('/api/onboarding/ai-provider', async (req, res) => {
  const aiProvider = String(req.body?.aiProvider || '').trim().toLowerCase();
  const aiApiKey = String(req.body?.aiApiKey || '').trim();
  const aiModelId = String(req.body?.aiModelId || '').trim();
  if (!aiProvider || !aiApiKey || !aiModelId) {
    return res.status(400).json({ error: 'aiProvider, aiApiKey and aiModelId are required' });
  }
  if (!['openai', 'anthropic', 'openrouter'].includes(aiProvider)) {
    return res.status(400).json({ error: 'Invalid aiProvider' });
  }
  try {
    const userId = String(req.authUser?.id || '');
    const setup = await upsertUserSetup(userId, {
      ai_provider: aiProvider,
      ai_api_key: aiApiKey,
      ai_model_id: aiModelId
    });
    return res.json({
      success: true,
      nextPath: onboardingPathFromSetup(setup),
      setup: setupToPayload(setup)
    });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to save AI provider', details: error.message });
  }
});

app.put('/api/onboarding/web-provider', async (req, res) => {
  const webProvider = String(req.body?.webProvider || '').trim().toLowerCase();
  const webApiKey = String(req.body?.webApiKey || '').trim();
  if (!webProvider || !webApiKey) {
    return res.status(400).json({ error: 'webProvider and webApiKey are required' });
  }
  if (!['tavily'].includes(webProvider)) {
    return res.status(400).json({ error: 'Invalid webProvider' });
  }
  try {
    const userId = String(req.authUser?.id || '');
    const setup = await upsertUserSetup(userId, { web_provider: webProvider, web_api_key: webApiKey });
    return res.json({
      success: true,
      nextPath: onboardingPathFromSetup(setup),
      setup: setupToPayload(setup)
    });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to save web provider', details: error.message });
  }
});

app.put('/api/onboarding/siem-provider', async (req, res) => {
  const siemProvider = String(req.body?.siemProvider || '').trim().toLowerCase();
  if (!siemProvider) {
    return res.status(400).json({ error: 'siemProvider is required' });
  }
  if (!['wazuh'].includes(siemProvider)) {
    return res.status(400).json({ error: 'Invalid siemProvider' });
  }
  try {
    const userId = String(req.authUser?.id || '');
    const setup = await upsertUserSetup(userId, { siem_provider: siemProvider });
    return res.json({
      success: true,
      nextPath: onboardingPathFromSetup(setup),
      setup: setupToPayload(setup)
    });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to save SIEM provider', details: error.message });
  }
});

app.put('/api/onboarding/siem-config', async (req, res) => {
  const indexerUrl = String(req.body?.indexerUrl || '').trim();
  const indexerUser = String(req.body?.indexerUser || '').trim();
  const indexerPass = String(req.body?.indexerPass || '').trim();
  const managerUrl = String(req.body?.managerUrl || '').trim();
  const sshUser = String(req.body?.sshUser || '').trim();
  const sshPort = Number(req.body?.sshPort || 22);
  const sshAuthMode = normalizeSshAuthMode(req.body?.sshAuthMode || 'password');
  const sshAuthRaw = String(req.body?.sshAuth || '');
  const sshAuth = sshAuthMode === 'key_file' ? normalizeSshPrivateKeyText(sshAuthRaw) : sshAuthRaw.trim();

  if (!indexerUrl || !indexerUser || !indexerPass || !managerUrl || !sshUser || !sshAuth) {
    return res.status(400).json({
      error: 'indexerUrl, indexerUser, indexerPass, managerUrl, sshUser and sshAuth are required'
    });
  }
  if (!Number.isFinite(sshPort) || sshPort <= 0) {
    return res.status(400).json({ error: 'sshPort must be a positive number' });
  }
  if (!['password', 'key_file'].includes(sshAuthMode)) {
    return res.status(400).json({ error: 'sshAuthMode must be password or key_file' });
  }
  if (sshAuthMode === 'key_file' && !isLikelyPemPrivateKey(sshAuth)) {
    return res.status(400).json({ error: 'sshAuth must be a valid PEM private key for key_file mode' });
  }
  try {
    const userId = String(req.authUser?.id || '');
    const setup = await upsertUserSetup(userId, {
      siem_indexer_url: indexerUrl,
      siem_indexer_user: indexerUser,
      siem_indexer_pass: indexerPass,
      siem_manager_url: managerUrl,
      siem_ssh_user: sshUser,
      siem_ssh_port: Math.round(sshPort),
      siem_ssh_auth: sshAuth,
      siem_ssh_auth_mode: sshAuthMode
    });
    return res.json({
      success: true,
      nextPath: onboardingPathFromSetup(setup),
      setup: setupToPayload(setup)
    });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to save SIEM configuration', details: error.message });
  }
});

app.post('/api/settings/test-indexer', requireAuth, async (req, res) => {
  const indexerUrl = normalizeIndexerNodeUrl(req.body?.indexerUrl);
  const indexerUser = String(req.body?.indexerUser || '').trim();
  const indexerPass = String(req.body?.indexerPass || '').trim();
  if (!indexerUrl || !indexerUser || !indexerPass) {
    return res.status(400).json({ error: 'indexerUrl, indexerUser and indexerPass are required' });
  }

  try {
    const client = new Client({
      node: indexerUrl,
      auth: { username: indexerUser, password: indexerPass },
      ssl: { rejectUnauthorized: false },
      requestTimeout: 6000
    });
    const info = await client.info();
    const body = info?.body || {};
    const cluster = String(body?.cluster_name || '').trim();
    const message = cluster
      ? `Indexer connected (cluster: ${cluster})`
      : 'Indexer connected successfully.';
    return res.json({ success: true, message });
  } catch (error) {
    const reason =
      error?.meta?.body?.error?.reason ||
      error?.meta?.body?.error?.root_cause?.[0]?.reason ||
      error?.message ||
      'Failed to connect to indexer.';
    return res.status(502).json({ error: String(reason) });
  }
});

app.post('/api/settings/test-manager', requireAuth, async (req, res) => {
  const managerUrl = String(req.body?.managerUrl || '').trim();
  const sshPort = Number(req.body?.sshPort || 22);
  const sshUser = String(req.body?.sshUser || '').trim();
  const sshAuth = normalizeSshPrivateKeyText(req.body?.sshAuth || '').trim();
  const sshAuthMode = normalizeSshAuthMode(req.body?.sshAuthMode || '');
  const target = parseManagerTarget(managerUrl, sshPort);
  if (!target.host || !Number.isFinite(target.port) || target.port <= 0) {
    return res.status(400).json({ error: 'Valid managerUrl/IP and sshPort are required' });
  }
  if (!sshUser || !sshAuth) {
    return res.status(400).json({ error: 'sshUser and SSH authentication value are required' });
  }
  if (sshAuthMode === 'key_file' && !isLikelyPemPrivateKey(sshAuth)) {
    return res.status(400).json({ error: 'sshAuth must be a valid PEM private key for key_file mode' });
  }

  try {
    await testSshConnection({
      host: target.host,
      port: target.port,
      username: sshUser,
      authMode: sshAuthMode,
      authValue: sshAuth
    });
    return res.json({ success: true, message: `SSH connected to ${target.host}:${target.port}` });
  } catch (error) {
    return res.status(502).json({
      error: `SSH failed on ${target.host}:${target.port} (${error.message || 'connection failed'})`
    });
  }
});

app.get('/api/auth/profile', async (req, res) => {
  try {
    const userId = String(req.authUser?.id || '');
    const user = await getUserById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    return res.json({
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        jobTitle: user.job_title || '',
        avatarDataUrl: user.avatar_data_url || ''
      }
    });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to load profile', details: error.message });
  }
});

app.put('/api/auth/profile', async (req, res) => {
  try {
    const userId = String(req.authUser?.id || '');
    const username = req.body?.username;
    const jobTitle = req.body?.jobTitle;
    const avatarDataUrl = req.body?.avatarDataUrl;

    if (avatarDataUrl !== undefined) {
      const avatar = String(avatarDataUrl || '');
      const isValidDataImageUrl =
        !avatar || /^data:image\/(png|jpeg|jpg|webp|gif);base64,[A-Za-z0-9+/=]+$/.test(avatar);
      if (!isValidDataImageUrl) {
        return res.status(400).json({ error: 'Invalid avatar image format' });
      }
      if (avatar.length > 2_000_000) {
        return res.status(400).json({ error: 'Avatar image is too large' });
      }
    }

    const user = await updateUserProfile(userId, { username, jobTitle, avatarDataUrl });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    for (const session of authSessions.values()) {
      if (session?.user?.id === user.id) {
        session.user = {
          ...session.user,
          username: user.username,
          jobTitle: user.job_title || '',
          avatarDataUrl: user.avatar_data_url || ''
        };
      }
    }

    return res.json({
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        jobTitle: user.job_title || '',
        avatarDataUrl: user.avatar_data_url || ''
      }
    });
  } catch (error) {
    if (String(error.message || '').includes('app_users_username_key')) {
      return res.status(409).json({ error: 'Username already exists' });
    }
    return res.status(500).json({ error: 'Failed to update profile', details: error.message });
  }
});

app.post('/api/auth/logout', (req, res) => {
  const token = getBearerToken(req);
  if (token) {
    authSessions.delete(token);
  }
  return res.json({ success: true });
});

app.get('/api/rules', async (req, res) => {
  try {
    const userId = String(req.authUser?.id || '');
    const data = await fetchRulesFromOpenSearch(userId);
    res.json(data);
  } catch (error) {
    res.status(502).json({
      source: 'opensearch',
      rules: [],
      warning: 'Unable to connect to the configured SIEM indexer. Check the Indexer URL, username, and password.',
      error: error.message || 'OpenSearch fetch failed.'
    });
  }
});

app.get('/api/rules/:ruleId', async (req, res) => {
  const rawRuleId = String(req.params.ruleId || '');
  const normalizedRuleId = normalizeRuleId(rawRuleId);
  if (!normalizedRuleId) {
    return res.status(400).json({ error: 'ruleId is required' });
  }

  try {
    const userId = String(req.authUser?.id || '');
    const rule = await fetchRuleByIdFromOpenSearch(normalizedRuleId, userId);
    if (!rule) {
      return res.status(404).json({ error: `Rule ${normalizedRuleId} not found` });
    }
    return res.json({ source: 'lookup', rule });
  } catch (_error) {
    return res.status(500).json({ error: `Failed to fetch rule ${normalizedRuleId}` });
  }
});

app.post('/api/fine-tune/stream', async (req, res) => {
  const { ruleId, ruleName } = req.body || {};
  if (!ruleId || !ruleName) {
    return res.status(400).json({ error: 'ruleId and ruleName are required' });
  }

  const { baseUrl: backendUrl, workflowId } = getBackendConfig();
  res.setHeader('Content-Type', 'application/x-ndjson; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  if (typeof res.flushHeaders === 'function') {
    res.flushHeaders();
  }

  if (!backendUrl) {
    const runId = createMockRun(ruleId, ruleName);
    const mockState = getMockRunState(runId);
    writeNdjson(res, { type: 'run_started', runId, run_id: runId, sessionId: '', session_id: '' });
    writeNdjson(res, { type: 'snapshot', payload: mockState });
    writeNdjson(res, { type: 'done', runId, run_id: runId, sessionId: '', session_id: '' });
    return res.end();
  }
  const authUser = req.authUser || {};
  const userId = String(authUser.id || '');
  const sessionId = await getOrCreateUserWorkflowSession(userId, workflowId);
  const startedAt = Date.now();
  const abortController = new AbortController();
  let clientDisconnected = false;

  const closeStream = () => {
    clientDisconnected = true;
    abortController.abort();
  };
  res.on('close', closeStream);
  req.on('aborted', closeStream);

  try {
    const params = new URLSearchParams();
    params.set('message', buildWorkflowMessage(ruleId, ruleName));
    params.set('session_id', sessionId);
    params.set('user_id', userId);
    params.set('background', 'true');
    params.set('stream', 'true');
    params.set('stream_events', 'true');
    params.set('stream_executor_events', 'true');

    const response = await fetch(`${backendUrl}/workflows/${encodeURIComponent(workflowId)}/runs`, {
      method: 'POST',
      headers: backendHeaders('application/x-www-form-urlencoded'),
      body: params.toString(),
      signal: abortController.signal
    });

    if (!response.ok) {
      const text = await response.text();
      writeNdjson(res, {
        type: 'error',
        error: 'Agent backend request failed',
        details: clipText(text, 6000)
      });
      return res.end();
    }

    let runIdFromStream = '';
    let resolvedSessionId = sessionId;
    let sentRunStarted = false;
    writeNdjson(res, {
      type: 'stream_opened',
      workflowId,
      sessionId: resolvedSessionId,
      session_id: resolvedSessionId
    });

    for await (const payload of iterateBackendStreamPayloads(response.body)) {
      const ids = getIdsFromBackendPayload(payload);
      if (ids.sessionId) {
        resolvedSessionId = ids.sessionId;
      }
      if (ids.runId && (!runIdFromStream || ids.runId === runIdFromStream)) {
        runIdFromStream = ids.runId;
      }

      if (runIdFromStream) {
        realRuns.set(runIdFromStream, {
          runId: runIdFromStream,
          sessionId: resolvedSessionId,
          userId,
          workflowId,
          ruleId,
          ruleName,
          createdAt: startedAt
        });
        await saveWorkflowRun({
          userId,
          workflowId,
          runId: runIdFromStream,
          sessionId: resolvedSessionId,
          ruleId,
          ruleName,
          status: 'running'
        });
      }

      if (ids.runId && !sentRunStarted) {
        sentRunStarted = true;
        writeNdjson(res, {
          type: 'run_started',
          runId: ids.runId,
          run_id: ids.runId,
          sessionId: resolvedSessionId,
          session_id: resolvedSessionId
        });
      }

      if (payload?.event) {
        writeNdjson(res, {
          type: 'workflow_event',
          runId: runIdFromStream,
          run_id: runIdFromStream,
          sessionId: resolvedSessionId,
          session_id: resolvedSessionId,
          event: payload
        });
      } else {
        writeNdjson(res, {
          type: 'run_output',
          runId: runIdFromStream,
          run_id: runIdFromStream,
          sessionId: resolvedSessionId,
          session_id: resolvedSessionId,
          output: payload
        });
      }

      if (clientDisconnected) {
        break;
      }
    }

    writeNdjson(res, {
      type: 'done',
      runId: runIdFromStream,
      run_id: runIdFromStream,
      sessionId: resolvedSessionId,
      session_id: resolvedSessionId
    });
    if (runIdFromStream) {
      await saveWorkflowRun({
        userId,
        workflowId,
        runId: runIdFromStream,
        sessionId: resolvedSessionId,
        ruleId,
        ruleName,
        status: 'running'
      });
    }
    return res.end();
  } catch (error) {
    if (clientDisconnected || error.name === 'AbortError') {
      return res.end();
    }
    writeNdjson(res, {
      type: 'error',
      error: 'Agent backend is unreachable',
      details: error.message
    });
    return res.end();
  }
});

app.post('/api/fine-tune/:runId/resume', async (req, res) => {
  const { runId } = req.params;
  const requestedSessionId = String(req.body?.sessionId || req.body?.session_id || '').trim();
  const rawLastEventIndex =
    req.body?.lastEventIndex ?? req.body?.last_event_index ?? req.query?.lastEventIndex ?? req.query?.last_event_index;
  const lastEventIndex = Number.isFinite(Number(rawLastEventIndex)) ? Number(rawLastEventIndex) : null;
  const { baseUrl: backendUrl, workflowId: defaultWorkflowId } = getBackendConfig();

  if (!backendUrl) {
    return res.status(400).json({ error: 'Resume requires AGENT_BACKEND_URL' });
  }

  const mapMeta = realRuns.get(runId) || null;
  const dbMeta = mapMeta ? null : await getRunMeta(runId);
  const meta = mapMeta || dbMeta;
  const resolvedSessionId = requestedSessionId || String(meta?.sessionId || meta?.agno_session_id || '').trim();
  const resolvedWorkflowId = String(meta?.workflowId || meta?.workflow_id || defaultWorkflowId);
  if (!resolvedSessionId) {
    return res.status(400).json({ error: 'sessionId is required to resume this run' });
  }

  res.setHeader('Content-Type', 'application/x-ndjson; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  if (typeof res.flushHeaders === 'function') {
    res.flushHeaders();
  }

  const abortController = new AbortController();
  let clientDisconnected = false;
  const closeStream = () => {
    clientDisconnected = true;
    abortController.abort();
  };
  res.on('close', closeStream);
  req.on('aborted', closeStream);

  try {
    const params = new URLSearchParams();
    params.set('session_id', resolvedSessionId);
    if (lastEventIndex !== null) {
      params.set('last_event_index', String(lastEventIndex));
    }

    const response = await fetch(
      `${backendUrl}/workflows/${encodeURIComponent(resolvedWorkflowId)}/runs/${encodeURIComponent(runId)}/resume`,
      {
        method: 'POST',
        headers: backendHeaders('application/x-www-form-urlencoded'),
        body: params.toString(),
        signal: abortController.signal
      }
    );

    if (!response.ok) {
      const text = await response.text();
      writeNdjson(res, {
        type: 'error',
        error: 'Agent backend resume request failed',
        details: clipText(text, 6000)
      });
      return res.end();
    }

    writeNdjson(res, {
      type: 'stream_opened',
      mode: 'resume',
      runId,
      run_id: runId,
      sessionId: resolvedSessionId,
      session_id: resolvedSessionId,
      lastEventIndex,
      last_event_index: lastEventIndex
    });

    let streamSessionId = resolvedSessionId;
    for await (const payload of iterateBackendStreamPayloads(response.body)) {
      const ids = getIdsFromBackendPayload(payload);
      if (ids.sessionId) {
        streamSessionId = ids.sessionId;
      }

      if (payload?.event) {
        writeNdjson(res, {
          type: 'workflow_event',
          runId,
          run_id: runId,
          sessionId: streamSessionId,
          session_id: streamSessionId,
          event: payload
        });
      } else {
        writeNdjson(res, {
          type: 'run_output',
          runId,
          run_id: runId,
          sessionId: streamSessionId,
          session_id: streamSessionId,
          output: payload
        });
      }

      if (clientDisconnected) {
        break;
      }
    }

    writeNdjson(res, {
      type: 'done',
      mode: 'resume',
      runId,
      run_id: runId,
      sessionId: streamSessionId,
      session_id: streamSessionId
    });
    return res.end();
  } catch (error) {
    if (clientDisconnected || error.name === 'AbortError') {
      return res.end();
    }
    writeNdjson(res, {
      type: 'error',
      error: 'Agent backend resume stream is unreachable',
      details: error.message
    });
    return res.end();
  }
});

app.post('/api/fine-tune', async (req, res) => {
  const { ruleId, ruleName } = req.body || {};

  if (!ruleId || !ruleName) {
    return res.status(400).json({ error: 'ruleId and ruleName are required' });
  }

  const { baseUrl: backendUrl, workflowId } = getBackendConfig();

  if (backendUrl) {
    try {
      const authUser = req.authUser || {};
      const userId = String(authUser.id || '');
      const sessionId = await getOrCreateUserWorkflowSession(userId, workflowId);
      const params = new URLSearchParams();
      params.set('message', buildWorkflowMessage(ruleId, ruleName));
      params.set('session_id', sessionId);
      params.set('user_id', userId);
      params.set('background', 'true');
      params.set('stream', 'false');

      const response = await fetch(
        `${backendUrl}/workflows/${encodeURIComponent(workflowId)}/runs`,
        {
          method: 'POST',
          headers: backendHeaders('application/x-www-form-urlencoded'),
          body: params.toString()
        }
      );

      if (!response.ok) {
        const text = await response.text();
        return res.status(502).json({
          error: 'Agent backend request failed',
          details: clipText(text, 6000)
        });
      }

      const body = await response.json();
      const runIdFromBackend = body?.run_id || body?.runId || body?.id;
      const resolvedSessionId = body?.session_id || sessionId;

      if (!runIdFromBackend) {
        return res.status(502).json({
          error: 'Agent backend did not return run_id'
        });
      }

      realRuns.set(runIdFromBackend, {
        runId: runIdFromBackend,
        sessionId: resolvedSessionId,
        userId,
        workflowId,
        ruleId,
        ruleName,
        createdAt: Date.now()
      });
      await saveWorkflowRun({
        userId,
        workflowId,
        runId: runIdFromBackend,
        sessionId: resolvedSessionId,
        ruleId,
        ruleName,
        status: String(body?.status || 'PENDING')
      });

      return res.json({
        runId: runIdFromBackend,
        run_id: runIdFromBackend,
        sessionId: resolvedSessionId,
        session_id: resolvedSessionId,
        status: 'accepted',
        backendStatus: body?.status || 'PENDING'
      });
    } catch (error) {
      return res.status(502).json({
        error: 'Agent backend is unreachable',
        details: error.message
      });
    }
  }

  const runId = createMockRun(ruleId, ruleName);
  return res.json({
    runId,
    status: 'accepted'
  });
});

app.post('/api/fine-tune/:runId/confirm/stream', async (req, res) => {
  const { runId } = req.params;
  const {
    action = '',
    requirementStepId = '',
    sessionId = '',
    mode = '',
    approvalId = '',
    toolCallId = '',
    userInput = null
  } = req.body || {};
  const normalizedMode = String(mode || '')
    .trim()
    .toLowerCase();
  const normalizedAction = String(action || '')
    .trim()
    .toLowerCase();
  const isApproveAction = ['approve', 'approved', 'accept', 'accepted', 'yes'].includes(normalizedAction);
  const isRejectAction = ['reject', 'rejected', 'deny', 'denied', 'decline', 'declined', 'no'].includes(
    normalizedAction
  );
  const isStepUserInputMode = normalizedMode === 'step_user_input';
  if (!isStepUserInputMode && !isApproveAction && !isRejectAction) {
    return res.status(400).json({
      error: "action must be one of: approve|reject (aliases: accept/deny)"
    });
  }
  const shouldApprove = isStepUserInputMode ? true : isApproveAction;
  const { baseUrl: backendUrl, workflowId: defaultWorkflowId } = getBackendConfig();

  if (!backendUrl) {
    return res.status(400).json({ error: 'HITL confirmation requires AGENT_BACKEND_URL' });
  }

  const authUser = req.authUser || {};
  const mapMeta = realRuns.get(runId) || null;
  const dbMeta = mapMeta ? null : await getRunMeta(runId);
  const meta = mapMeta || dbMeta;
  const resolvedSessionId = String(sessionId || meta?.sessionId || meta?.agno_session_id || '');
  const resolvedWorkflowId = String(meta?.workflowId || meta?.workflow_id || defaultWorkflowId);
  if (!resolvedSessionId) {
    return res.status(400).json({ error: 'sessionId is required for this run' });
  }

  try {
    const runUrl = `${backendUrl}/workflows/${encodeURIComponent(
      resolvedWorkflowId
    )}/runs/${encodeURIComponent(runId)}?session_id=${encodeURIComponent(resolvedSessionId)}`;
    const runResponse = await fetch(runUrl, { headers: backendHeaders() });
    if (!runResponse.ok) {
      const text = await runResponse.text();
      return res.status(502).json({
        error: 'Failed to load workflow run before confirmation',
        details: clipText(text, 5000)
      });
    }

    const run = await runResponse.json();
    const requirements = Array.isArray(run?.step_requirements) ? run.step_requirements : [];
    const unresolvedRequirements = requirements.filter((item) => item && item.step_id && item.confirmed === null);
    const unresolvedStepRequirements = unresolvedRequirements.filter(
      (item) => !item?.requires_executor_input
    );

    const pendingExecutorTools = [];
    requirements.forEach((requirement, requirementIndex) => {
      if (!requirement || !requirement?.requires_executor_input || requirement?.confirmed !== null) {
        return;
      }
      const executorRequirements = Array.isArray(requirement?.executor_requirements)
        ? requirement.executor_requirements
        : [];
      executorRequirements.forEach((executorRequirement, executorRequirementIndex) => {
        const toolExecution = executorRequirement?.tool_execution;
        if (
          toolExecution?.requires_confirmation &&
          (toolExecution?.confirmed === null || toolExecution?.confirmed === undefined)
        ) {
          pendingExecutorTools.push({
            requirementIndex,
            executorRequirementIndex,
            stepId: requirement?.step_id || '',
            toolExecution
          });
        }
      });
    });

    const targetPendingTool =
      pendingExecutorTools.find((tool) => toolCallId && tool?.toolExecution?.tool_call_id === toolCallId) ||
      pendingExecutorTools.find((tool) => approvalId && tool?.toolExecution?.approval_id === approvalId) ||
      pendingExecutorTools.find((tool) => requirementStepId && tool?.stepId === requirementStepId) ||
      pendingExecutorTools[pendingExecutorTools.length - 1] ||
      null;
    const isToolConfirmation =
      normalizedMode === 'tool_confirmation' ||
      (!normalizedMode && Boolean(targetPendingTool));

    const continueParams = new URLSearchParams();
    continueParams.set('session_id', resolvedSessionId);
    continueParams.set('stream', 'true');

    if (isToolConfirmation && targetPendingTool) {
      const updatedRequirements = requirements.map((requirement, requirementIndex) => {
        if (!requirement || requirementIndex !== targetPendingTool.requirementIndex) {
          return requirement;
        }
        const executorRequirements = Array.isArray(requirement?.executor_requirements)
          ? requirement.executor_requirements
          : [];
        const nextExecutorRequirements = executorRequirements.map((executorRequirement, executorRequirementIndex) => {
          if (
            executorRequirementIndex !== targetPendingTool.executorRequirementIndex ||
            !executorRequirement?.tool_execution
          ) {
            return executorRequirement;
          }
          return {
            ...executorRequirement,
            tool_execution: {
              ...executorRequirement.tool_execution,
              confirmed: shouldApprove,
              confirmation_note: shouldApprove ? null : 'Rejected from frontend'
            }
          };
        });
        return {
          ...requirement,
          executor_requirements: nextExecutorRequirements
        };
      });
      continueParams.set('step_requirements', JSON.stringify(updatedRequirements));
    } else if (isToolConfirmation) {
      return res.status(409).json({
        error: 'No pending command approval available to confirm'
      });
    } else if (isStepUserInputMode) {
      const normalizedUserInput =
        userInput && typeof userInput === 'object' && !Array.isArray(userInput) ? userInput : null;
      if (!normalizedUserInput) {
        return res.status(400).json({
          error: 'userInput object is required for step_user_input mode'
        });
      }

      const unresolvedUserInputRequirements = unresolvedStepRequirements.filter((item) =>
        Boolean(item?.requires_user_input)
      );
      if (!unresolvedUserInputRequirements.length) {
        return res.status(409).json({
          error: 'No pending user-input requirement available'
        });
      }

      const targetRequirement =
        unresolvedUserInputRequirements.find((item) => item.step_id === requirementStepId) ||
        unresolvedUserInputRequirements[unresolvedUserInputRequirements.length - 1];
      const resolvedRequirementStepId = targetRequirement?.step_id || '';

      const updatedRequirements = requirements.map((item) => {
        if (!item || !item.step_id) {
          return item;
        }
        if (item.step_id !== resolvedRequirementStepId) {
          return item;
        }
        const nextUserInputSchema = Array.isArray(item?.user_input_schema)
          ? item.user_input_schema.map((field) => {
              if (!field || typeof field !== 'object') {
                return field;
              }
              const name = String(field.name || '').trim();
              return {
                ...field,
                value: name && Object.prototype.hasOwnProperty.call(normalizedUserInput, name)
                  ? normalizedUserInput[name]
                  : field.value ?? null
              };
            })
          : item?.user_input_schema;
        return {
          ...item,
          confirmed: true,
          user_input: normalizedUserInput,
          user_input_schema: nextUserInputSchema,
          rejection_feedback: null
        };
      });
      continueParams.set('step_requirements', JSON.stringify(updatedRequirements));
    } else {
      if (!unresolvedStepRequirements.length) {
        return res.status(409).json({
          error: 'No pending requirement available to confirm'
        });
      }

      const targetRequirement =
        unresolvedStepRequirements.find((item) => item.step_id === requirementStepId) ||
        unresolvedStepRequirements[unresolvedStepRequirements.length - 1];
      const resolvedRequirementStepId = targetRequirement?.step_id || '';

      const updatedRequirements = requirements.map((item) => {
        if (!item || !item.step_id) {
          return item;
        }
        if (item.step_id !== resolvedRequirementStepId) {
          return item;
        }
        return {
          ...item,
          confirmed: shouldApprove,
          rejection_feedback: shouldApprove ? null : 'Rejected from frontend'
        };
      });
      continueParams.set('step_requirements', JSON.stringify(updatedRequirements));
    }

    const continueResponse = await fetch(
      `${backendUrl}/workflows/${encodeURIComponent(
        resolvedWorkflowId
      )}/runs/${encodeURIComponent(runId)}/continue`,
      {
        method: 'POST',
        headers: backendHeaders('application/x-www-form-urlencoded'),
        body: continueParams.toString()
      }
    );
    if (!continueResponse.ok) {
      const text = await continueResponse.text();
      return res.status(502).json({
        error: 'Failed to continue workflow after confirmation',
        details: clipText(text, 6000)
      });
    }

    res.setHeader('Content-Type', 'application/x-ndjson; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    if (typeof res.flushHeaders === 'function') {
      res.flushHeaders();
    }

    writeNdjson(res, {
      type: 'stream_opened',
      runId,
      run_id: runId,
      sessionId: resolvedSessionId,
      session_id: resolvedSessionId
    });
    writeNdjson(res, {
      type: 'run_started',
      runId,
      run_id: runId,
      sessionId: resolvedSessionId,
      session_id: resolvedSessionId
    });

    let streamRunId = runId;
    let streamSessionId = resolvedSessionId;
    for await (const payload of iterateBackendStreamPayloads(continueResponse.body)) {
      const ids = getIdsFromBackendPayload(payload);
      if (ids.runId) {
        streamRunId = ids.runId;
      }
      if (ids.sessionId) {
        streamSessionId = ids.sessionId;
      }

      if (payload?.event) {
        writeNdjson(res, {
          type: 'workflow_event',
          runId: streamRunId,
          run_id: streamRunId,
          sessionId: streamSessionId,
          session_id: streamSessionId,
          event: payload
        });
      } else {
        writeNdjson(res, {
          type: 'run_output',
          runId: streamRunId,
          run_id: streamRunId,
          sessionId: streamSessionId,
          session_id: streamSessionId,
          output: payload
        });
      }
    }

    writeNdjson(res, {
      type: 'done',
      runId: streamRunId,
      run_id: streamRunId,
      sessionId: streamSessionId,
      session_id: streamSessionId
    });
    await saveWorkflowRun({
      userId: String(authUser.id || meta?.userId || meta?.user_id || ''),
      workflowId: resolvedWorkflowId,
      runId: streamRunId,
      sessionId: streamSessionId,
      status: 'running'
    });
    return res.end();
  } catch (error) {
    if (res.headersSent) {
      writeNdjson(res, {
        type: 'error',
        error: 'Agent backend is unreachable',
        details: error.message
      });
      return res.end();
    }
    return res.status(502).json({
      error: 'Agent backend is unreachable',
      details: error.message
    });
  }
});

app.post('/api/fine-tune/:runId/confirm', async (req, res) => {
  const { runId } = req.params;
  const {
    action = '',
    requirementStepId = '',
    sessionId = '',
    mode = '',
    approvalId = '',
    toolCallId = '',
    userInput = null
  } = req.body || {};
  const normalizedMode = String(mode || '')
    .trim()
    .toLowerCase();
  const normalizedAction = String(action || '')
    .trim()
    .toLowerCase();
  const isApproveAction = ['approve', 'approved', 'accept', 'accepted', 'yes'].includes(normalizedAction);
  const isRejectAction = ['reject', 'rejected', 'deny', 'denied', 'decline', 'declined', 'no'].includes(
    normalizedAction
  );
  const isStepUserInputMode = normalizedMode === 'step_user_input';
  if (!isStepUserInputMode && !isApproveAction && !isRejectAction) {
    return res.status(400).json({
      error: "action must be one of: approve|reject (aliases: accept/deny)"
    });
  }
  const shouldApprove = isStepUserInputMode ? true : isApproveAction;
  const { baseUrl: backendUrl, workflowId: defaultWorkflowId } = getBackendConfig();

  if (!backendUrl) {
    return res.status(400).json({ error: 'HITL confirmation requires AGENT_BACKEND_URL' });
  }

  const authUser = req.authUser || {};
  const mapMeta = realRuns.get(runId) || null;
  const dbMeta = mapMeta ? null : await getRunMeta(runId);
  const meta = mapMeta || dbMeta;
  const resolvedSessionId = String(sessionId || meta?.sessionId || meta?.agno_session_id || '');
  const resolvedWorkflowId = String(meta?.workflowId || meta?.workflow_id || defaultWorkflowId);
  if (!resolvedSessionId) {
    return res.status(400).json({ error: 'sessionId is required for this run' });
  }

  try {
    const runUrl = `${backendUrl}/workflows/${encodeURIComponent(
      resolvedWorkflowId
    )}/runs/${encodeURIComponent(runId)}?session_id=${encodeURIComponent(resolvedSessionId)}`;
    const runResponse = await fetch(runUrl, { headers: backendHeaders() });
    if (!runResponse.ok) {
      const text = await runResponse.text();
      return res.status(502).json({
        error: 'Failed to load workflow run before confirmation',
        details: clipText(text, 5000)
      });
    }

    const run = await runResponse.json();
    const requirements = Array.isArray(run?.step_requirements) ? run.step_requirements : [];
    const unresolvedRequirements = requirements.filter((item) => item && item.step_id && item.confirmed === null);
    const unresolvedStepRequirements = unresolvedRequirements.filter(
      (item) => !item?.requires_executor_input
    );

    const pendingExecutorTools = [];
    requirements.forEach((requirement, requirementIndex) => {
      if (!requirement || !requirement?.requires_executor_input || requirement?.confirmed !== null) {
        return;
      }
      const executorRequirements = Array.isArray(requirement?.executor_requirements)
        ? requirement.executor_requirements
        : [];
      executorRequirements.forEach((executorRequirement, executorRequirementIndex) => {
        const toolExecution = executorRequirement?.tool_execution;
        if (
          toolExecution?.requires_confirmation &&
          (toolExecution?.confirmed === null || toolExecution?.confirmed === undefined)
        ) {
          pendingExecutorTools.push({
            requirementIndex,
            executorRequirementIndex,
            stepId: requirement?.step_id || '',
            toolExecution
          });
        }
      });
    });

    const targetPendingTool =
      pendingExecutorTools.find((tool) => toolCallId && tool?.toolExecution?.tool_call_id === toolCallId) ||
      pendingExecutorTools.find((tool) => approvalId && tool?.toolExecution?.approval_id === approvalId) ||
      pendingExecutorTools.find((tool) => requirementStepId && tool?.stepId === requirementStepId) ||
      pendingExecutorTools[pendingExecutorTools.length - 1] ||
      null;
    const isToolConfirmation =
      normalizedMode === 'tool_confirmation' ||
      (!normalizedMode && Boolean(targetPendingTool));

    const continueParams = new URLSearchParams();
    continueParams.set('session_id', resolvedSessionId);
    // Command approvals should be acknowledged quickly. With stream=false,
    // AgentOS waits and serializes a huge RunOutput; stream=true lets us drain
    // progress in the background while the browser reconnects to live events.
    continueParams.set('stream', isToolConfirmation ? 'true' : 'false');

    let resolvedRequirementStepId = '';

    if (isToolConfirmation && targetPendingTool) {
      resolvedRequirementStepId = targetPendingTool?.stepId || '';

      const updatedRequirements = requirements.map((requirement, requirementIndex) => {
        if (!requirement || requirementIndex !== targetPendingTool.requirementIndex) {
          return requirement;
        }
        const executorRequirements = Array.isArray(requirement?.executor_requirements)
          ? requirement.executor_requirements
          : [];
        const nextExecutorRequirements = executorRequirements.map((executorRequirement, executorRequirementIndex) => {
          if (
            executorRequirementIndex !== targetPendingTool.executorRequirementIndex ||
            !executorRequirement?.tool_execution
          ) {
            return executorRequirement;
          }
          return {
            ...executorRequirement,
            tool_execution: {
              ...executorRequirement.tool_execution,
              confirmed: shouldApprove,
              confirmation_note: shouldApprove ? null : 'Rejected from frontend'
            }
          };
        });
        return {
          ...requirement,
          executor_requirements: nextExecutorRequirements
        };
      });
      continueParams.set('step_requirements', JSON.stringify(updatedRequirements));
    } else if (isToolConfirmation) {
      return res.status(409).json({
        error: 'No pending command approval available to confirm'
      });
    } else if (isStepUserInputMode) {
      const normalizedUserInput =
        userInput && typeof userInput === 'object' && !Array.isArray(userInput) ? userInput : null;
      if (!normalizedUserInput) {
        return res.status(400).json({
          error: 'userInput object is required for step_user_input mode'
        });
      }

      const unresolvedUserInputRequirements = unresolvedStepRequirements.filter((item) =>
        Boolean(item?.requires_user_input)
      );
      if (!unresolvedUserInputRequirements.length) {
        return res.status(409).json({
          error: 'No pending user-input requirement available'
        });
      }

      const targetRequirement =
        unresolvedUserInputRequirements.find((item) => item.step_id === requirementStepId) ||
        unresolvedUserInputRequirements[unresolvedUserInputRequirements.length - 1];
      resolvedRequirementStepId = targetRequirement?.step_id || '';

      const updatedRequirements = requirements.map((item) => {
        if (!item || !item.step_id) {
          return item;
        }
        if (item.step_id !== resolvedRequirementStepId) {
          return item;
        }
        const nextUserInputSchema = Array.isArray(item?.user_input_schema)
          ? item.user_input_schema.map((field) => {
              if (!field || typeof field !== 'object') {
                return field;
              }
              const name = String(field.name || '').trim();
              return {
                ...field,
                value: name && Object.prototype.hasOwnProperty.call(normalizedUserInput, name)
                  ? normalizedUserInput[name]
                  : field.value ?? null
              };
            })
          : item?.user_input_schema;
        return {
          ...item,
          confirmed: true,
          user_input: normalizedUserInput,
          user_input_schema: nextUserInputSchema,
          rejection_feedback: null
        };
      });
      continueParams.set('step_requirements', JSON.stringify(updatedRequirements));
    } else {
      if (!unresolvedStepRequirements.length) {
        return res.status(409).json({
          error: 'No pending requirement available to confirm'
        });
      }

      const targetRequirement =
        unresolvedStepRequirements.find((item) => item.step_id === requirementStepId) ||
        unresolvedStepRequirements[unresolvedStepRequirements.length - 1];
      resolvedRequirementStepId = targetRequirement?.step_id || '';

      const updatedRequirements = requirements.map((item) => {
        if (!item || !item.step_id) {
          return item;
        }
        if (item.step_id !== resolvedRequirementStepId) {
          return item;
        }
        return {
          ...item,
          confirmed: shouldApprove,
          rejection_feedback: shouldApprove ? null : 'Rejected from frontend'
        };
      });
      continueParams.set('step_requirements', JSON.stringify(updatedRequirements));
    }

    const continueResponse = await fetch(
      `${backendUrl}/workflows/${encodeURIComponent(
        resolvedWorkflowId
      )}/runs/${encodeURIComponent(runId)}/continue`,
      {
        method: 'POST',
        headers: backendHeaders('application/x-www-form-urlencoded'),
        body: continueParams.toString()
      }
    );
    if (!continueResponse.ok) {
      const text = await continueResponse.text();
      return res.status(502).json({
        error: 'Failed to continue workflow after confirmation',
        details: clipText(text, 6000)
      });
    }

    let continueBody = {};
    if (isToolConfirmation) {
      drainBackendStream(continueResponse.body, `command approval ${runId}`);
    } else {
      continueBody = await continueResponse.json().catch(() => ({}));
    }

    const nextRunStatus = isStepUserInputMode
      ? 'user_input_submitted'
      : shouldApprove
      ? 'approved'
      : 'rejected';

    await saveWorkflowRun({
      userId: String(authUser.id || meta?.userId || meta?.user_id || ''),
      workflowId: resolvedWorkflowId,
      runId,
      sessionId: resolvedSessionId,
      status: nextRunStatus
    });

    return res.json({
      status: 'accepted',
      backendStatus: continueBody?.status || null,
      runId,
      run_id: runId,
      sessionId: resolvedSessionId,
      requirementStepId: resolvedRequirementStepId || requirementStepId || '',
      action: shouldApprove ? 'approved' : 'rejected'
    });
  } catch (error) {
    return res.status(502).json({
      error: 'Agent backend is unreachable',
      details: error.message
    });
  }
});

app.get('/api/fine-tune/:runId', async (req, res) => {
  const { runId } = req.params;
  const requestedSessionId = String(req.query?.sessionId || '').trim();
  const { baseUrl: backendUrl, workflowId: defaultWorkflowId } = getBackendConfig();

  if (backendUrl) {
    try {
      const mapMeta = realRuns.get(runId) || null;
      const dbMeta = mapMeta ? null : await getRunMeta(runId);
      const meta = mapMeta || dbMeta;
      const metaSessionId = String(meta?.sessionId || meta?.agno_session_id || '').trim();
      const candidateSessionIds = [];
      if (metaSessionId) {
        candidateSessionIds.push(metaSessionId);
      }
      if (requestedSessionId && requestedSessionId !== metaSessionId) {
        candidateSessionIds.push(requestedSessionId);
      }
      const resolvedWorkflowId = String(
        req.query?.workflowId || meta?.workflowId || meta?.workflow_id || defaultWorkflowId
      );
      if (!candidateSessionIds.length) {
        return res.status(400).json({
          error: 'sessionId is required for run status polling'
        });
      }

      let runResponse = null;
      let runBody = null;
      let resolvedSessionId = '';
      let lastStatus = 0;
      let lastBodyText = '';

      for (const candidateSessionId of candidateSessionIds) {
        const response = await fetch(
          `${backendUrl}/workflows/${encodeURIComponent(
            resolvedWorkflowId
          )}/runs/${encodeURIComponent(runId)}?session_id=${encodeURIComponent(candidateSessionId)}`,
          { headers: backendHeaders() }
        );
        if (response.ok) {
          runResponse = response;
          resolvedSessionId = candidateSessionId;
          break;
        }
        lastStatus = response.status;
        lastBodyText = await response.text();
        if (response.status !== 404) {
          break;
        }
      }

      if (!runResponse) {
        if (lastStatus === 404) {
          return res.status(404).json({
            error: 'Run not found on backend',
            details: clipText(lastBodyText || 'Run not found', 6000)
          });
        }
        return res.status(502).json({
          error: 'Agent backend status request failed',
          details: clipText(lastBodyText || 'Unknown backend error', 6000)
        });
      }

      runBody = await runResponse.json();
      if (!meta) {
        realRuns.set(runId, {
          runId,
          sessionId: resolvedSessionId,
          workflowId: resolvedWorkflowId,
          createdAt: Date.now()
        });
      }
      const mappedPayload = mapRunToFrontendPayload(runBody, {
        runId,
        sessionId: resolvedSessionId
      }, {
        ignoreStaleUserInputGate: String(meta?.status || '').toLowerCase() === 'user_input_submitted'
      });
      const mappedWorkflowGateMode = String(mappedPayload?.workflowGate?.mode || '').toLowerCase();
      const shouldPreserveSubmittedInputStatus =
        String(meta?.status || '').toLowerCase() === 'user_input_submitted' &&
        normalizeBackendStatus(runBody?.status) === 'paused' &&
        mappedWorkflowGateMode !== 'step_user_input';

      await saveWorkflowRun({
        userId: String(req.authUser?.id || meta?.userId || meta?.user_id || ''),
        workflowId: resolvedWorkflowId,
        runId,
        sessionId: resolvedSessionId,
        status: shouldPreserveSubmittedInputStatus ? 'user_input_submitted' : normalizeBackendStatus(runBody?.status)
      });

      return res.json(mappedPayload);
    } catch (error) {
      return res.status(502).json({
        error: 'Agent backend is unreachable',
        details: error.message
      });
    }
  }

  const state = getMockRunState(runId);
  if (!state) {
    return res.status(404).json({ error: 'Run not found' });
  }

  return res.json(state);
});

app.use((error, _req, res, next) => {
  if (error?.type === 'entity.too.large') {
    return res.status(413).json({
      error: 'Upload too large. Please use a smaller image.'
    });
  }
  return next(error);
});

app.use('/api', (_req, res) => {
  res.status(404).json({ error: 'API route not found' });
});

app.get('/login', (_req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/login.html', (_req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/signup', (_req, res) => {
  res.sendFile(path.join(__dirname, 'signup.html'));
});

app.get('/signup.html', (_req, res) => {
  res.sendFile(path.join(__dirname, 'signup.html'));
});

app.get('/aiprovider', (_req, res) => {
  res.sendFile(path.join(__dirname, 'aiprovider.html'));
});

app.get('/aiprovider.html', (_req, res) => {
  res.sendFile(path.join(__dirname, 'aiprovider.html'));
});

app.get('/webprovider', (_req, res) => {
  res.sendFile(path.join(__dirname, 'webprovider.html'));
});

app.get('/webprovider.html', (_req, res) => {
  res.sendFile(path.join(__dirname, 'webprovider.html'));
});

app.get('/siemprovider', (_req, res) => {
  res.sendFile(path.join(__dirname, 'siemprovider.html'));
});

app.get('/siemprovider.html', (_req, res) => {
  res.sendFile(path.join(__dirname, 'siemprovider.html'));
});

app.get('/siemconfig', (_req, res) => {
  res.sendFile(path.join(__dirname, 'siemconfig.html'));
});

app.get('/siemconfig.html', (_req, res) => {
  res.sendFile(path.join(__dirname, 'siemconfig.html'));
});

app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

async function startServer() {
  try {
    await ensureAppTables();
    await ensureBootstrapUser();
    app.listen(port, '0.0.0.0', () => {
      console.log(`Frontend running on http://0.0.0.0:${port}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

startServer();
