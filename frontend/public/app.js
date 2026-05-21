const rulesListEl = document.getElementById('rules-list');
const rulesEmptyMessageEl = document.getElementById('rules-empty-message');
const ruleIdChipEl = document.getElementById('rule-id-chip');
const ruleStatusChipEl = document.getElementById('rule-status-chip');
const ruleNameEl = document.getElementById('rule-name');
const ruleDescriptionEl = document.getElementById('rule-description');
const fineTuneBtnEl = document.getElementById('fine-tune-btn');
const fineTuneStatusEl = document.getElementById('fine-tune-status');
const agentBlockEl = document.getElementById('agent-block');
const agentSubtitleEl = document.getElementById('agent-subtitle');
const manualRuleIdEl = document.getElementById('manual-rule-id');
const manualRuleApplyEl = document.getElementById('manual-rule-apply');
const reportBoxEl = document.getElementById('report-box');
const activityListEl = document.getElementById('activity-list');
const reportModalEl = document.getElementById('report-modal');
const reportWindowBodyEl = document.getElementById('report-window-body');
const reportWindowCloseEl = document.getElementById('report-window-close');
const reportWindowDownloadEl = document.getElementById('report-window-download');
const reportWindowFooterEl = document.getElementById('report-window-footer');
const reportWindowGateMessageEl = document.getElementById('report-window-gate-message');
const reportWindowApproveEl = document.getElementById('report-window-approve');
const reportWindowRejectEl = document.getElementById('report-window-reject');
const reportWindowInputWrapEl = document.getElementById('report-window-input-wrap');
const reportWindowInputTextEl = document.getElementById('report-window-input-text');
const reportWindowSubmitInputEl = document.getElementById('report-window-submit-input');
const appShellEl = document.querySelector('.app-shell');
const sideCollapseBtnEl = document.getElementById('side-collapse-btn');
const sideCollapseIconEl = document.getElementById('side-collapse-icon');
const sideExpandBtnEl = document.getElementById('side-expand-btn');
const sideAvatarBtnEl = document.getElementById('side-avatar-btn');
const sideAvatarImageEl = document.getElementById('side-avatar-image');
const sideAvatarInitialEl = document.getElementById('side-avatar-initial');
const sideAvatarInputEl = document.getElementById('side-avatar-input');
const sideUserNameEl = document.getElementById('side-user-name');
const sideUserTitleEl = document.getElementById('side-user-title');
const sideSettingsBtnEl = document.getElementById('side-settings-btn');
const sideSignoutBtnEl = document.getElementById('side-signout-btn');
const settingsModalEl = document.getElementById('settings-modal');
const settingsCloseBtnEl = document.getElementById('settings-close-btn');
const settingsCancelBtnEl = document.getElementById('settings-cancel-btn');
const settingsSaveBtnEl = document.getElementById('settings-save-btn');
const settingsStatusEl = document.getElementById('settings-status');
const settingsAiProviderEl = document.getElementById('settings-ai-provider');
const settingsAiKeyEl = document.getElementById('settings-ai-key');
const settingsAiModelEl = document.getElementById('settings-ai-model');
const settingsAiModelHintEl = document.getElementById('settings-ai-model-hint');
const settingsLoadModelsBtnEl = document.getElementById('settings-load-models-btn');
const settingsWebProviderEl = document.getElementById('settings-web-provider');
const settingsWebKeyEl = document.getElementById('settings-web-key');
const settingsSiemProviderEl = document.getElementById('settings-siem-provider');
const settingsIndexerUrlEl = document.getElementById('settings-indexer-url');
const settingsIndexerUserEl = document.getElementById('settings-indexer-user');
const settingsIndexerPassEl = document.getElementById('settings-indexer-pass');
const settingsManagerUrlEl = document.getElementById('settings-manager-url');
const settingsSshUserEl = document.getElementById('settings-ssh-user');
const settingsSshPortEl = document.getElementById('settings-ssh-port');
const settingsSshAuthModeEl = document.getElementById('settings-ssh-auth-mode');
const settingsSshPasswordWrapEl = document.getElementById('settings-ssh-password-wrap');
const settingsSshKeyWrapEl = document.getElementById('settings-ssh-key-wrap');
const settingsSshAuthEl = document.getElementById('settings-ssh-auth');
const settingsSshKeyTextEl = document.getElementById('settings-ssh-key-text');
const settingsSshImportBtnEl = document.getElementById('settings-ssh-import-btn');
const settingsSshKeyFileEl = document.getElementById('settings-ssh-key-file');
const settingsSshModeHintEl = document.getElementById('settings-ssh-mode-hint');
const settingsTestIndexerBtnEl = document.getElementById('settings-test-indexer-btn');
const settingsIndexerTestStatusEl = document.getElementById('settings-indexer-test-status');
const settingsTestManagerBtnEl = document.getElementById('settings-test-manager-btn');
const settingsManagerTestStatusEl = document.getElementById('settings-manager-test-status');
const fineTuneBtnDefaultHtml = fineTuneBtnEl ? fineTuneBtnEl.innerHTML : '';

let rules = [];
let selectedRuleId = null;
let manualRule = null;
let pollTimer = null;
let activeStreamAbortController = null;
let streamReconnectTimer = null;
let streamReconnectAttempts = 0;
let lastStreamEventIndex = null;
let currentRunSessionId = '';
let hitlActionPending = false;
let hitlActionPendingSince = 0;
let currentRunId = '';
const seenStepIds = new Set();
const expandedStepDetails = new Set();
const expandedPayloadSteps = new Set();
let streamState = null;
let latestReport = null;
let currentWorkflowGate = null;
let currentCommandGate = null;
let commandHistory = [];
let workflowGateApproved = false;
let fulfilledUserInputGateRunId = '';
let awaitingPostUserInputRunId = '';
let lastStreamRenderAt = 0;
let autoFocusedRunningStepKey = '';
let currentAutoStepTransition = { expanded: '', collapsed: '' };
let autoTransitionResetTimer = null;
let streamTypingTimer = null;
const streamTypingState = new Map();
let lastRenderedRunId = '';
let lastRenderedActivity = [];
let lastRenderedCommandGate = null;
let lastPollingRenderSignature = '';
let gateHydrationInFlight = false;
const collapsedStreamBlocks = new Set();
let reportHydrationInFlight = false;
const SIDEBAR_COLLAPSED_KEY = 'ruleflow_sidebar_collapsed';
const ACTIVE_RUN_STORAGE_KEY = 'wazuh_active_fine_tune_run';
const HITL_PENDING_TIMEOUT_MS = 20000;
const AUTH_TOKEN_STORAGE_KEY = 'wazuh_auth_token';
let currentAuthUser = null;
let recommendationInputText = '';
let ruleSelectionLocked = false;
let settingsModelFetchSeq = 0;
let settingsModelDebounceTimer = null;
let settingsSaveInProgress = false;
let settingsSshAuthMode = 'password';
let settingsIndexerTestInProgress = false;
let settingsManagerTestInProgress = false;

const workflowTemplate = [
  { name: 'research_threat_hunting', title: 'Rule Hunting Agent', kind: 'tool_call' },
  { name: 'research_web_intel', title: 'Web Searcher Agent', kind: 'tool_result' },
  { name: 'final_report', title: 'Retrieval Agent', kind: 'synthesis' },
  { name: 'apply_detection_changes', title: 'Detection Engineer agent', kind: 'tool_call' }
];

const workflowTemplateByName = new Map(workflowTemplate.map((step, index) => [step.name, { ...step, index }]));

function getAuthToken() {
  try {
    return String(localStorage.getItem(AUTH_TOKEN_STORAGE_KEY) || '').trim();
  } catch (_error) {
    return '';
  }
}

function clearAuthToken() {
  try {
    localStorage.removeItem(AUTH_TOKEN_STORAGE_KEY);
  } catch (_error) {
    // ignore storage errors
  }
}

function redirectToLogin() {
  window.location.replace('/login');
}

const nativeFetch = window.fetch.bind(window);
window.fetch = function patchedFetch(input, init = {}) {
  let url = '';
  if (typeof input === 'string') {
    url = input;
  } else if (input && typeof input.url === 'string') {
    url = input.url;
  }

  const isApiRequest = url.startsWith('/api/') || url.includes('/api/');
  if (!isApiRequest) {
    return nativeFetch(input, init);
  }

  const token = getAuthToken();
  if (!token) {
    return nativeFetch(input, init);
  }

  const headers = new Headers(init?.headers || (input instanceof Request ? input.headers : undefined));
  if (!headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  return nativeFetch(input, { ...init, headers });
};

async function ensureAuthenticated() {
  const token = getAuthToken();
  if (!token) {
    redirectToLogin();
    throw new Error('Authentication required');
  }

  const response = await fetch('/api/auth/session');
  if (!response.ok) {
    clearAuthToken();
    redirectToLogin();
    throw new Error('Authentication required');
  }
  const payload = await response.json().catch(() => ({}));
  const onboardingNextPath = String(payload?.onboarding?.nextPath || '/');
  if (onboardingNextPath && onboardingNextPath !== '/') {
    window.location.replace(onboardingNextPath);
    throw new Error('Onboarding not completed');
  }
  currentAuthUser = payload?.user || null;
}

function getInitialFromName(name) {
  const safe = String(name || '').trim();
  if (!safe) {
    return 'U';
  }
  return safe[0].toUpperCase();
}

function renderSidebarUser(user = {}) {
  const username = String(user.username || '').trim() || 'User';
  const jobTitle = String(user.jobTitle || '').trim() || 'Security Analyst';
  const avatarDataUrl = String(user.avatarDataUrl || '').trim();

  if (sideUserNameEl) {
    sideUserNameEl.textContent = username;
  }
  if (sideUserTitleEl) {
    sideUserTitleEl.textContent = jobTitle;
  }

  if (!sideAvatarImageEl || !sideAvatarInitialEl) {
    return;
  }
  if (avatarDataUrl) {
    sideAvatarImageEl.src = avatarDataUrl;
    sideAvatarImageEl.classList.remove('hidden');
    sideAvatarInitialEl.classList.add('hidden');
    return;
  }
  sideAvatarImageEl.removeAttribute('src');
  sideAvatarImageEl.classList.add('hidden');
  sideAvatarInitialEl.classList.remove('hidden');
  sideAvatarInitialEl.textContent = getInitialFromName(username);
}

async function loadUserProfile() {
  const response = await fetch('/api/auth/profile');
  if (!response.ok) {
    throw new Error('Failed to load user profile.');
  }
  const payload = await response.json().catch(() => ({}));
  const user = payload?.user || currentAuthUser || {};
  currentAuthUser = { ...(currentAuthUser || {}), ...user };
  renderSidebarUser(currentAuthUser);
}

function setSettingsStatus(message, isError = false) {
  if (!settingsStatusEl) {
    return;
  }
  settingsStatusEl.textContent = String(message || '');
  settingsStatusEl.style.color = isError ? '#ba1a1a' : '#64748b';
}

function setSettingsInlineTestStatus(targetEl, message, tone = 'neutral') {
  if (!targetEl) {
    return;
  }
  targetEl.textContent = String(message || '');
  if (tone === 'error') {
    targetEl.style.color = '#ba1a1a';
    return;
  }
  if (tone === 'success') {
    targetEl.style.color = '#0f766e';
    return;
  }
  targetEl.style.color = '#64748b';
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

function readSettingsSshAuthValue(mode = settingsSshAuthMode) {
  if (normalizeSshAuthMode(mode) === 'key_file') {
    return normalizeSshPrivateKeyText(settingsSshKeyTextEl?.value || '');
  }
  return String(settingsSshAuthEl?.value || '').trim();
}

function setSettingsSshAuthMode(mode) {
  settingsSshAuthMode = normalizeSshAuthMode(mode);
  if (settingsSshAuthModeEl) {
    settingsSshAuthModeEl.value = settingsSshAuthMode;
  }
  if (settingsSshPasswordWrapEl) {
    settingsSshPasswordWrapEl.classList.toggle('hidden', settingsSshAuthMode === 'key_file');
  }
  if (settingsSshKeyWrapEl) {
    settingsSshKeyWrapEl.classList.toggle('hidden', settingsSshAuthMode !== 'key_file');
  }
  if (!settingsSshModeHintEl) {
    return;
  }
  settingsSshModeHintEl.textContent =
    settingsSshAuthMode === 'key_file'
      ? 'Auth mode: key file uploaded'
      : 'Auth mode: password';
}

function setSettingsModalVisible(visible) {
  if (!settingsModalEl) {
    return;
  }
  settingsModalEl.classList.toggle('hidden', !visible);
  settingsModalEl.setAttribute('aria-hidden', visible ? 'false' : 'true');
}

function setSettingsModelOptions(models = [], preferredModelId = '') {
  if (!settingsAiModelEl) {
    return;
  }
  const list = Array.isArray(models) ? models : [];
  settingsAiModelEl.innerHTML = '';

  const placeholder = document.createElement('option');
  placeholder.value = '';
  placeholder.textContent = list.length ? 'Choose model' : 'No models found';
  settingsAiModelEl.appendChild(placeholder);

  list.forEach((model) => {
    const id = String(model?.id || '').trim();
    if (!id) {
      return;
    }
    const option = document.createElement('option');
    option.value = id;
    option.textContent = String(model?.name || id).trim() || id;
    settingsAiModelEl.appendChild(option);
  });

  if (preferredModelId) {
    const exists = Array.from(settingsAiModelEl.options).some((opt) => opt.value === preferredModelId);
    if (exists) {
      settingsAiModelEl.value = preferredModelId;
    }
  }
}

async function fetchOnboardingStatusPayload() {
  const response = await fetch('/api/onboarding/status');
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.error || 'Failed to load user settings.');
  }
  return payload;
}

function fillSettingsForm(setup = {}) {
  if (settingsAiProviderEl) settingsAiProviderEl.value = String(setup.aiProvider || 'openai').trim() || 'openai';
  if (settingsAiKeyEl) settingsAiKeyEl.value = String(setup.aiApiKey || '').trim();
  if (settingsWebProviderEl) settingsWebProviderEl.value = String(setup.webProvider || 'tavily').trim() || 'tavily';
  if (settingsWebKeyEl) settingsWebKeyEl.value = String(setup.webApiKey || '').trim();
  if (settingsSiemProviderEl) settingsSiemProviderEl.value = String(setup.siemProvider || 'wazuh').trim() || 'wazuh';

  const siem = setup.siemConfig || {};
  if (settingsIndexerUrlEl) settingsIndexerUrlEl.value = String(siem.indexerUrl || '').trim();
  if (settingsIndexerUserEl) settingsIndexerUserEl.value = String(siem.indexerUser || '').trim();
  if (settingsIndexerPassEl) settingsIndexerPassEl.value = String(siem.indexerPass || '').trim();
  if (settingsManagerUrlEl) settingsManagerUrlEl.value = String(siem.managerUrl || '').trim();
  if (settingsSshUserEl) settingsSshUserEl.value = String(siem.sshUser || '').trim();
  if (settingsSshPortEl) settingsSshPortEl.value = Number(siem.sshPort || 22) || 22;
  if (settingsSshAuthEl) settingsSshAuthEl.value = '';
  if (settingsSshKeyTextEl) settingsSshKeyTextEl.value = '';
  const preferredMode = normalizeSshAuthMode(siem.sshAuthMode || '');
  const authValueRaw = String(siem.sshAuth || '');
  const authValue = preferredMode === 'key_file' ? normalizeSshPrivateKeyText(authValueRaw) : authValueRaw.trim();
  if (preferredMode === 'key_file') {
    if (settingsSshKeyTextEl) settingsSshKeyTextEl.value = authValue;
  } else if (settingsSshAuthEl) {
    settingsSshAuthEl.value = authValue;
  }
  if (preferredMode === 'key_file') {
    setSettingsSshAuthMode('key_file');
  } else if (/BEGIN [A-Z ]*PRIVATE KEY/.test(authValueRaw)) {
    setSettingsSshAuthMode('key_file');
    if (settingsSshKeyTextEl) settingsSshKeyTextEl.value = normalizeSshPrivateKeyText(authValueRaw);
  } else {
    setSettingsSshAuthMode('password');
  }
}

async function loadSettingsModels(preferredModelId = '') {
  const aiProvider = String(settingsAiProviderEl?.value || '').trim();
  const aiApiKey = String(settingsAiKeyEl?.value || '').trim();
  if (!aiProvider || !aiApiKey) {
    setSettingsModelOptions([], '');
    if (settingsAiModelHintEl) {
      settingsAiModelHintEl.textContent = 'Enter provider API key to load models.';
    }
    return;
  }

  const seq = ++settingsModelFetchSeq;
  if (settingsAiModelHintEl) {
    settingsAiModelHintEl.textContent = 'Loading models...';
  }
  setSettingsModelOptions([], '');

  const response = await fetch('/api/onboarding/ai-models', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ aiProvider, aiApiKey })
  });
  const payload = await response.json().catch(() => ({}));

  if (seq !== settingsModelFetchSeq) {
    return;
  }
  if (!response.ok) {
    throw new Error(payload.error || 'Failed to load models.');
  }

  const models = Array.isArray(payload.models) ? payload.models : [];
  setSettingsModelOptions(models, preferredModelId);
  if (settingsAiModelHintEl) {
    settingsAiModelHintEl.textContent = models.length ? `${models.length} models loaded.` : 'No models found.';
  }
}

function scheduleSettingsModelLoad() {
  if (settingsModelDebounceTimer) {
    clearTimeout(settingsModelDebounceTimer);
  }
  settingsModelDebounceTimer = setTimeout(() => {
    loadSettingsModels(String(settingsAiModelEl?.value || '').trim()).catch((error) => {
      if (settingsAiModelHintEl) {
        settingsAiModelHintEl.textContent = error.message;
      }
    });
  }, 450);
}

async function openSettingsModal() {
  if (!settingsModalEl) {
    return;
  }
  setSettingsStatus('');
  setSettingsInlineTestStatus(settingsIndexerTestStatusEl, '', 'neutral');
  setSettingsInlineTestStatus(settingsManagerTestStatusEl, '', 'neutral');
  setSettingsModalVisible(true);

  try {
    const payload = await fetchOnboardingStatusPayload();
    const setup = payload?.setup || {};
    fillSettingsForm(setup);
    await loadSettingsModels(String(setup.aiModelId || '').trim());
  } catch (error) {
    setSettingsStatus(error.message || 'Failed to load settings.', true);
  }
}

function closeSettingsModal() {
  setSettingsModalVisible(false);
  setSettingsInlineTestStatus(settingsIndexerTestStatusEl, '', 'neutral');
  setSettingsInlineTestStatus(settingsManagerTestStatusEl, '', 'neutral');
}

function readSettingsForm() {
  const mode = normalizeSshAuthMode(settingsSshAuthModeEl?.value || settingsSshAuthMode);
  const sshAuthRaw = readSettingsSshAuthValue(mode);
  const inferredMode = /BEGIN [A-Z ]*PRIVATE KEY/.test(sshAuthRaw) ? 'key_file' : mode;
  return {
    aiProvider: String(settingsAiProviderEl?.value || '').trim().toLowerCase(),
    aiApiKey: String(settingsAiKeyEl?.value || '').trim(),
    aiModelId: String(settingsAiModelEl?.value || '').trim(),
    webProvider: String(settingsWebProviderEl?.value || '').trim().toLowerCase(),
    webApiKey: String(settingsWebKeyEl?.value || '').trim(),
    siemProvider: String(settingsSiemProviderEl?.value || '').trim().toLowerCase(),
    indexerUrl: String(settingsIndexerUrlEl?.value || '').trim(),
    indexerUser: String(settingsIndexerUserEl?.value || '').trim(),
    indexerPass: String(settingsIndexerPassEl?.value || '').trim(),
    managerUrl: String(settingsManagerUrlEl?.value || '').trim(),
    sshUser: String(settingsSshUserEl?.value || '').trim(),
    sshPort: Number(settingsSshPortEl?.value || 22),
    sshAuth: sshAuthRaw,
    sshAuthMode: normalizeSshAuthMode(inferredMode)
  };
}

function setSettingsSavingState(isSaving) {
  settingsSaveInProgress = Boolean(isSaving);
  if (settingsSaveBtnEl) {
    settingsSaveBtnEl.disabled = settingsSaveInProgress;
    settingsSaveBtnEl.textContent = settingsSaveInProgress ? 'Saving...' : 'Save Changes';
  }
}

async function saveSettingsFromModal() {
  if (settingsSaveInProgress) {
    return;
  }
  const form = readSettingsForm();

  if (!form.aiProvider || !form.aiApiKey || !form.aiModelId) {
    setSettingsStatus('AI provider, key, and model are required.', true);
    return;
  }
  if (!form.webProvider || !form.webApiKey) {
    setSettingsStatus('Web provider and web API key are required.', true);
    return;
  }
  if (
    !form.siemProvider ||
    !form.indexerUrl ||
    !form.indexerUser ||
    !form.indexerPass ||
    !form.managerUrl ||
    !form.sshUser ||
    !form.sshAuth ||
    !Number.isFinite(form.sshPort) ||
    form.sshPort <= 0
  ) {
    setSettingsStatus('All SIEM fields are required and SSH port must be valid.', true);
    return;
  }

  setSettingsSavingState(true);
  setSettingsStatus('Saving settings...');
  try {
    let response = await fetch('/api/onboarding/ai-provider', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        aiProvider: form.aiProvider,
        aiApiKey: form.aiApiKey,
        aiModelId: form.aiModelId
      })
    });
    let payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload.error || 'Failed to save AI provider settings.');
    }

    response = await fetch('/api/onboarding/web-provider', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        webProvider: form.webProvider,
        webApiKey: form.webApiKey
      })
    });
    payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload.error || 'Failed to save web provider settings.');
    }

    response = await fetch('/api/onboarding/siem-provider', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        siemProvider: form.siemProvider
      })
    });
    payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload.error || 'Failed to save SIEM provider settings.');
    }

    response = await fetch('/api/onboarding/siem-config', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        indexerUrl: form.indexerUrl,
        indexerUser: form.indexerUser,
        indexerPass: form.indexerPass,
        managerUrl: form.managerUrl,
        sshUser: form.sshUser,
        sshPort: form.sshPort,
        sshAuth: form.sshAuth,
        sshAuthMode: form.sshAuthMode
      })
    });
    payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload.error || 'Failed to save SIEM configuration.');
    }

    await loadRules();
    setSettingsStatus('Settings saved successfully.');
    setTimeout(() => {
      closeSettingsModal();
      setSettingsStatus('');
    }, 450);
  } catch (error) {
    setSettingsStatus(error.message || 'Failed to save settings.', true);
  } finally {
    setSettingsSavingState(false);
  }
}

async function testSettingsIndexerConnection() {
  if (settingsIndexerTestInProgress) {
    return;
  }
  const indexerUrl = String(settingsIndexerUrlEl?.value || '').trim();
  const indexerUser = String(settingsIndexerUserEl?.value || '').trim();
  const indexerPass = String(settingsIndexerPassEl?.value || '').trim();

  if (!indexerUrl || !indexerUser || !indexerPass) {
    setSettingsInlineTestStatus(
      settingsIndexerTestStatusEl,
      'Need indexer URL, user, and password.',
      'error'
    );
    return;
  }

  settingsIndexerTestInProgress = true;
  if (settingsTestIndexerBtnEl) {
    settingsTestIndexerBtnEl.disabled = true;
    settingsTestIndexerBtnEl.innerHTML = '<span class="settings-test-spinner"></span>Testing';
  }
  setSettingsInlineTestStatus(settingsIndexerTestStatusEl, 'Testing indexer...', 'neutral');

  try {
    const response = await fetch('/api/settings/test-indexer', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ indexerUrl, indexerUser, indexerPass })
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload.error || 'Indexer connection failed.');
    }
    setSettingsInlineTestStatus(
      settingsIndexerTestStatusEl,
      payload.message || 'Indexer connection successful.',
      'success'
    );
  } catch (error) {
    setSettingsInlineTestStatus(
      settingsIndexerTestStatusEl,
      error.message || 'Indexer connection failed.',
      'error'
    );
  } finally {
    settingsIndexerTestInProgress = false;
    if (settingsTestIndexerBtnEl) {
      settingsTestIndexerBtnEl.disabled = false;
      settingsTestIndexerBtnEl.textContent = 'Test Indexer';
    }
  }
}

async function testSettingsManagerConnection() {
  if (settingsManagerTestInProgress) {
    return;
  }
  const managerUrl = String(settingsManagerUrlEl?.value || '').trim();
  const sshPort = Number(settingsSshPortEl?.value || 22);
  const sshUser = String(settingsSshUserEl?.value || '').trim();
  const sshAuthMode = normalizeSshAuthMode(settingsSshAuthModeEl?.value || settingsSshAuthMode);
  const sshAuth = readSettingsSshAuthValue(sshAuthMode);
  if (!managerUrl || !Number.isFinite(sshPort) || sshPort <= 0) {
    setSettingsInlineTestStatus(
      settingsManagerTestStatusEl,
      'Need manager URL/IP and valid SSH port.',
      'error'
    );
    return;
  }
  if (!sshUser || !sshAuth) {
    setSettingsInlineTestStatus(
      settingsManagerTestStatusEl,
      'Need SSH user and authentication value.',
      'error'
    );
    return;
  }

  settingsManagerTestInProgress = true;
  if (settingsTestManagerBtnEl) {
    settingsTestManagerBtnEl.disabled = true;
    settingsTestManagerBtnEl.innerHTML = '<span class="settings-test-spinner"></span>Testing';
  }
  setSettingsInlineTestStatus(settingsManagerTestStatusEl, 'Testing SSH login...', 'neutral');

  try {
    const response = await fetch('/api/settings/test-manager', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ managerUrl, sshPort, sshUser, sshAuth, sshAuthMode })
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload.error || 'Manager connection failed.');
    }
    setSettingsInlineTestStatus(
      settingsManagerTestStatusEl,
      payload.message || 'Manager SSH login successful.',
      'success'
    );
  } catch (error) {
    setSettingsInlineTestStatus(
      settingsManagerTestStatusEl,
      error.message || 'Manager connection failed.',
      'error'
    );
  } finally {
    settingsManagerTestInProgress = false;
    if (settingsTestManagerBtnEl) {
      settingsTestManagerBtnEl.disabled = false;
      settingsTestManagerBtnEl.textContent = 'Test Manager';
    }
  }
}

async function handleSettingsSshKeyUpload(file) {
  if (!file) {
    return;
  }
  const name = String(file.name || '').toLowerCase();
  if (!name.endsWith('.key') && !name.endsWith('.pem')) {
    throw new Error('Please upload a .key or .pem file.');
  }
  const text = await file.text();
  const keyText = normalizeSshPrivateKeyText(text);
  if (!keyText) {
    throw new Error('Uploaded key file is empty.');
  }
  if (settingsSshKeyTextEl) {
    settingsSshKeyTextEl.value = keyText;
  }
  setSettingsSshAuthMode('key_file');
}

async function imageFileToAvatarDataUrl(file) {
  const originalDataUrl = await new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result || ''));
    reader.onerror = () => reject(new Error('Failed to read image file.'));
    reader.readAsDataURL(file);
  });

  const image = await new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => resolve(img);
    img.onerror = () => reject(new Error('Invalid image file.'));
    img.src = originalDataUrl;
  });

  const maxSize = 256;
  const scale = Math.min(1, maxSize / Math.max(image.width || 1, image.height || 1));
  const width = Math.max(1, Math.round((image.width || 1) * scale));
  const height = Math.max(1, Math.round((image.height || 1) * scale));

  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext('2d');
  if (!ctx) {
    return originalDataUrl;
  }
  ctx.drawImage(image, 0, 0, width, height);

  let compressed = canvas.toDataURL('image/jpeg', 0.82);
  if (compressed.length > 1_500_000) {
    compressed = canvas.toDataURL('image/jpeg', 0.7);
  }
  return compressed;
}

async function uploadAvatarFromFile(file) {
  if (!file) {
    return;
  }
  if (!String(file.type || '').startsWith('image/')) {
    fineTuneStatusEl.textContent = 'Please upload an image file.';
    return;
  }
  const dataUrl = await imageFileToAvatarDataUrl(file);
  const response = await fetch('/api/auth/profile', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ avatarDataUrl: dataUrl })
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.error || 'Failed to upload avatar.');
  }
  currentAuthUser = { ...(currentAuthUser || {}), ...(payload.user || {}) };
  renderSidebarUser(currentAuthUser);
}

function splitGates(payload = {}) {
  const workflowGate = payload?.workflowGate || null;
  const commandGate = payload?.commandGate || null;
  if (workflowGate || commandGate) {
    return { workflowGate, commandGate };
  }

  const fallbackGate = payload?.gate || null;
  if (!fallbackGate?.pending) {
    return { workflowGate: null, commandGate: null };
  }
  if (fallbackGate.mode === 'tool_confirmation') {
    return { workflowGate: null, commandGate: fallbackGate };
  }
  return { workflowGate: fallbackGate, commandGate: null };
}

function isStepUserInputGate(gate) {
  return Boolean(gate?.pending) && String(gate?.mode || '').toLowerCase() === 'step_user_input';
}

function shouldIgnoreStaleUserInputGate(runId, workflowGate, commandGate) {
  return (
    Boolean(runId) &&
    fulfilledUserInputGateRunId === String(runId) &&
    isStepUserInputGate(workflowGate) &&
    !commandGate?.pending
  );
}

function preserveLiveCommandGate(runId, workflowGate, commandGate) {
  if (!shouldIgnoreStaleUserInputGate(runId, workflowGate, commandGate)) {
    return { workflowGate, commandGate };
  }
  if (currentCommandGate?.pending) {
    return { workflowGate: null, commandGate: currentCommandGate };
  }
  return { workflowGate: null, commandGate: null };
}

function isHitlActionLocked() {
  if (!hitlActionPending) {
    return false;
  }
  if (
    hitlActionPendingSince > 0 &&
    Date.now() - hitlActionPendingSince > HITL_PENDING_TIMEOUT_MS
  ) {
    hitlActionPending = false;
    hitlActionPendingSince = 0;
    return false;
  }
  return true;
}

function beginHitlAction() {
  hitlActionPending = true;
  hitlActionPendingSince = Date.now();
}

function endHitlAction() {
  hitlActionPending = false;
  hitlActionPendingSince = 0;
}

function readRunContextFromUrl() {
  try {
    const url = new URL(window.location.href);
    const runId = String(url.searchParams.get('runId') || '').trim();
    const sessionId = String(url.searchParams.get('sessionId') || '').trim();
    const rawLastEventIndex = url.searchParams.get('lastEventIndex');
    if (runId && sessionId) {
      return {
        runId,
        sessionId,
        source: 'url',
        lastEventIndex: Number.isFinite(Number(rawLastEventIndex))
          ? Number(rawLastEventIndex)
          : null
      };
    }
  } catch (_error) {
    // ignore url parsing errors and fall back to local storage
  }

  try {
    const raw = localStorage.getItem(ACTIVE_RUN_STORAGE_KEY);
    if (!raw) {
      return null;
    }
    const parsed = JSON.parse(raw);
    const runId = String(parsed?.runId || '').trim();
    const sessionId = String(parsed?.sessionId || '').trim();
    if (!runId || !sessionId) {
      return null;
    }
    return {
      runId,
      sessionId,
      source: 'storage',
      lastEventIndex: Number.isFinite(Number(parsed?.lastEventIndex))
        ? Number(parsed.lastEventIndex)
        : null
    };
  } catch (_error) {
    return null;
  }
}

function writeRunContextToUrl(runId, sessionId) {
  const normalizedRunId = String(runId || '').trim();
  const normalizedSessionId = String(sessionId || '').trim();
  if (!normalizedRunId || !normalizedSessionId) {
    return;
  }

  try {
    const url = new URL(window.location.href);
    url.searchParams.set('runId', normalizedRunId);
    url.searchParams.set('sessionId', normalizedSessionId);
    if (Number.isFinite(Number(lastStreamEventIndex))) {
      url.searchParams.set('lastEventIndex', String(Number(lastStreamEventIndex)));
    } else {
      url.searchParams.delete('lastEventIndex');
    }
    window.history.replaceState(null, '', url.toString());
  } catch (_error) {
    // ignore url mutation errors
  }
}

function clearRunContextFromUrl() {
  try {
    const url = new URL(window.location.href);
    url.searchParams.delete('runId');
    url.searchParams.delete('sessionId');
    window.history.replaceState(null, '', url.toString());
  } catch (_error) {
    // ignore url mutation errors
  }
}

function clearPersistedRunContext() {
  clearRunContextFromUrl();
  try {
    localStorage.removeItem(ACTIVE_RUN_STORAGE_KEY);
  } catch (_error) {
    // ignore storage errors
  }
}

function persistRunContext() {
  if (!currentRunId || !currentRunSessionId) {
    return;
  }
  try {
    localStorage.setItem(
      ACTIVE_RUN_STORAGE_KEY,
      JSON.stringify({
        runId: currentRunId,
        sessionId: currentRunSessionId,
        lastEventIndex: lastStreamEventIndex,
        updatedAt: Date.now()
      })
    );
  } catch (_error) {
    // ignore storage errors
  }
}

function setRunContext(runIdValue = '', sessionIdValue = '', options = {}) {
  const runId = String(runIdValue || '').trim();
  const sessionId = String(sessionIdValue || '').trim();
  if (runId) {
    currentRunId = runId;
    if (streamState) {
      streamState.runId = runId;
    }
  }
  if (sessionId) {
    currentRunSessionId = sessionId;
    if (streamState) {
      streamState.sessionId = sessionId;
    }
  }
  if (options?.persist !== false) {
    persistRunContext();
    writeRunContextToUrl(currentRunId, currentRunSessionId);
  }
}

function gateRenderKey(gate) {
  if (!gate || !gate.pending) {
    return '';
  }
  return [
    gate.mode || '',
    gate.stepName || '',
    gate.requirementStepId || '',
    gate.toolCallId || '',
    gate.approvalId || '',
    gate.commandPreview || '',
    gate.message || ''
  ].join('|');
}

function buildPollingRenderSignature(payload, activity, workflowGate, commandGate) {
  const steps = Array.isArray(activity)
    ? activity.map((step) => ({
        id: step?.id || '',
        status: step?.status || '',
        detail: step?.detail || '',
        toolName: step?.toolName || '',
        toolCalls: Array.isArray(step?.toolCalls)
          ? step.toolCalls.map((tool) => ({
              id: tool?.id || '',
              status: tool?.status || '',
              name: tool?.name || '',
              result: typeof tool?.result === 'string' ? tool.result.slice(0, 120) : ''
            }))
          : []
      }))
    : [];
  return JSON.stringify({
    status: normalizeRunStatus(payload?.status),
    stage: payload?.stage || '',
    phaseLabel: payload?.phaseLabel || '',
    reportReady: Boolean(payload?.reportReady || payload?.report_ready),
    workflowGate: gateRenderKey(workflowGate),
    commandGate: gateRenderKey(commandGate),
    activity: steps
  });
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function clipText(value, maxLen = 600) {
  const text = String(value || '');
  return text.length > maxLen ? `${text.slice(0, maxLen)}...` : text;
}

function buildWaveStyle(isRunning) {
  if (!isRunning) {
    return '';
  }
  const durationSec = 2.5;
  const phase = (Date.now() / 1000) % durationSec;
  const delay = -phase.toFixed(3);
  return ` style="animation-delay:${delay}s"`;
}

function appendStreamChunk(previousValue, chunkValue) {
  const prev = String(previousValue || '');
  const chunk = String(chunkValue || '');
  if (!chunk.trim() && !chunk.includes('\n')) {
    return prev;
  }
  if (!prev) {
    return chunk;
  }
  if (prev.endsWith(chunk)) {
    return prev;
  }
  if (chunk.startsWith(prev)) {
    return chunk;
  }
  const tail = prev.slice(-800);
  if (tail.includes(chunk)) {
    return prev;
  }
  const overlapMax = Math.min(prev.length, chunk.length, 600);
  for (let size = overlapMax; size >= 20; size -= 1) {
    if (prev.endsWith(chunk.slice(0, size))) {
      return prev + chunk.slice(size);
    }
  }
  return prev + chunk;
}

function setRuleSelectionLocked(locked) {
  ruleSelectionLocked = Boolean(locked);
  if (!rulesListEl) {
    return;
  }
  rulesListEl.classList.toggle('is-locked', ruleSelectionLocked);
}

function extractCommandPreview(value) {
  if (!value) {
    return '';
  }
  if (typeof value === 'string') {
    return value;
  }
  if (typeof value === 'object' && typeof value.command === 'string') {
    return value.command;
  }
  return '';
}

function extractCommandFromToolInput(value) {
  if (!value) {
    return '';
  }
  if (typeof value === 'object' && typeof value.command === 'string') {
    return value.command;
  }
  if (typeof value === 'string') {
    const raw = value.trim();
    if (!raw) {
      return '';
    }
    try {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object' && typeof parsed.command === 'string') {
        return parsed.command;
      }
    } catch (_error) {
      // keep raw string fallback
    }
    return raw;
  }
  return '';
}

function asPretty(value) {
  if (value === undefined || value === null) {
    return '';
  }

  if (typeof value === 'string') {
    return value;
  }

  try {
    return JSON.stringify(value, null, 2);
  } catch (_error) {
    return String(value);
  }
}

function compactToolValue(value, maxLen = 120000) {
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

function extractStepResponse(step) {
  if (!step || typeof step !== 'object') {
    return null;
  }
  const direct =
    step?.stepResponse ??
    step?.step_response ??
    step?.response ??
    step?.output ??
    step?.outputText ??
    step?.content ??
    null;
  if (direct !== undefined && direct !== null && direct !== '') {
    return direct;
  }
  const hasToolCalls = Array.isArray(step?.toolCalls || step?.tool_calls)
    ? (step.toolCalls || step.tool_calls).length > 0
    : false;
  if (!hasToolCalls && step?.result !== undefined && step?.result !== null && step?.result !== '') {
    return step.result;
  }
  return null;
}

function toDisplayText(value) {
  if (value === undefined || value === null) {
    return '';
  }
  if (typeof value === 'string') {
    return value;
  }
  try {
    return JSON.stringify(value, null, 2);
  } catch (_error) {
    return String(value);
  }
}

function scheduleStreamTypingFrame() {
  if (streamTypingTimer) {
    return;
  }
  streamTypingTimer = setTimeout(() => {
    streamTypingTimer = null;
    if (patchStreamContentInPlace()) {
      return;
    }
    if (!Array.isArray(lastRenderedActivity) || !lastRenderedActivity.length) {
      return;
    }
    renderActivity(lastRenderedRunId, lastRenderedActivity, lastRenderedCommandGate);
  }, 42);
}

function patchStreamContentInPlace() {
  if (!streamState || !activityListEl) {
    return false;
  }
  let patched = false;
  for (const [stepName, stepState] of streamState.steps) {
    if (stepState.status !== 'running') {
      continue;
    }
    const streamTextRaw = toDisplayText(stepState.streamText || '').trim();
    if (!streamTextRaw) {
      continue;
    }
    const key = stepState.id || stepName;
    const streamKey = key + '::step';
    const streamText = getTypedStreamText(streamKey, streamTextRaw, true);
    const els = activityListEl.querySelectorAll('[data-stream-key="' + streamKey + '"]');
    if (els.length > 0) {
      els.forEach(function (el) { el.textContent = streamText; });
      patched = true;
    }
  }
  return patched;
}

function getTypedStreamText(streamId, fullText, isRunning) {
  const text = String(fullText || '');
  if (!text) {
    streamTypingState.delete(streamId);
    return '';
  }
  if (!isRunning) {
    streamTypingState.set(streamId, { text, shown: text.length, lastTs: Date.now() });
    return text;
  }

  const now = Date.now();
  const charsPerSecond = 140;
  let state = streamTypingState.get(streamId);
  if (!state || state.text !== text) {
    const existingShown = state ? Number(state.shown || 0) : 0;
    state = {
      text,
      shown: Math.min(existingShown, text.length),
      lastTs: now
    };
    streamTypingState.set(streamId, state);
  }

  const deltaMs = Math.max(0, now - Number(state.lastTs || now));
  state.lastTs = now;
  const advance = Math.max(1, Math.floor((deltaMs / 1000) * charsPerSecond));
  state.shown = Math.min(text.length, Number(state.shown || 0) + advance);
  if (state.shown < text.length) {
    scheduleStreamTypingFrame();
  }
  return text.slice(0, state.shown);
}

function splitRuleXmlBlocks(text) {
  const blocks = [];
  const source = String(text || '');
  const regex = /<rule\b[\s\S]*?<\/rule>/gi;
  let lastIndex = 0;
  let match = regex.exec(source);

  while (match) {
    if (match.index > lastIndex) {
      blocks.push({ type: 'text', content: source.slice(lastIndex, match.index) });
    }
    blocks.push({ type: 'xml', content: match[0] });
    lastIndex = regex.lastIndex;
    match = regex.exec(source);
  }

  if (lastIndex < source.length) {
    blocks.push({ type: 'text', content: source.slice(lastIndex) });
  }

  return blocks.length ? blocks : [{ type: 'text', content: source }];
}

function highlightXml(xmlText) {
  const escaped = escapeHtml(xmlText);
  return escaped.replace(
    /(&lt;\/?)([A-Za-z_][A-Za-z0-9:._-]*)([\s\S]*?)(\/?&gt;)/g,
    (_full, openPart, tagName, attrsPart, closePart) => {
      const attrs = attrsPart.replace(
        /([A-Za-z_:][A-Za-z0-9:._-]*)(=)(&quot;.*?&quot;)/g,
        '<span class="xml-attr">$1</span>$2<span class="xml-value">$3</span>'
      );
      return `${openPart}<span class="xml-tag">${tagName}</span>${attrs}${closePart}`;
    }
  );
}

function renderToolResult(value) {
  const text = toDisplayText(value);
  if (!text) {
    return '<pre class="tree-payload-value"></pre>';
  }

  const chunks = splitRuleXmlBlocks(text);
  const hasXml = chunks.some((chunk) => chunk.type === 'xml');
  if (!hasXml) {
    return `<pre class="tree-payload-value">${escapeHtml(text)}</pre>`;
  }

  const html = chunks
    .map((chunk) => {
      if (chunk.type === 'xml') {
        return `
          <div class="tree-code-block">
            <div class="tree-code-head">XML</div>
            <pre class="tree-code-content">${highlightXml(chunk.content)}</pre>
          </div>
        `;
      }
      const content = chunk.content.replace(/^\s+|\s+$/g, '');
      if (!content) {
        return '';
      }
      return `<div class="tree-result-text">${escapeHtml(content)}</div>`;
    })
    .join('');

  return `<div class="tree-result-mixed">${html}</div>`;
}

function currentRule() {
  if (manualRule) {
    return manualRule;
  }
  return rules.find((rule) => rule.id === selectedRuleId) || null;
}

function shortRuleId(ruleId) {
  return String(ruleId || '').replace(/^RUL-/i, '');
}

function normalizeManualRuleId(rawRuleId) {
  const trimmed = String(rawRuleId || '').trim();
  if (!trimmed) {
    return '';
  }
  const withoutPrefix = trimmed.replace(/^RUL-/i, '');
  return `RUL-${withoutPrefix}`;
}

function findRuleById(ruleId) {
  const normalizedTarget = normalizeManualRuleId(ruleId);
  return rules.find((rule) => normalizeManualRuleId(rule?.id) === normalizedTarget) || null;
}

async function fetchRuleById(ruleId) {
  const numericRuleId = shortRuleId(ruleId);
  const response = await fetch(`/api/rules/${encodeURIComponent(numericRuleId)}`);
  const contentType = response.headers.get('content-type') || '';
  if (!contentType.includes('application/json')) {
    throw new Error('Rule lookup API is unavailable. Restart backend and try again.');
  }
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.error || `Rule ${ruleId} not found.`);
  }
  if (!payload || typeof payload !== 'object' || !payload.rule) {
    throw new Error(`Rule ${ruleId} lookup failed.`);
  }
  return payload.rule;
}

function applySidebarCollapsed(isCollapsed) {
  if (!appShellEl) {
    return;
  }
  appShellEl.classList.toggle('sidebar-collapsed', Boolean(isCollapsed));
  document.body.classList.toggle('sidebar-collapsed', Boolean(isCollapsed));
  if (sideCollapseBtnEl) {
    sideCollapseBtnEl.setAttribute('aria-label', isCollapsed ? 'Expand sidebar' : 'Collapse sidebar');
  }
  if (sideCollapseIconEl) {
    sideCollapseIconEl.textContent = 'chevron_left';
  }
}

function normalizeRunStatus(status) {
  const normalized = String(status || '').toLowerCase();
  if (normalized === 'completed' || normalized === 'done') {
    return 'completed';
  }
  if (normalized === 'failed' || normalized === 'error') {
    return 'error';
  }
  if (normalized === 'paused') {
    return 'paused';
  }
  return 'running';
}

function normalizeActivity(activity) {
  if (!Array.isArray(activity)) {
    return [];
  }

  return activity.map((step, index) => {
    const status = String(step?.status || '').toLowerCase();
    const normalizedStatus =
      status === 'running' || status === 'pending' || status === 'done'
        ? status
        : 'done';

    return {
      id: step?.id || step?.key || `step-${index + 1}`,
      index: index + 1,
      title: step?.title || `Step ${index + 1}`,
      kind: step?.kind || 'agent_step',
      detail: step?.detail || step?.message || '',
      response: compactToolValue(extractStepResponse(step), 120000),
      status: normalizedStatus,
      toolName: step?.toolName || step?.tool || '',
      input: step?.input || step?.inputPreview || '',
      result: step?.result || step?.resultPreview || '',
      toolCalls: Array.isArray(step?.toolCalls || step?.tool_calls)
        ? (step.toolCalls || step.tool_calls).map((tool, toolIndex) => ({
            id: tool?.id || tool?.tool_call_id || `tool-${index + 1}-${toolIndex + 1}`,
            order: Number(tool?.order || tool?.sequence || toolIndex + 1) || toolIndex + 1,
            name: tool?.name || tool?.toolName || tool?.tool_name || 'tool_call',
            input: compactToolValue(tool?.input || tool?.tool_args || null),
            result: compactToolValue(tool?.result ?? null),
            status: (() => {
              const rawStatus = String(tool?.status || '').toLowerCase();
              if (rawStatus === 'running') {
                return 'running';
              }
              if (rawStatus === 'error') {
                return 'error';
              }
              if (rawStatus === 'rejected') {
                return 'rejected';
              }
              return 'done';
            })(),
            latencyMs: Number(tool?.latencyMs || tool?.latency || 0) || null
          }))
        : [],
      latencyMs: Number(step?.latencyMs || step?.latency || 0) || null,
      tokensIn: Number(step?.tokensIn || 0) || null,
      tokensOut: Number(step?.tokensOut || 0) || null
    };
  });
}

function summarizeStepText(content, fallback = 'Step completed.') {
  const text = clipText(content ?? '', 1600).replace(/\r/g, '').trim();
  if (!text) {
    return fallback;
  }

  const line = text
    .split('\n')
    .map((part) => part.trim())
    .find((part) => part.length > 0 && !part.startsWith('#') && !part.startsWith('```'));
  return clipText(line || text, 220);
}

function formatInlineMarkdown(text) {
  return escapeHtml(text)
    .replace(/`([^`]+)`/g, '<code class="md-code-inline">$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/\*([^*]+)\*/g, '<em>$1</em>');
}

function markdownToHtml(markdownText) {
  const raw = String(markdownText || '').replace(/\r/g, '');
  if (!raw.trim()) {
    return '<p class="md-p">No report content.</p>';
  }

  const codeBlocks = [];
  let content = raw.replace(/```([a-zA-Z0-9_-]*)\n([\s\S]*?)```/g, (_match, language, code) => {
    const token = `__CODE_BLOCK_${codeBlocks.length}__`;
    const langClass = language ? ` language-${escapeHtml(language)}` : '';
    codeBlocks.push(
      `<pre class="md-code-block"><code class="${langClass}">${escapeHtml(code)}</code></pre>`
    );
    return token;
  });

  const lines = content.split('\n');
  const html = [];
  let inUnorderedList = false;
  let inOrderedList = false;

  const closeLists = () => {
    if (inUnorderedList) {
      html.push('</ul>');
      inUnorderedList = false;
    }
    if (inOrderedList) {
      html.push('</ol>');
      inOrderedList = false;
    }
  };

  lines.forEach((line) => {
    const trimmed = line.trim();
    if (!trimmed) {
      closeLists();
      return;
    }

    const headingMatch = trimmed.match(/^(#{1,6})\s+(.*)$/);
    if (headingMatch) {
      closeLists();
      const level = headingMatch[1].length;
      html.push(
        `<h${level} class="md-h${level}">${formatInlineMarkdown(headingMatch[2])}</h${level}>`
      );
      return;
    }

    const unorderedMatch = trimmed.match(/^[-*]\s+(.*)$/);
    if (unorderedMatch) {
      if (!inUnorderedList) {
        closeLists();
        html.push('<ul class="md-list">');
        inUnorderedList = true;
      }
      html.push(`<li class="md-li">${formatInlineMarkdown(unorderedMatch[1])}</li>`);
      return;
    }

    const orderedMatch = trimmed.match(/^\d+\.\s+(.*)$/);
    if (orderedMatch) {
      if (!inOrderedList) {
        closeLists();
        html.push('<ol class="md-list">');
        inOrderedList = true;
      }
      html.push(`<li class="md-li">${formatInlineMarkdown(orderedMatch[1])}</li>`);
      return;
    }

    closeLists();
    html.push(`<p class="md-p">${formatInlineMarkdown(trimmed)}</p>`);
  });
  closeLists();

  let rendered = html.join('\n');
  codeBlocks.forEach((blockHtml, index) => {
    rendered = rendered.replace(`__CODE_BLOCK_${index}__`, blockHtml);
  });
  return rendered;
}

function collectUrlsFromValue(value, urls = []) {
  if (!value) {
    return urls;
  }
  if (typeof value === 'string') {
    const matches = value.match(/https?:\/\/[^\s"'<>]+/g);
    if (matches) {
      matches.forEach((url) => urls.push(url));
    }
    return urls;
  }
  if (Array.isArray(value)) {
    value.forEach((item) => collectUrlsFromValue(item, urls));
    return urls;
  }
  if (typeof value === 'object') {
    Object.values(value).forEach((item) => collectUrlsFromValue(item, urls));
  }
  return urls;
}

function extractWebsiteDomains(tool = {}) {
  const combinedUrls = []
    .concat(collectUrlsFromValue(tool.input))
    .concat(collectUrlsFromValue(tool.result));
  const domains = [];
  const seenDomains = new Set();

  combinedUrls.forEach((url) => {
    try {
      const domain = new URL(url).hostname.replace(/^www\./i, '').trim();
      if (!domain || seenDomains.has(domain)) {
        return;
      }
      seenDomains.add(domain);
      domains.push(domain);
    } catch (_error) {
      // ignore invalid urls
    }
  });

  return domains;
}

function shouldUseWebToolIcon(step, tool) {
  const toolName = String(tool?.name || '').toLowerCase();
  return toolName === 'tavily_search';
}

function isFinalReportTool(step, tool) {
  if (!step || !tool) {
    return false;
  }
  const stepId = String(step.id || '').toLowerCase();
  const toolName = String(tool.name || '').toLowerCase();
  return stepId === 'final_report' && toolName === 'create_final_report';
}

function renderReportWindowFooter() {
  if (!reportWindowFooterEl || !reportWindowGateMessageEl) {
    return;
  }
  const actionLocked = isHitlActionLocked();
  if (!currentWorkflowGate?.pending) {
    reportWindowFooterEl.classList.add('hidden');
    reportWindowFooterEl.classList.remove('attention-border');
    reportWindowGateMessageEl.textContent = '';
    if (reportWindowInputWrapEl) {
      reportWindowInputWrapEl.classList.add('hidden');
    }
    return;
  }

  const isUserInputGate = String(currentWorkflowGate?.mode || '').toLowerCase() === 'step_user_input';
  reportWindowFooterEl.classList.remove('hidden');
  reportWindowFooterEl.classList.add('attention-border');
  reportWindowGateMessageEl.textContent =
    currentWorkflowGate.message || 'Do I apply recommended detection rule inside Wazuh now?';
  if (reportWindowApproveEl) {
    reportWindowApproveEl.disabled = actionLocked || isUserInputGate;
    reportWindowApproveEl.classList.toggle('hidden', isUserInputGate);
  }
  if (reportWindowRejectEl) {
    reportWindowRejectEl.disabled = actionLocked || isUserInputGate;
    reportWindowRejectEl.classList.toggle('hidden', isUserInputGate);
  }
  if (reportWindowInputWrapEl) {
    reportWindowInputWrapEl.classList.toggle('hidden', !isUserInputGate);
    if (isUserInputGate) {
      if (reportWindowInputTextEl) {
        reportWindowInputTextEl.value = recommendationInputText;
        setTimeout(() => {
          if (
            reportWindowInputTextEl &&
            !reportModalEl?.classList.contains('hidden') &&
            String(currentWorkflowGate?.mode || '').toLowerCase() === 'step_user_input'
          ) {
            reportWindowInputTextEl.focus();
          }
        }, 0);
      }
    }
  }
  if (reportWindowSubmitInputEl) {
    reportWindowSubmitInputEl.disabled = actionLocked || !String(recommendationInputText || '').trim();
  }
}

function closeReportWindow() {
  if (!reportModalEl) {
    return;
  }
  reportModalEl.classList.add('hidden');
  reportModalEl.setAttribute('aria-hidden', 'true');
}

function openReportWindow() {
  if (!reportModalEl || !reportWindowBodyEl || !latestReport) {
    return;
  }
  reportWindowBodyEl.innerHTML = markdownToHtml(latestReport.markdown || '');
  renderReportWindowFooter();
  reportModalEl.classList.remove('hidden');
  reportModalEl.setAttribute('aria-hidden', 'false');
}

function toSafeFilename(value) {
  return String(value || '')
    .trim()
    .replace(/\s+/g, '_')
    .replace(/[^a-zA-Z0-9._-]/g, '')
    .slice(0, 80);
}

function downloadReportAsMarkdown() {
  if (!latestReport) {
    fineTuneStatusEl.textContent = 'Final report is not ready yet.';
    return;
  }
  const baseName = toSafeFilename(latestReport.title || 'Final_Report') || 'Final_Report';
  const ts = new Date().toISOString().slice(0, 10);
  const filename = `${baseName}_${ts}.md`;
  const blob = new Blob([latestReport.markdown || ''], {
    type: 'text/markdown;charset=utf-8'
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.style.display = 'none';
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 3000);
}

function createStreamStepState(step) {
  return {
    id: step.name,
    index: step.index + 1,
    title: step.title,
    kind: step.kind,
    detail: '',
    streamText: '',
    response: '',
    status: 'pending',
    toolName: '',
    toolCalls: [],
    input: null,
    result: null,
    latencyMs: null,
    tokensIn: null,
    tokensOut: null
  };
}

function createInitialStreamState() {
  const steps = new Map();
  workflowTemplate.forEach((step, index) => {
    steps.set(step.name, createStreamStepState({ ...step, index }));
  });
  return {
    runId: '',
    sessionId: '',
    lastEventIndex: null,
    status: 'running',
    phaseLabel: '',
    currentStepName: '',
    reportMarkdown: '',
    workflowGate: null,
    commandGate: null,
    stepNameByStepId: new Map(),
    steps
  };
}

async function hydrateRunFromSnapshot(options = {}) {
  const runId = String(options?.runId || streamState?.runId || currentRunId || '').trim();
  if (!runId || gateHydrationInFlight || reportHydrationInFlight) {
    return;
  }

  gateHydrationInFlight = true;
  reportHydrationInFlight = true;
  try {
    const query = currentRunSessionId ? `?sessionId=${encodeURIComponent(currentRunSessionId)}` : '';
    const response = await fetch(`/api/fine-tune/${encodeURIComponent(runId)}${query}`);
    if (!response.ok) {
      return;
    }
    const payload = await response.json().catch(() => ({}));
    setRunContext(
      payload.runId || payload.run_id || currentRunId || runId,
      payload.sessionId || payload.session_id || currentRunSessionId
    );

    const runStatus = normalizeRunStatus(payload.status);
    const rawActivity = normalizeActivity(payload.activity);
    let { workflowGate, commandGate } = splitGates(payload);
    if (runStatus === 'completed' || runStatus === 'error') {
      workflowGate = null;
      commandGate = null;
    } else {
      ({ workflowGate, commandGate } = preserveLiveCommandGate(runId, workflowGate, commandGate));
    }
    currentWorkflowGate = workflowGate;
    currentCommandGate = commandGate;
    applyPollingCommandStateFromActivity(rawActivity);

    const executorRuns = payload.step_executor_runs || payload.stepExecutorRuns || [];
    applyPollingCommandState(executorRuns);
    applyExecutorRunsCollection(executorRuns);

    const applyStepFromSnapshot = rawActivity.find((s) => s.id === 'apply_detection_changes');
    if (
      applyStepFromSnapshot &&
      (applyStepFromSnapshot.status === 'running' || applyStepFromSnapshot.status === 'done') &&
      !workflowGate?.pending
    ) {
      workflowGateApproved = true;
    }

    const activity = rawActivity.filter((step) => {
      if (step.id === 'apply_detection_changes' && !workflowGateApproved && step.status !== 'done') {
        return false;
      }
      return true;
    });

    if (streamState) {
      streamState.status = runStatus;
      streamState.workflowGate = workflowGate;
      streamState.commandGate = commandGate;
      if (workflowGate?.message || commandGate?.message) {
        streamState.phaseLabel = workflowGate?.message || commandGate?.message || streamState.phaseLabel;
      }
      const markdown = String(payload?.report?.markdown || '').trim();
      if (markdown) {
        streamState.reportMarkdown = clipText(markdown, 25000);
      }
    }

    if (workflowGate?.pending && String(workflowGate.mode || '').toLowerCase() === 'step_user_input') {
      fineTuneStatusEl.textContent = 'Workflow paused. Recommendation input required.';
    }
    if (runStatus === 'paused' && !workflowGate?.pending && commandGate?.pending) {
      fineTuneStatusEl.textContent = 'Workflow paused. Awaiting your confirmation.';
    }

    updateRunPresentation(payload, activity);
    renderActivity(currentRunId || runId, activity, commandGate);
    renderReport(Boolean(payload.reportReady || payload.report_ready) ? payload.report : null);
    renderReportWindowFooter();
  } catch (_error) {
    // Ignore hydration failures. Polling and later events will reconcile.
  } finally {
    gateHydrationInFlight = false;
    reportHydrationInFlight = false;
  }
}

function getStepByName(stepName) {
  if (!streamState || !stepName) {
    return null;
  }
  if (!streamState.steps.has(stepName)) {
    return null;
  }
  return streamState.steps.get(stepName);
}

function findToolCallOnStep(step, toolCallId = '') {
  if (!step || !toolCallId || !Array.isArray(step.toolCalls)) {
    return null;
  }
  return step.toolCalls.find((toolCall) => toolCall.id === toolCallId) || null;
}

function normalizeConfirmationAction(action) {
  const normalized = String(action || '')
    .trim()
    .toLowerCase();
  if (['reject', 'rejected', 'deny', 'denied', 'decline', 'declined', 'no'].includes(normalized)) {
    return 'reject';
  }
  return 'approve';
}

function normalizeToolIdPart(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80);
}

function pushCommandHistory(entry) {
  const id = entry?.toolCallId || entry?.id || `cmd-${commandHistory.length + 1}`;
  const existing = commandHistory.findIndex(
    (c) => c.toolCallId === id
  );
  if (existing >= 0) {
    commandHistory[existing] = { ...commandHistory[existing], ...entry, toolCallId: id };
  } else {
    commandHistory.push({ ...entry, toolCallId: id });
  }
}

function applyPollingCommandState(stepExecutorRuns) {
  if (!Array.isArray(stepExecutorRuns) || !streamState) {
    return;
  }
  const applyStep = getStepByName('apply_detection_changes');
  if (!applyStep) {
    return;
  }
  stepExecutorRuns.forEach((executorRun) => {
    if ((executorRun?.step_name || '') !== 'apply_detection_changes') {
      return;
    }
    const tools = Array.isArray(executorRun?.tools) ? executorRun.tools : [];
    tools.forEach((tool) => {
      const toolName = tool?.tool_name || tool?.name || '';
      if (toolName !== 'run_ssh_command') {
        return;
      }
      const toolCallId =
        tool?.tool_call_id ||
        tool?.approval_id ||
        tool?.id ||
        null;
      const command = extractCommandPreview(tool?.tool_args || null);
      const status = tool?.tool_call_error
        ? 'error'
        : (tool?.confirmed === true || tool?.confirmed === null && tool?.requires_confirmation === false)
        ? 'done'
        : (tool?.confirmed === false)
        ? 'rejected'
        : 'running';
      const result = tool?.result ?? null;
      pushCommandHistory({
        toolCallId,
        toolName: 'run_ssh_command',
        command,
        status,
        result
      });
    });
  });
}

function applyPollingCommandStateFromActivity(activity) {
  if (!Array.isArray(activity) || !activity.length) {
    return;
  }
  const applyStep = activity.find((step) => String(step?.id || '').toLowerCase() === 'apply_detection_changes');
  if (!applyStep || !Array.isArray(applyStep.toolCalls)) {
    return;
  }
  applyStep.toolCalls.forEach((tool) => {
    const toolName = tool?.name || tool?.tool_name || '';
    if (toolName !== 'run_ssh_command') {
      return;
    }
    const rawStatus = String(tool?.status || '').toLowerCase();
    const status =
      rawStatus === 'running'
        ? 'running'
        : rawStatus === 'error'
        ? 'error'
        : rawStatus === 'rejected'
        ? 'rejected'
        : 'done';
    pushCommandHistory({
      toolCallId: tool?.id || tool?.tool_call_id || null,
      toolName: 'run_ssh_command',
      command: extractCommandPreview(tool?.input || null),
      status,
      result: tool?.result ?? null
    });
  });
}

function addToolCallToStep(step, tool = {}, options = {}) {
  if (!step) {
    return null;
  }
  if (!Array.isArray(step.toolCalls)) {
    step.toolCalls = [];
  }
  const eventName = normalizeEventName(options?.eventName || '');
  const toolName = tool.tool_name || tool.name || 'tool_call';
  const toolInput = tool.tool_args || tool.input || null;
  const commandPreview = extractCommandPreview(toolInput);
  const fallbackId = [
    step.id || 'step',
    normalizeToolIdPart(toolName),
    normalizeToolIdPart(commandPreview || JSON.stringify(toolInput || {}))
  ]
    .filter(Boolean)
    .join('::');
  const explicitToolCallId =
    tool.tool_call_id ||
    tool.toolCallId ||
    tool.approval_id ||
    tool.approvalId ||
    tool.id ||
    '';
  const hasExplicitToolCallId = Boolean(String(explicitToolCallId).trim());
  const toolCallIdBase = hasExplicitToolCallId
    ? String(explicitToolCallId)
    : fallbackId || `${step.id || 'step'}::tool_call`;
  let toolCall = hasExplicitToolCallId ? findToolCallOnStep(step, toolCallIdBase) : null;

  if (!toolCall && !hasExplicitToolCallId && eventName === 'toolcallcompleted') {
    for (let i = step.toolCalls.length - 1; i >= 0; i -= 1) {
      const candidate = step.toolCalls[i];
      if (
        candidate &&
        candidate.name === toolName &&
        (candidate.status === 'running' || (!candidate.result && candidate.status !== 'done'))
      ) {
        toolCall = candidate;
        break;
      }
    }
  }

  if (!toolCall && !hasExplicitToolCallId && eventName !== 'toolcallstarted') {
    toolCall = findToolCallOnStep(step, toolCallIdBase);
  }

  if (!toolCall) {
    const sequentialSuffix = step.toolCalls.length + 1;
    const toolCallId = hasExplicitToolCallId
      ? toolCallIdBase
      : `${toolCallIdBase}::${sequentialSuffix}`;
    toolCall = {
      id: toolCallId,
      order: sequentialSuffix,
      name: toolName,
      input: compactToolValue(toolInput),
      result: compactToolValue(tool.result ?? null),
      preamble: compactToolValue(tool.preamble ?? null),
      status: 'running',
      latencyMs: null
    };
    step.toolCalls.push(toolCall);
  }
  return toolCall;
}

function normalizeEventName(value) {
  return String(value || '').replace(/[^A-Za-z0-9]/g, '').toLowerCase();
}

function eventNameMatches(eventName, baseName) {
  const normalizedEventName = normalizeEventName(eventName);
  const normalizedBaseName = normalizeEventName(baseName);
  return (
    normalizedEventName === normalizedBaseName ||
    normalizedEventName === `${normalizedBaseName}event`
  );
}

function extractToolArgsPayload(tool) {
  if (!tool || typeof tool !== 'object') {
    return null;
  }
  return tool.tool_args || tool.toolArgs || tool.arguments || tool.args || null;
}

function collectRequirementList(payload = {}) {
  const candidates = [
    payload?.step_requirements,
    payload?.requirements,
    payload?.active_requirements
  ];
  for (const list of candidates) {
    if (Array.isArray(list) && list.length) {
      return list;
    }
  }
  if (Array.isArray(payload?.executor_requirements) && payload.executor_requirements.length) {
    return [
      {
        step_id: payload.step_id || '',
        step_name: payload.step_name || '',
        confirmed: null,
        requires_executor_input: true,
        executor_requirements: payload.executor_requirements
      }
    ];
  }
  return [];
}

function isPendingConfirmationValue(value) {
  if (value === null || value === undefined) {
    return true;
  }
  const normalized = String(value).trim().toLowerCase();
  return normalized === '' || normalized === 'pending';
}

function extractPendingToolFromRequirements(rawRequirements) {
  const requirements = Array.isArray(rawRequirements) ? rawRequirements : [];
  for (let i = requirements.length - 1; i >= 0; i -= 1) {
    const requirement = requirements[i];
    if (!requirement || !isPendingConfirmationValue(requirement.confirmed)) {
      continue;
    }

    const toolExecutions = [];
    if (requirement?.tool_execution && typeof requirement.tool_execution === 'object') {
      toolExecutions.push(requirement.tool_execution);
    }
    const executorRequirements = Array.isArray(requirement?.executor_requirements)
      ? requirement.executor_requirements
      : [];
    for (let j = executorRequirements.length - 1; j >= 0; j -= 1) {
      const toolExecution = executorRequirements[j]?.tool_execution;
      if (toolExecution && typeof toolExecution === 'object') {
        toolExecutions.push(toolExecution);
      }
    }

    for (let k = toolExecutions.length - 1; k >= 0; k -= 1) {
      const toolExecution = toolExecutions[k];
      const toolName = String(
        toolExecution.tool_name || toolExecution.name || toolExecution.toolName || ''
      ).trim();
      const requiresConfirmation =
        toolExecution.requires_confirmation === undefined ? true : Boolean(toolExecution.requires_confirmation);
      if (!toolName || !requiresConfirmation || !isPendingConfirmationValue(toolExecution.confirmed)) {
        continue;
      }
      return {
        toolName,
        toolArgs: extractToolArgsPayload(toolExecution),
        approvalId: toolExecution.approval_id || toolExecution.approvalId || null,
        toolCallId: toolExecution.tool_call_id || toolExecution.toolCallId || null,
        requirementStepId: requirement?.step_id || ''
      };
    }
  }
  return null;
}

function resolveStepNameFromEvent(event) {
  const directName =
    event?.step_name ||
    event?.stepName ||
    event?.step_output?.step_name ||
    event?.step_response?.step_name ||
    '';
  if (directName && workflowTemplateByName.has(directName)) {
    return directName;
  }

  const stepId = event?.step_id || event?.stepId || '';
  if (stepId && streamState?.stepNameByStepId?.has(stepId)) {
    return streamState.stepNameByStepId.get(stepId);
  }

  if (streamState?.currentStepName && workflowTemplateByName.has(streamState.currentStepName)) {
    return streamState.currentStepName;
  }
  return '';
}

function inferRunningStepName() {
  if (!streamState?.steps) {
    return '';
  }
  for (const step of workflowTemplate) {
    const stateStep = streamState.steps.get(step.name);
    if (stateStep?.status === 'running') {
      return step.name;
    }
  }
  return '';
}

function stepContentFromEvent(event) {
  if (event?.step_response?.content !== undefined && event?.step_response?.content !== null) {
    return event.step_response.content;
  }
  if (event?.step_output?.content !== undefined && event?.step_output?.content !== null) {
    return event.step_output.content;
  }
  if (event?.content !== undefined && event?.content !== null) {
    return event.content;
  }
  return '';
}

function updateReportFromStep(stepName, content) {
  if (!streamState || stepName !== 'final_report') {
    return;
  }
  const markdown =
    typeof content === 'string'
      ? content
      : content
      ? JSON.stringify(content, null, 2)
      : '';
  if (!markdown) {
    return;
  }
  streamState.reportMarkdown = clipText(markdown, 25000);
}

function computeStageFromActivity(activity, status) {
  let completedCount = 0;
  let runningIndex = -1;
  activity.forEach((step, index) => {
    if (step.status === 'done') {
      completedCount += 1;
    }
    if (step.status === 'running') {
      runningIndex = index;
    }
  });

  if (status === 'completed' || completedCount >= 3 || runningIndex >= 2) {
    return 'synthesis';
  }
  if (completedCount >= 1 || runningIndex >= 1) {
    return 'tooling';
  }
  return 'planning';
}

function buildActivityFromStreamState() {
  if (!streamState) {
    return [];
  }

  const activity = [];
  let furthestVisibleIndex = 0;
  const externalIntelIndex = workflowTemplateByName.get('research_web_intel')?.index ?? 1;
  const externalIntelStep = streamState.steps.get('research_web_intel');

  workflowTemplate.forEach((step, index) => {
    const stateStep = streamState.steps.get(step.name);
    if (!stateStep) {
      return;
    }
    if (stateStep.status === 'done' || stateStep.status === 'running') {
      furthestVisibleIndex = Math.max(furthestVisibleIndex, index);
    }
  });

  workflowTemplate.forEach((step, index) => {
    const stateStep = streamState.steps.get(step.name);
    if (!stateStep) {
      return;
    }
    const shouldPreviewFinalSynthesis =
      step.name === 'final_report' &&
      stateStep.status === 'pending' &&
      externalIntelStep?.status === 'done' &&
      furthestVisibleIndex >= externalIntelIndex &&
      index <= furthestVisibleIndex + 1 &&
      normalizeRunStatus(streamState.status) === 'running' &&
      !streamState.reportMarkdown;

    if (stateStep.status === 'pending' && !shouldPreviewFinalSynthesis && index > furthestVisibleIndex) {
      return;
    }

    // Hide Detection Rule Apply until the workflow gate has been approved.
    // Also block when a step_confirmation gate is pending (report window not yet acted on).
    const isApplyHidden =
      step.name === 'apply_detection_changes' &&
      !workflowGateApproved &&
      stateStep.status !== 'done' &&
      (stateStep.status !== 'running' || Boolean(streamState.workflowGate?.pending));
    if (isApplyHidden) {
      return;
    }

    const displayStatus = shouldPreviewFinalSynthesis ? 'running' : stateStep.status;
    const displayDetail = '';

    activity.push({
      ...stateStep,
      status: displayStatus,
      detail: displayDetail
    });
  });

  return activity;
}

function renderStreamState() {
  if (!streamState) {
    return;
  }

  const status = normalizeRunStatus(streamState.status);
  const activity = buildActivityFromStreamState();
  const stage = computeStageFromActivity(activity, status);
  const phaseLabel =
    streamState.phaseLabel ||
    (status === 'completed'
      ? 'Workflow completed.'
      : status === 'paused'
      ? streamState.workflowGate?.message ||
        streamState.commandGate?.message ||
        'Waiting for confirmation.'
      : stage === 'planning'
      ? 'Collecting rule context and baseline syntax...'
      : stage === 'tooling'
      ? 'Running SIEM research and external intelligence collection...'
      : 'Building final synthesis and waiting for next action...');

  const reportReady = Boolean(streamState.reportMarkdown);
  const payload = {
    runId: streamState.runId || currentRunId || '',
    sessionId: streamState.sessionId || currentRunSessionId || '',
    status,
    stage,
    phaseLabel,
    gate: streamState.workflowGate,
    workflowGate: streamState.workflowGate,
    commandGate: streamState.commandGate,
    reportReady,
    report_ready: reportReady,
    report: reportReady
      ? {
          title: 'Final Fine-Tuning Report',
          summary: summarizeStepText(streamState.reportMarkdown, 'Final report generated.'),
          markdown: streamState.reportMarkdown
        }
      : null
  };
  currentWorkflowGate = streamState.workflowGate || null;
  currentCommandGate = streamState.commandGate || null;

  agentBlockEl.classList.remove('hidden');
  updateRunPresentation(payload, activity);
  renderActivity(currentRunId || streamState.runId || '', activity, streamState.commandGate);
  renderReport(reportReady ? payload.report : null);
  renderReportWindowFooter();
}

function extractEmbeddedResponseTools(payload) {
  if (!payload || typeof payload !== 'object') {
    return [];
  }
  const candidates = [payload?.response, payload?.step_response?.response, payload?.step_output?.response];
  for (const candidate of candidates) {
    if (candidate && Array.isArray(candidate.tools) && candidate.tools.length) {
      return candidate.tools;
    }
  }
  return [];
}

function applyEmbeddedResponseTools(step, payload) {
  if (!step) {
    return;
  }
  const tools = extractEmbeddedResponseTools(payload);
  if (!tools.length) {
    return;
  }
  tools.forEach((tool) => {
    const toolCall = addToolCallToStep(step, tool);
    if (!toolCall) {
      return;
    }
    toolCall.name = tool.tool_name || toolCall.name;
    toolCall.input = compactToolValue(tool.tool_args || toolCall.input);
    toolCall.result = compactToolValue(tool.result ?? toolCall.result);
    toolCall.status = tool.tool_call_error ? 'error' : 'done';
    if (tool?.metrics?.duration) {
      toolCall.latencyMs = Math.round(Number(tool.metrics.duration) * 1000);
    }
  });
  if (step.toolCalls.length) {
    const latestTool = [...step.toolCalls].sort((a, b) => (Number(a.order) || 0) - (Number(b.order) || 0)).at(-1);
    if (latestTool) {
      step.toolName = latestTool.name;
      step.input = latestTool.input;
    }
  }
}

function applyStepResultCollection(stepResults) {
  if (!Array.isArray(stepResults) || !streamState) {
    return;
  }
  stepResults.forEach((stepResult) => {
    const stepName = stepResult?.step_name;
    if (!stepName || !workflowTemplateByName.has(stepName)) {
      return;
    }
    const step = getStepByName(stepName);
    if (!step) {
      return;
    }
    step.status = 'done';
    step.streamText = '';
    step.detail = '';
    if (stepResult?.content) {
      step.response = compactToolValue(stepResult.content, 120000);
    }
    applyEmbeddedResponseTools(step, stepResult);
    updateReportFromStep(stepName, stepResult?.content);
  });
}

function applyExecutorRunsCollection(executorRuns) {
  if (!Array.isArray(executorRuns) || !streamState) {
    return;
  }

  executorRuns.forEach((executorRun) => {
    const stepName = executorRun?.step_name || '';
    if (!stepName || !workflowTemplateByName.has(stepName)) {
      return;
    }
    const step = getStepByName(stepName);
    if (!step) {
      return;
    }
    const tools = Array.isArray(executorRun?.tools) ? executorRun.tools : [];
    tools.forEach((tool) => {
      const toolCall = addToolCallToStep(step, tool);
      if (!toolCall) {
        return;
      }
      toolCall.name = tool.tool_name || toolCall.name;
      toolCall.input = compactToolValue(tool.tool_args || toolCall.input);
      toolCall.result = compactToolValue(tool.result ?? toolCall.result);
      toolCall.status = tool.tool_call_error ? 'error' : 'done';
      if (tool?.metrics?.duration) {
        toolCall.latencyMs = Math.round(Number(tool.metrics.duration) * 1000);
      }
      if (stepName === 'apply_detection_changes' && (tool.tool_name || '') === 'run_ssh_command') {
        commandExecutionState = {
          toolName: 'run_ssh_command',
          command: extractCommandPreview(tool.tool_args || null),
          status: tool.tool_call_error ? 'error' : 'done',
          result: compactToolValue(tool.result ?? null, 120000)
        };
      }
    });
    if (step.toolCalls.length) {
      const latestTool = [...step.toolCalls].sort(
        (a, b) => (Number(a.order) || 0) - (Number(b.order) || 0)
      )[step.toolCalls.length - 1];
      step.toolName = latestTool.name;
      step.input = latestTool.input;
    }
  });
}

function applyRunOutputSnapshot(output) {
  if (!streamState || !output || typeof output !== 'object') {
    return;
  }

  const reportedStatus = normalizeRunStatus(output.status || output.run_status || '');
  if (reportedStatus) {
    streamState.status = reportedStatus;
  }
  if (reportedStatus === 'completed' || reportedStatus === 'error') {
    streamState.workflowGate = null;
    streamState.commandGate = null;
    currentWorkflowGate = null;
    currentCommandGate = null;
  }
  setRunContext(output.run_id, output.session_id);

  applyStepResultCollection(output.step_results);
  applyExecutorRunsCollection(output.step_executor_runs);
  if (!streamState.reportMarkdown && output.content) {
    streamState.reportMarkdown =
      typeof output.content === 'string'
        ? clipText(output.content, 25000)
        : clipText(JSON.stringify(output.content, null, 2), 25000);
  }
}

function applyWorkflowEvent(event) {
  if (!streamState || !event || typeof event !== 'object') {
    return;
  }

  const eventName = normalizeEventName(event.event);
  let stepName = resolveStepNameFromEvent(event);
  if (!stepName && eventName === 'stepstarted') {
    const currentIndex = workflowTemplateByName.get(streamState.currentStepName || '')?.index ?? -1;
    const nextCandidate = workflowTemplate[currentIndex + 1]?.name || '';
    if (nextCandidate && workflowTemplateByName.has(nextCandidate)) {
      stepName = nextCandidate;
    }
  }
  if (!stepName && (eventName === 'stepoutput' || eventName === 'stepcompleted')) {
    stepName = inferRunningStepName() || streamState.currentStepName || '';
  }
  const step = getStepByName(stepName);
  const stepId = event?.step_id || '';
  if (stepId && stepName) {
    streamState.stepNameByStepId.set(stepId, stepName);
  }

  const workflowRunId = event?.workflow_run_id || event?.workflowRunId || '';
  if (workflowRunId) {
    setRunContext(workflowRunId, '');
  } else if (
    event?.run_id &&
    (eventName.startsWith('workflow') || eventName.startsWith('step'))
  ) {
    setRunContext(event.run_id, '');
  }
  if (event?.session_id) {
    setRunContext('', event.session_id);
  }

  if (eventNameMatches(eventName, 'workflowstarted')) {
    streamState.status = 'running';
    streamState.phaseLabel = '';
  }

  if (eventNameMatches(eventName, 'stepstarted')) {
    if (step) {
      streamState.currentStepName = stepName;
      step.status = 'running';
      step.detail = '';
    }
    streamState.workflowGate = null;
    streamState.commandGate = null;
  }

  if (eventNameMatches(eventName, 'toolcallstarted')) {
    const targetStep = step || getStepByName(streamState.currentStepName);
    const tool = event.tool || {};
    if (targetStep) {
      if (targetStep.streamText && !/\n\s*$/.test(targetStep.streamText)) {
        targetStep.streamText += '\n\n';
      }
      targetStep.status = 'running';
      const toolCall = addToolCallToStep(targetStep, tool, { eventName });
      if (toolCall) {
        toolCall.name = tool.tool_name || tool.name || toolCall.name;
        toolCall.input = compactToolValue(tool.tool_args || tool.arguments || toolCall.input);
        toolCall.status = 'running';
        targetStep.toolName = toolCall.name;
        targetStep.input = toolCall.input;
      } else {
        targetStep.toolName = tool.tool_name || tool.name || targetStep.toolName;
        targetStep.input = tool.tool_args || tool.arguments || targetStep.input;
      }
      targetStep.detail = '';
    }
  }

  if (
    eventNameMatches(eventName, 'runcontent') ||
    eventNameMatches(eventName, 'runintermediatecontent') ||
    eventNameMatches(eventName, 'teamruncontent') ||
    eventNameMatches(eventName, 'teamrunintermediatecontent')
  ) {
    const targetStep = step || getStepByName(streamState.currentStepName);
    if (targetStep) {
      targetStep.status = 'running';
      const content = stepContentFromEvent(event);
      const streamChunk = toDisplayText(content);
      if (streamChunk && streamChunk.trim()) {
        targetStep.streamText = clipText(
          appendStreamChunk(targetStep.streamText, streamChunk),
          120000
        );
      }
      targetStep.detail = '';
    }
  }

  if (eventNameMatches(eventName, 'toolcallcompleted')) {
    const targetStep = step || getStepByName(streamState.currentStepName);
    const tool = event.tool || {};
    if (targetStep) {
      if (targetStep.streamText && !/\n\s*$/.test(targetStep.streamText)) {
        targetStep.streamText += '\n\n';
      }
      targetStep.status = 'running';
      const toolCall = addToolCallToStep(targetStep, tool, { eventName });
      if (toolCall) {
        toolCall.name = tool.tool_name || tool.name || toolCall.name;
        toolCall.input = compactToolValue(tool.tool_args || toolCall.input);
        toolCall.result = compactToolValue(
          tool.result ?? event.result ?? event.content ?? toolCall.result
        );
        toolCall.status = tool.tool_call_error ? 'error' : 'done';
        if (tool?.metrics?.duration) {
          toolCall.latencyMs = Math.round(Number(tool.metrics.duration) * 1000);
        }
        targetStep.toolName = toolCall.name;
        targetStep.input = toolCall.input;
      } else {
        targetStep.toolName = tool.tool_name || tool.name || targetStep.toolName;
      }
      targetStep.detail = '';
      if (
        String(targetStep.id || '').toLowerCase() === 'apply_detection_changes' &&
        (tool.tool_name || tool.name || '') === 'run_ssh_command'
      ) {
        const resultValue = compactToolValue(tool.result ?? event.result ?? event.content ?? null, 120000);
        const toolCallId =
          tool?.tool_call_id ||
          tool?.approval_id ||
          null;
        pushCommandHistory({
          toolCallId,
          toolName: 'run_ssh_command',
          command: extractCommandPreview(tool.tool_args || null),
          status: tool.tool_call_error ? 'error' : 'done',
          result: resultValue
        });
      }
    }
  }

  if (eventNameMatches(eventName, 'stepoutput') || eventNameMatches(eventName, 'stepcompleted')) {
    if (step) {
      const content = stepContentFromEvent(event);
      step.status = 'done';
      step.streamText = '';
      step.detail = '';
      if (content) {
        step.response = compactToolValue(content, 120000);
      }
      const metrics = event?.step_response?.metrics || {};
      if (metrics?.duration) {
        step.latencyMs = Math.round(Number(metrics.duration) * 1000);
      }
      if (metrics?.input_tokens) {
        step.tokensIn = Number(metrics.input_tokens);
      }
      if (metrics?.output_tokens) {
        step.tokensOut = Number(metrics.output_tokens);
      }
      applyEmbeddedResponseTools(step, event);
      updateReportFromStep(stepName, content);
    }
  }

  if (
    eventNameMatches(eventName, 'runpaused') ||
    eventNameMatches(eventName, 'steppaused') ||
    eventNameMatches(eventName, 'stepexecutorpaused')
  ) {
    const pausedStepName =
      stepName && workflowTemplateByName.has(stepName)
        ? stepName
        : streamState.currentStepName || 'apply_detection_changes';
    const pausedStep = getStepByName(pausedStepName);
    const tools = Array.isArray(event.tools)
      ? event.tools
      : event?.tool && typeof event.tool === 'object'
      ? [event.tool]
      : [];
    const eventPendingTool = tools.length ? tools[tools.length - 1] : null;
    const requirementList = collectRequirementList(event);
    const requirementPendingTool = extractPendingToolFromRequirements(requirementList);
    const selectedPendingTool = requirementPendingTool || eventPendingTool || null;
    const resolvedToolName = String(
      selectedPendingTool?.toolName ||
      selectedPendingTool?.tool_name ||
      selectedPendingTool?.name ||
      selectedPendingTool?.toolName ||
      ''
    ).trim();
    const resolvedToolArgs = selectedPendingTool
      ? extractToolArgsPayload(selectedPendingTool)
      : null;
    const resolvedApprovalId =
      selectedPendingTool?.approvalId ||
      selectedPendingTool?.approval_id ||
      null;
    const resolvedToolCallId =
      selectedPendingTool?.toolCallId ||
      selectedPendingTool?.tool_call_id ||
      null;
    const hasPendingTool =
      Boolean(resolvedToolName) &&
      (resolvedToolName !== pausedStepName || Boolean(extractCommandPreview(resolvedToolArgs || null)));
    const unresolvedRequirements = requirementList
      .filter((item) => item && isPendingConfirmationValue(item.confirmed))
      .map((item) => item || {})
      .filter(Boolean);
    const unresolvedUserInput = unresolvedRequirements.find((item) => Boolean(item?.requires_user_input)) || null;
    const requirementStepId =
      unresolvedUserInput?.step_id ||
      requirementPendingTool?.requirementStepId ||
      event.step_id ||
      '';
    const isUserInputGate = Boolean(unresolvedUserInput) && !hasPendingTool;
    const gate = {
      pending: true,
      mode: hasPendingTool ? 'tool_confirmation' : isUserInputGate ? 'step_user_input' : 'step_confirmation',
      message:
        event.content ||
        event.message ||
        unresolvedUserInput?.user_input_message ||
        'Do you approve applying detection changes in Wazuh now?',
      stepName: pausedStepName,
      requirementStepId: requirementStepId,
      commandPreview: extractCommandPreview(resolvedToolArgs || null),
      toolName: resolvedToolName,
      toolArgs: resolvedToolArgs,
      approvalId: resolvedApprovalId,
      toolCallId: resolvedToolCallId,
      userInputSchema: Array.isArray(unresolvedUserInput?.user_input_schema)
        ? unresolvedUserInput.user_input_schema
        : []
    };
    streamState.status = 'paused';
    streamState.workflowGate = hasPendingTool ? null : gate;
    streamState.commandGate = hasPendingTool ? gate : null;
    streamState.phaseLabel = gate.message;
    if (pausedStep) {
      pausedStep.status = 'running';
      pausedStep.detail = hasPendingTool
        ? 'Pending command approval in Detection Rule Apply.'
        : 'Pending workflow approval in Final Report window.';
      if (gate.toolName) {
        pausedStep.toolName = gate.toolName;
        pausedStep.input = gate.toolArgs;
        const pendingToolCall = addToolCallToStep(pausedStep, {
          tool_call_id: gate.toolCallId || gate.approvalId || `${pausedStepName}-pending-approval`,
          tool_name: gate.toolName,
          tool_args: gate.toolArgs || null
        });
        if (pendingToolCall) {
          pendingToolCall.status = 'running';
        }
      }
    }
    fineTuneStatusEl.textContent = 'Workflow paused. Awaiting your confirmation.';
    if (!hasPendingTool) {
      hydrateRunFromSnapshot({ runId: currentRunId || streamState?.runId || '' }).catch(() => {});
    }
  }

  if (eventNameMatches(eventName, 'workflowcompleted')) {
    streamState.status = 'completed';
    streamState.workflowGate = null;
    streamState.commandGate = null;
    awaitingPostUserInputRunId = '';
    streamState.phaseLabel = 'Workflow completed.';
    applyStepResultCollection(event.step_results);
    if (!streamState.reportMarkdown && event.content) {
      streamState.reportMarkdown =
        typeof event.content === 'string'
          ? clipText(event.content, 25000)
          : clipText(JSON.stringify(event.content, null, 2), 25000);
    }
    finalizeRun('Fine-tuning completed.');
  }

  if (eventNameMatches(eventName, 'workflowerror') || eventNameMatches(eventName, 'runerror')) {
    streamState.status = 'error';
    streamState.workflowGate = null;
    streamState.commandGate = null;
    awaitingPostUserInputRunId = '';
    streamState.phaseLabel = event.content || 'Workflow failed.';
    finalizeRun('Fine-tuning failed.');
  }

  const isHighFrequencyContentEvent =
    eventNameMatches(eventName, 'runcontent') ||
    eventNameMatches(eventName, 'runintermediatecontent') ||
    eventNameMatches(eventName, 'teamruncontent') ||
    eventNameMatches(eventName, 'teamrunintermediatecontent');
  if (isHighFrequencyContentEvent) {
    const now = Date.now();
    if (now - lastStreamRenderAt < 180) {
      return;
    }
    lastStreamRenderAt = now;
    if (patchStreamContentInPlace()) {
      return;
    }
  }

  renderStreamState();
}

function updateRunPresentation(payload, activity) {
  const runStatus = normalizeRunStatus(payload?.status);
  const live = activity.some((step) => step.status === 'running');
  agentBlockEl.classList.toggle('is-live', live || runStatus === 'running' || runStatus === 'paused');
  const subtitle =
    payload?.phaseLabel ||
    payload?.phase ||
    (runStatus === 'completed'
      ? 'Run completed. Fine-tuning report generated.'
      : 'Agent is running workflow steps.');
  agentSubtitleEl.textContent = subtitle;
  agentBlockEl.dataset.status = runStatus;
}

function renderRules() {
  setRuleSelectionLocked(ruleSelectionLocked);
  if (rulesEmptyMessageEl) {
    rulesEmptyMessageEl.innerHTML = '';
    rulesEmptyMessageEl.classList.add('hidden');
  }
  rulesListEl.innerHTML = rules
    .map((rule) => {
      const activeClass = rule.id === selectedRuleId ? 'active' : '';
      const cleanId = shortRuleId(rule.id);

      return `
        <div class="rule-row ${activeClass}" data-rule-id="${escapeHtml(rule.id)}">
          <div class="rule-main">
            <div class="rule-name">${escapeHtml(rule.name)}</div>
          </div>
          <div class="rule-id-col">
            <span class="rule-id-text">${escapeHtml(cleanId)}</span>
            <button class="rule-id-action" type="button" aria-label="select rule">
              <span class="material-symbols-outlined">add</span>
            </button>
          </div>
        </div>
      `;
    })
    .join('');

  document.querySelectorAll('.rule-row').forEach((row) => {
    row.addEventListener('click', () => {
      if (ruleSelectionLocked) {
        return;
      }
      manualRule = null;
      if (manualRuleIdEl) {
        manualRuleIdEl.value = '';
      }
      if (fineTuneStatusEl) {
        fineTuneStatusEl.textContent = '';
      }
      selectedRuleId = row.dataset.ruleId;
      renderRules();
      renderSelectedRule();
    });
  });
}

function renderRulesEmptyState(message) {
  rules = [];
  selectedRuleId = null;
  manualRule = null;
  if (manualRuleIdEl) {
    manualRuleIdEl.value = '';
    manualRuleIdEl.disabled = true;
  }
  if (manualRuleApplyEl) {
    manualRuleApplyEl.disabled = true;
  }
  if (rulesListEl) {
    rulesListEl.innerHTML = '';
  }
  if (rulesEmptyMessageEl) {
    rulesEmptyMessageEl.innerHTML = `
      <span class="rules-empty-content">${escapeHtml(message)}</span>
      <button id="rules-empty-settings-btn" class="rules-empty-settings-btn" type="button" aria-label="Open settings">
        <span class="material-symbols-outlined" aria-hidden="true">settings</span>
      </button>
    `;
    rulesEmptyMessageEl.classList.remove('hidden');
    const settingsBtn = document.getElementById('rules-empty-settings-btn');
    if (settingsBtn) {
      settingsBtn.addEventListener('click', () => {
        openSettingsModal().catch((error) => {
          setSettingsStatus(error.message || 'Failed to open settings.', true);
        });
      });
    }
  }
  if (ruleIdChipEl) {
    ruleIdChipEl.textContent = 'SIEM';
  }
  if (ruleStatusChipEl) {
    ruleStatusChipEl.textContent = 'Config required';
  }
  if (ruleNameEl) {
    ruleNameEl.textContent = 'No SIEM rule selected';
  }
  if (ruleDescriptionEl) {
    ruleDescriptionEl.textContent = 'Fix the SIEM indexer configuration, then reload this page.';
  }
  if (fineTuneBtnEl) {
    fineTuneBtnEl.disabled = true;
  }
}

function renderSelectedRule() {
  const rule = currentRule();
  if (!rule) {
    return;
  }

  ruleIdChipEl.textContent = rule.id || `RUL-${shortRuleId(rule.id)}`;
  if (ruleStatusChipEl) {
    ruleStatusChipEl.textContent = rule.status;
  }
  ruleNameEl.textContent = rule.name;
  if (ruleDescriptionEl) {
    ruleDescriptionEl.textContent = rule.description;
  }
  if (fineTuneBtnEl && !currentRunId) {
    fineTuneBtnEl.disabled = false;
    fineTuneBtnEl.innerHTML = fineTuneBtnDefaultHtml;
  }
}

async function applyManualRuleSelection() {
  const rawRuleId = manualRuleIdEl?.value || '';
  const normalizedRuleId = normalizeManualRuleId(rawRuleId);
  if (!normalizedRuleId) {
    fineTuneStatusEl.textContent = 'Please enter a Rule ID first.';
    return;
  }

  const existingRule = findRuleById(normalizedRuleId);
  if (existingRule) {
    manualRule = null;
    selectedRuleId = existingRule.id;
    renderRules();
    renderSelectedRule();
    if (fineTuneStatusEl) {
      fineTuneStatusEl.textContent = '';
    }
    return;
  }

  let fetchedRule = null;
  try {
    fetchedRule = await fetchRuleById(normalizedRuleId);
  } catch (_error) {
    // Keep manual flow usable even when backend lookup is unavailable.
  }
  manualRule = {
    id: normalizeManualRuleId(fetchedRule?.id || normalizedRuleId),
    name: String(fetchedRule?.name || `Rule ${shortRuleId(normalizedRuleId)}`),
    status: String(fetchedRule?.status || 'Manual'),
    description: String(
      fetchedRule?.description || `Manual rule ${shortRuleId(normalizedRuleId)} selected for fine tuning.`
    )
  };
  selectedRuleId = null;
  renderRules();
  renderSelectedRule();
  if (fineTuneStatusEl) {
    fineTuneStatusEl.textContent = '';
  }
}

function renderReport(report) {
  if (!report) {
    latestReport = null;
    reportBoxEl.classList.add('hidden');
    reportBoxEl.classList.remove('revealed');
    reportBoxEl.innerHTML = '';
    closeReportWindow();
    renderReportWindowFooter();
    return;
  }

  latestReport = {
    title: report.title || 'Final Report',
    summary: report.summary || '',
    markdown: clipText(report.markdown || '', 25000)
  };

  reportBoxEl.classList.remove('hidden');
  reportBoxEl.classList.add('revealed');
  reportBoxEl.innerHTML = `
    <div class="report-title-row">
      <div class="report-title">${escapeHtml(latestReport.title)}</div>
      <button class="report-open-btn report-box-open" type="button" aria-label="Open final report">
        <span class="material-symbols-outlined">open_in_new</span>
        Open Report
      </button>
    </div>
    <div class="report-summary">${escapeHtml(latestReport.summary)}</div>
  `;
  const reportOpenBtn = reportBoxEl.querySelector('.report-box-open');
  if (reportOpenBtn) {
    reportOpenBtn.addEventListener('click', (event) => {
      event.preventDefault();
      openReportWindow();
    });
  }
  renderReportWindowFooter();
}

async function submitHitlAction(runId, gate, action, options = {}) {
  if (!gate || !gate.pending || isHitlActionLocked()) {
    return;
  }
  beginHitlAction();
  fineTuneStatusEl.textContent = 'Submitting confirmation...';
  renderReportWindowFooter();
  const resolvedRunId = runId || currentRunId || streamState?.runId || '';
  if (!resolvedRunId) {
    endHitlAction();
    return;
  }

  try {
    const normalizedAction = normalizeConfirmationAction(action);
    const requestBody = {
      action: normalizedAction,
      requirementStepId: gate.requirementStepId || '',
      sessionId: currentRunSessionId || '',
      mode: gate.mode || '',
      approvalId: gate.approvalId || '',
      toolCallId: gate.toolCallId || '',
      userInput:
        options && options.userInput && typeof options.userInput === 'object'
          ? options.userInput
          : undefined
    };

    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
    stopActiveStream();
    lastPollingRenderSignature = '';

    if (gate.mode === 'step_user_input' || gate.mode === 'tool_confirmation') {
      if (gate.mode === 'step_user_input') {
        workflowGateApproved = true;
        fulfilledUserInputGateRunId = resolvedRunId;
        awaitingPostUserInputRunId = '';
        recommendationInputText = '';
        closeReportWindow();
      }
      if (gate.mode === 'tool_confirmation') {
        const cmd = gate.commandPreview || extractCommandPreview(gate.toolArgs || null);
        pushCommandHistory({
          toolCallId: gate.toolCallId || null,
          toolName: gate.toolName || 'run_ssh_command',
          command: cmd,
          status: normalizedAction === 'reject' ? 'rejected' : 'running',
          result: normalizedAction === 'reject' ? 'Command execution was denied by user.' : null
        });
      }
      currentWorkflowGate = null;
      currentCommandGate = null;
      if (streamState) {
        streamState.status = 'running';
        streamState.workflowGate = null;
        streamState.commandGate = null;
        streamState.phaseLabel =
          gate.mode === 'tool_confirmation'
            ? 'Command decision submitted. Streaming next action...'
            : 'Continuing to Detection Engineer...';
        const applyStep = getStepByName('apply_detection_changes');
        if (applyStep && applyStep.status !== 'done') {
          if (gate.mode === 'tool_confirmation' && Array.isArray(applyStep.toolCalls)) {
            const targetCommand = String(
              gate.commandPreview || extractCommandPreview(gate.toolArgs || null) || ''
            ).trim();
            const targetToolCall = applyStep.toolCalls.find((toolCall) => {
              if (gate.toolCallId && String(toolCall.id || '') === String(gate.toolCallId)) {
                return true;
              }
              const commandText = String(extractCommandFromToolInput(toolCall.input) || '').trim();
              return Boolean(targetCommand) && commandText === targetCommand;
            });
            if (targetToolCall) {
              expandedPayloadSteps.delete(`${applyStep.id}::${targetToolCall.id}`);
              targetToolCall.status = normalizedAction === 'reject' ? 'rejected' : 'running';
              if (normalizedAction === 'reject' && !targetToolCall.result) {
                targetToolCall.result = 'Command execution was denied by user.';
              }
            }
          }
          applyStep.status = 'running';
          applyStep.detail =
            gate.mode === 'tool_confirmation'
              ? 'Waiting for the next Detection Engineer action...'
              : 'Applying approved detection change...';
        }
        renderStreamState();
      }
      const streamResponse = await fetch(`/api/fine-tune/${encodeURIComponent(resolvedRunId)}/confirm/stream`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody)
      });
      if (!streamResponse.ok) {
        const errorData = await streamResponse.json().catch(() => ({}));
        throw new Error(errorData.error || 'Failed to submit confirmation');
      }
      // The decision is accepted once the stream opens. Release the UI lock now
      // so controls don't feel frozen while the backend streams the follow-up.
      endHitlAction();
      renderReportWindowFooter();
      fineTuneStatusEl.textContent =
        gate.mode === 'tool_confirmation'
          ? 'Command decision submitted. Streaming Detection Engineer...'
          : 'Recommendation submitted. Streaming Detection Engineer...';
      let sawFollowupEvent = false;
      for await (const payload of iterateNdjsonResponse(streamResponse)) {
        applyStreamEnvelope(payload);
        sawFollowupEvent = true;
        if (streamState?.commandGate?.pending) {
          break;
        }
      }
      if (!sawFollowupEvent || !streamState?.commandGate?.pending) {
        await hydrateRunFromSnapshot({ runId: resolvedRunId }).catch(() => {});
      }
      renderReportWindowFooter();
      return;
    }

    const response = await fetch(`/api/fine-tune/${encodeURIComponent(resolvedRunId)}/confirm`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(requestBody)
    });

    if (!response.ok) {
      if (response.status === 409) {
        currentWorkflowGate = null;
        currentCommandGate = null;
        if (streamState) {
          streamState.status = 'running';
          streamState.workflowGate = null;
          streamState.commandGate = null;
        }
        startRunStream({
          runId: resolvedRunId,
          sessionId: currentRunSessionId || '',
          lastEventIndex: lastStreamEventIndex,
          resume: true
        }).catch(() => {
          startPolling(resolvedRunId, currentRunSessionId || '');
        });
        return;
      }
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.error || 'Failed to submit confirmation');
    }

    const confirmPayload = await response.json().catch(() => ({}));
    setRunContext(
      confirmPayload?.runId || confirmPayload?.run_id || resolvedRunId,
      confirmPayload?.sessionId || confirmPayload?.session_id || currentRunSessionId
    );
    fineTuneStatusEl.textContent = 'Confirmation submitted. Continuing workflow...';
    if (gate.mode === 'tool_confirmation') {
      const cmd = gate.commandPreview || extractCommandPreview(gate.toolArgs || null);
      if (normalizedAction === 'approve') {
        pushCommandHistory({
          toolCallId: gate.toolCallId || null,
          toolName: gate.toolName || 'run_ssh_command',
          command: cmd,
          status: 'running',
          result: null
        });
      } else {
        pushCommandHistory({
          toolCallId: gate.toolCallId || null,
          toolName: gate.toolName || 'run_ssh_command',
          command: cmd,
          status: 'rejected',
          result: 'Command execution was denied by user.'
        });
      }
    }
    if (
      (gate.mode === 'step_confirmation' || gate.mode === 'step_user_input') &&
      normalizedAction === 'approve'
    ) {
      workflowGateApproved = true;
      if (gate.mode === 'step_user_input') {
        fulfilledUserInputGateRunId = resolvedRunId;
        awaitingPostUserInputRunId = resolvedRunId;
        recommendationInputText = '';
        closeReportWindow();
      }
    } else if (
      (gate.mode === 'step_confirmation' || gate.mode === 'step_user_input') &&
      normalizedAction === 'reject'
    ) {
      workflowGateApproved = false;
    }
    currentWorkflowGate = null;
    currentCommandGate = null;
    setRunContext(resolvedRunId, currentRunSessionId);
    if (streamState) {
      streamState.status = 'running';
      streamState.workflowGate = null;
      streamState.commandGate = null;
      const applyStep = getStepByName('apply_detection_changes');
      if (applyStep && applyStep.status !== 'done') {
        if (gate.mode === 'tool_confirmation' && Array.isArray(applyStep.toolCalls)) {
          const targetCommand = String(
            gate.commandPreview || extractCommandPreview(gate.toolArgs || null) || ''
          ).trim();
          const targetToolCall = applyStep.toolCalls.find((toolCall) => {
            if (gate.toolCallId && String(toolCall.id || '') === String(gate.toolCallId)) {
              return true;
            }
            const commandText = String(extractCommandFromToolInput(toolCall.input) || '').trim();
            return Boolean(targetCommand) && commandText === targetCommand;
          });
          if (targetToolCall) {
            expandedPayloadSteps.delete(`${applyStep.id}::${targetToolCall.id}`);
            if (normalizedAction === 'reject') {
              targetToolCall.status = 'rejected';
              if (!targetToolCall.result) {
                targetToolCall.result = 'Command execution was denied by user.';
              }
            } else {
              targetToolCall.status = 'running';
            }
          }
        }
        if (gate.mode === 'step_confirmation' && normalizedAction === 'reject') {
          applyStep.status = 'done';
          applyStep.detail = 'Detection change was denied by user.';
        } else if (gate.mode === 'tool_confirmation' && normalizedAction === 'reject') {
          applyStep.status = 'running';
          applyStep.detail = 'Latest command was denied. Waiting for next workflow action.';
        } else {
          applyStep.status = 'running';
          applyStep.detail = 'Applying approved detection change...';
        }
      }
      renderStreamState();
    }
    renderReportWindowFooter();

    startRunStream({
      runId: currentRunId || resolvedRunId,
      sessionId: currentRunSessionId || '',
      lastEventIndex: lastStreamEventIndex,
      resume: true
    }).catch(() => {
      startPolling(currentRunId || resolvedRunId, currentRunSessionId || '');
    });
  } catch (error) {
    fineTuneStatusEl.textContent = error.message;
  } finally {
    endHitlAction();
    renderReportWindowFooter();
  }
}

async function submitRecommendationSelection() {
  if (!currentWorkflowGate?.pending || String(currentWorkflowGate?.mode || '') !== 'step_user_input') {
    return;
  }
  const value = String(recommendationInputText || '').trim();
  if (!value) {
    fineTuneStatusEl.textContent = 'Enter recommendation input first.';
    return;
  }
  await submitHitlAction(currentRunId, currentWorkflowGate, 'approve', {
    userInput: { recommendation_numbers: value }
  });
}

function renderActivity(runId, activity, commandGate = null) {
  lastRenderedRunId = runId || '';
  lastRenderedActivity = Array.isArray(activity) ? activity : [];
  lastRenderedCommandGate = commandGate;
  if (!Array.isArray(activity) || !activity.length) {
    autoFocusedRunningStepKey = '';
    currentAutoStepTransition = { expanded: '', collapsed: '' };
    activityListEl.classList.remove('is-live');
    activityListEl.innerHTML = '<div class="activity-empty">Awaiting systemic initiation...</div>';
    return;
  }

  const runningStep = activity.find((step) => step.status === 'running') || null;
  if (runningStep) {
    const runningStepKey = runningStep.id || `step-${runningStep.index}`;
    if (autoFocusedRunningStepKey !== runningStepKey) {
      const previousRunningStepKey = autoFocusedRunningStepKey;
      expandedStepDetails.delete(runningStepKey);
      activity.forEach((step) => {
        if (step.status === 'done' && step.index < runningStep.index) {
          const doneKey = step.id || `step-${step.index}`;
          if (doneKey !== runningStepKey && doneKey !== 'final_report') {
            expandedStepDetails.add(doneKey);
          }
        }
      });
      if (previousRunningStepKey && previousRunningStepKey !== runningStepKey && previousRunningStepKey !== 'final_report') {
        expandedStepDetails.add(previousRunningStepKey);
      }
      currentAutoStepTransition = {
        expanded: runningStepKey,
        collapsed: previousRunningStepKey || ''
      };
      autoFocusedRunningStepKey = runningStepKey;
      if (autoTransitionResetTimer) {
        clearTimeout(autoTransitionResetTimer);
      }
      autoTransitionResetTimer = setTimeout(() => {
        currentAutoStepTransition = { expanded: '', collapsed: '' };
        autoTransitionResetTimer = null;
      }, 420);
    } else {
      // Keep the transition flags briefly so CSS animation can complete
      // across rapid re-renders during streaming/polling.
    }
  } else {
    autoFocusedRunningStepKey = '';
    currentAutoStepTransition = { expanded: '', collapsed: '' };
    if (autoTransitionResetTimer) {
      clearTimeout(autoTransitionResetTimer);
      autoTransitionResetTimer = null;
    }
  }

  const live = activity.some((step) => step.status === 'running');
  const actionLocked = isHitlActionLocked();
  activityListEl.classList.toggle('is-live', live);
  const reportVisible = Boolean(latestReport?.markdown || streamState?.reportMarkdown);

  const rowEntries = activity.map((step) => {
    const isRunning = step.status === 'running';
    const key = step.id || `step-${step.index}`;
    const isFinalSynthesisStep = String(step.id || '').toLowerCase() === 'final_report';
    const suppressSecondaryFinderStream = isFinalSynthesisStep;
    const isCollapsed = expandedStepDetails.has(key);
    const isExpanded = !isCollapsed;
    const autoExpanding = currentAutoStepTransition.expanded === key;
    const autoCollapsing = currentAutoStepTransition.collapsed === key;
    let toolItems = Array.isArray(step.toolCalls) && step.toolCalls.length
      ? [...step.toolCalls].sort((a, b) => (Number(a.order) || 0) - (Number(b.order) || 0))
      : step.toolName
      ? [
          {
            id: `${key}-tool`,
            order: 1,
            name: step.toolName,
            input: step.input,
            result: step.result,
            status: isRunning ? 'running' : 'done'
          }
        ]
      : [];
    const stepResponseContent = isFinalSynthesisStep && reportVisible ? '' : step.response;
    const stepResponseText = toDisplayText(stepResponseContent || '').trim();
    const showStepResponse = Boolean(stepResponseText);
    const streamTextRaw = toDisplayText(step.streamText || '').trim();
    const streamText = getTypedStreamText(`${key}::step`, streamTextRaw, isRunning);
    const showStreamNarrative = Boolean(streamText) && toolItems.length === 0;
    const sanitizedDetail = (() => {
      const raw = String(step.detail || '').trim();
      if (isRunning && /[_a-z0-9-]+\s+completed\.$/i.test(raw)) {
        return '';
      }
      return raw;
    })();
    const visibleStepDetail = isFinalSynthesisStep
      ? sanitizedDetail.replace(/\*\*/g, '').trim()
      : '';
    const stepResponseHtml = showStepResponse
      ? `
          <div class="tree-step-response">
            <div class="tree-payload-label">Agent Response</div>
            ${renderToolResult(stepResponseContent)}
          </div>
        `
      : '';
    const stepStreamId = `${key}::stream`;
    const isStepStreamCollapsed = collapsedStreamBlocks.has(stepStreamId);
    const streamNarrativeHtml = showStreamNarrative
      ? `
          <div class="tree-step-stream is-collapsible ${isStepStreamCollapsed ? 'is-collapsed' : 'is-expanded'}">
            <button class="tree-stream-toggle" type="button" data-stream-id="${escapeHtml(stepStreamId)}" aria-label="toggle stream text">
              <span class="material-symbols-outlined">${isStepStreamCollapsed ? 'keyboard_arrow_right' : 'keyboard_arrow_down'}</span>
            </button>
            <div class="tree-stream-text" data-stream-key="${escapeHtml(key + '::step')}">${escapeHtml(streamText)}</div>
          </div>
        `
      : '';
    const isApplyStep = String(step.id || '').toLowerCase() === 'apply_detection_changes';
    const showInlineCommandGate =
      isApplyStep &&
      commandGate?.pending &&
      commandGate?.mode === 'tool_confirmation';

    if (isFinalSynthesisStep) {
      toolItems = toolItems.filter(
        (tool) => String(tool?.name || '').toLowerCase() !== 'create_final_report'
      );
    }
    // Build tool cards (header + own expandable body) so each command keeps its own result attached.
    const toolCards = [];
    toolItems.forEach((tool, toolIndex) => {
      const payloadId = `${key}::${tool.id || tool.tool_call_id || toolIndex + 1}`;
      const isExpanded = expandedPayloadSteps.has(payloadId);
      const normalizedToolStatus = String(tool.status || '').toLowerCase();
      const isToolRunning = normalizedToolStatus === 'running';
      const isSshCommandTool =
        isApplyStep && String(tool.name || '').toLowerCase() === 'run_ssh_command';
      const commandText = isSshCommandTool ? extractCommandFromToolInput(tool.input) : '';
      const isPendingCommandTool =
        isApplyStep &&
        showInlineCommandGate &&
        (commandGate?.toolCallId
          ? String(tool.id || '') === String(commandGate.toolCallId)
          : isToolRunning && toolIndex === toolItems.length - 1);
      const isSubmittedCommandTool = isSshCommandTool && isToolRunning && !isPendingCommandTool;
      const hasPayload = Boolean(tool.input || tool.result);
      const hasExpandablePayload =
        hasPayload && !(isSshCommandTool && (isPendingCommandTool || isSubmittedCommandTool));
      const isWebTool = shouldUseWebToolIcon(step, tool);
      const isWazuhTool2 = String(step.id || '').toLowerCase() === 'research_threat_hunting';
      const isSkillInstructionsTool = String(tool.name || '').toLowerCase() === 'get_skill_instructions';
      const toolIconHtml2 = isSshCommandTool
        ? `<span class="material-symbols-outlined tree-tool-icon">terminal</span>`
        : isSkillInstructionsTool
        ? `<span class="material-symbols-outlined tree-tool-icon">description</span>`
        : isToolRunning
        ? `<span class="material-symbols-outlined tree-tool-icon">sync</span>`
        : isWebTool
        ? `<span class="material-symbols-outlined tree-tool-icon is-web">public</span>`
        : isWazuhTool2
        ? `<img src="/wazuh.png" class="tree-tool-wazuh-icon" alt="Wazuh" width="14" height="14" />`
        : `<span class="material-symbols-outlined tree-tool-icon">build</span>`;
      const isTavilyCall2 = String(tool.name || '').toLowerCase().startsWith('tavily_');
      const toolDomains2 = isTavilyCall2 ? extractWebsiteDomains(tool) : [];
      const visibleDomains2 = toolDomains2.slice(0, 5);
      const hiddenDomainsCount2 = Math.max(0, toolDomains2.length - visibleDomains2.length);
      const toolPreambleRaw = String(toDisplayText(tool.preamble || '')).trim();
      const toolPreamble = suppressSecondaryFinderStream
        ? ''
        : getTypedStreamText(`${payloadId}::preamble`, toolPreambleRaw, isRunning);
      const toolPreambleStreamId = `${payloadId}::preamble-stream`;
      const isToolPreambleCollapsed = collapsedStreamBlocks.has(toolPreambleStreamId);
      const toolPreambleHtml = toolPreamble
        ? `
            <div class="tree-step-stream is-collapsible ${isToolPreambleCollapsed ? 'is-collapsed' : 'is-expanded'}">
              <button class="tree-stream-toggle" type="button" data-stream-id="${escapeHtml(toolPreambleStreamId)}" aria-label="toggle stream text">
                <span class="material-symbols-outlined">${isToolPreambleCollapsed ? 'keyboard_arrow_right' : 'keyboard_arrow_down'}</span>
              </button>
              <div class="tree-stream-text" data-stream-key="${escapeHtml(payloadId + '::preamble')}">${escapeHtml(toolPreamble)}</div>
            </div>
          `
        : '';
      const websiteIconsHtml2 = visibleDomains2.length
        ? `<span class="tool-site-icons">${visibleDomains2.map((domain) => `<img class="tool-site-icon" src="https://www.google.com/s2/favicons?domain=${encodeURIComponent(domain)}&sz=32" alt="${escapeHtml(domain)}" loading="lazy" />`).join('')}${hiddenDomainsCount2 ? `<span class="tool-site-more">+${hiddenDomainsCount2}</span>` : ''}</span>`
        : '';
      const inlineCommandActions = isPendingCommandTool
        ? `
            <span class="command-tool-actions">
              <button class="hitl-btn approve inline-command-approve command-tool-action-btn" type="button" ${actionLocked ? 'disabled' : ''}>Approve</button>
              <button class="hitl-btn reject inline-command-reject command-tool-action-btn" type="button" ${actionLocked ? 'disabled' : ''}>Deny</button>
            </span>
          `
        : '';
      const commandStateClass = isSshCommandTool
        ? isPendingCommandTool
          ? 'is-command-pending'
          : isSubmittedCommandTool
          ? 'is-command-submitted'
          : normalizedToolStatus === 'rejected'
          ? 'is-command-rejected'
          : normalizedToolStatus === 'error'
          ? 'is-command-error'
          : 'is-command-archived'
        : '';
      const toolDisplayName = isSshCommandTool
        ? `Ran ${escapeHtml(commandText || 'run_ssh_command')}`
        : isSkillInstructionsTool
        ? 'Reading the wazuh.md skill'
        : escapeHtml(tool.name || 'tool_call');
      const toolBodyHtml = isExpanded && hasExpandablePayload
        ? (() => {
            const pendingHint = isPendingCommandTool
              ? `<div class="command-tool-hint">${escapeHtml(commandGate?.message || 'Approve command execution')}</div>`
              : '';
            const terminalResult = tool.result
              ? `<pre class="terminal-output">${escapeHtml(toDisplayText(tool.result))}</pre>`
              : normalizedToolStatus === 'rejected'
              ? `<pre class="terminal-output is-empty is-denied">Command denied by user.</pre>`
              : normalizedToolStatus === 'error'
              ? `<pre class="terminal-output is-empty is-error">Command failed. Check backend logs for details.</pre>`
              : normalizedToolStatus === 'done'
              ? `<pre class="terminal-output is-empty">No output returned.</pre>`
              : `<pre class="terminal-output is-empty">Waiting for SSH result...</pre>`;
            const commandBody = commandText
              ? `<div class="terminal-command-line"><span class="terminal-prompt">$</span><span class="terminal-command-text">${escapeHtml(commandText)}</span></div>`
              : '';
            return `
              <div class="tree-tool-body ${isSshCommandTool ? 'is-command-tool-body' : ''}" style="width:100%;margin-top:4px;">
                ${isSshCommandTool ? `${pendingHint}<div class="terminal-output-wrap"><div class="terminal-head"><span class="terminal-head-dots"><span class="dot dot-red"></span><span class="dot dot-yellow"></span><span class="dot dot-green"></span></span><span class="terminal-head-title">wazuh-manager</span></div>${commandBody}${commandBody ? '<div class="terminal-divider"></div>' : ''}${terminalResult}</div>` : ''}
                ${!isSshCommandTool && tool.input ? `<div class="tree-payload-label">Input</div><pre class="tree-payload-value">${escapeHtml(asPretty(tool.input))}</pre>` : ''}
                ${!isSshCommandTool && tool.result ? `<div class="tree-payload-label">Result</div>${renderToolResult(tool.result)}` : ''}
              </div>
            `;
          })()
        : '';

      toolCards.push(`
        ${toolPreambleHtml}
        <div class="tree-tool ${isSshCommandTool ? `is-command-tool ${commandStateClass}` : ''}">
          <div class="tree-tool-header ${hasExpandablePayload ? 'payload-toggle' : ''}" ${hasExpandablePayload ? `data-payload-id="${escapeHtml(payloadId)}"` : ''}>
            ${toolIconHtml2}
            <span class="tree-tool-name">${toolDisplayName}</span>
            ${websiteIconsHtml2}
            ${inlineCommandActions}
            ${hasExpandablePayload ? `<span class="material-symbols-outlined tree-chevron">${isExpanded ? 'keyboard_arrow_up' : 'keyboard_arrow_down'}</span>` : ''}
          </div>
          ${toolBodyHtml}
        </div>
      `);
    });

    const toolHtmlFinal = toolItems.length
      ? `<div class="tree-tools-row ${isApplyStep ? 'is-command-list' : ''}">${toolCards.join('')}</div>`
      : '';
    const hasToolPreamble = suppressSecondaryFinderStream
      ? false
      : toolItems.some((tool) => String(toDisplayText(tool?.preamble || '')).trim());
    const pendingNarrativeHtml =
      toolItems.length > 0 && streamText && !hasToolPreamble && !showStreamNarrative
        ? `
            <div class="tree-step-stream is-collapsible ${collapsedStreamBlocks.has(`${key}::pending-stream`) ? 'is-collapsed' : 'is-expanded'}">
              <button class="tree-stream-toggle" type="button" data-stream-id="${escapeHtml(`${key}::pending-stream`)}" aria-label="toggle stream text">
                <span class="material-symbols-outlined">${collapsedStreamBlocks.has(`${key}::pending-stream`) ? 'keyboard_arrow_right' : 'keyboard_arrow_down'}</span>
              </button>
              <div class="tree-stream-text" data-stream-key="${escapeHtml(key + '::step')}">${escapeHtml(streamText)}</div>
            </div>
          `
        : '';
    const streamBlocksHtml = `${streamNarrativeHtml}${pendingNarrativeHtml}`;
    const streamBeforeToolsHtml = (isFinalSynthesisStep || toolItems.length > 0) ? '' : streamBlocksHtml;
    const streamAfterToolsHtml = (isFinalSynthesisStep || toolItems.length > 0) ? streamBlocksHtml : '';

    return {
      id: String(step.id || '').toLowerCase(),
      html: `
      <div class="tree-step ${isRunning ? 'running' : 'done'}">
        <div class="tree-step-header">
          <div class="tree-step-icon-wrapper"><span class="tree-step-dot"></span></div>
          <h4 class="tree-step-title ${isRunning ? 'wave-text' : ''}"${buildWaveStyle(isRunning)}>${escapeHtml(step.title)}</h4>
          <button class="tree-step-toggle" data-step-id="${escapeHtml(key)}" type="button" aria-label="toggle step details">
            <span class="material-symbols-outlined">${isExpanded ? 'keyboard_arrow_down' : 'keyboard_arrow_right'}</span>
          </button>
        </div>
        <div class="tree-step-body ${isExpanded ? 'is-expanded' : 'is-collapsed'} ${autoExpanding ? 'auto-expanding' : ''} ${autoCollapsing ? 'auto-collapsing' : ''}">
          ${visibleStepDetail ? `<div class="tree-step-detail">${escapeHtml(visibleStepDetail)}</div>` : ''}
          ${streamBeforeToolsHtml}
          ${toolHtmlFinal}
          ${streamAfterToolsHtml}
          ${stepResponseHtml}
        </div>
      </div>
    `
    };
  });

  const rows = rowEntries.map((entry) => entry.html);
  if (reportVisible) {
    const reportOpenStepHtml = `
      <div class="tree-step done report-open-step">
        <div class="tree-step-header">
          <div class="tree-step-icon-wrapper"><span class="tree-step-dot"></span></div>
          <h4 class="tree-step-title">Final Report</h4>
          <button class="step-report-open-btn report-step-open step-report-action ${currentWorkflowGate?.pending ? 'pulse-ring' : ''}" type="button" aria-label="Open final report">
            <span class="material-symbols-outlined">open_in_new</span>
            Open Report
          </button>
        </div>
      </div>
    `;
    const finalReportIndex = rowEntries.findIndex((entry) => entry.id === 'final_report');
    const detectionStepIndex = rowEntries.findIndex((entry) => entry.id === 'apply_detection_changes');
    const insertAt =
      finalReportIndex >= 0 ? finalReportIndex + 1 : detectionStepIndex >= 0 ? detectionStepIndex : rows.length;
    rows.splice(insertAt, 0, reportOpenStepHtml);
  }
  const rowsHtml = rows.join('');
  // Preserve scroll positions of expanded payload containers before re-render
  const listScrollTop = activityListEl.scrollTop;
  const savedScrollPositions = new Map();
  activityListEl.querySelectorAll('.tree-payload-value, .tree-code-content, .terminal-output').forEach((el) => {
    if (el.scrollTop > 0) {
      const parentTool = el.closest('.tree-tool');
      const payloadToggle = parentTool?.querySelector('.payload-toggle');
      const payloadId = payloadToggle?.dataset?.payloadId || '';
      if (payloadId) {
        const suffix = el.classList.contains('terminal-output') ? 'terminal' : 'payload';
        savedScrollPositions.set(`${payloadId}::${suffix}`, el.scrollTop);
      }
    }
  });

  activityListEl.innerHTML = `
    <div class="tree-stream">
      ${rowsHtml}
    </div>
  `;

  // Restore scroll positions after re-render
  if (savedScrollPositions.size > 0) {
    activityListEl.querySelectorAll('.payload-toggle').forEach((toggle) => {
      const payloadId = toggle.dataset?.payloadId || '';
      if (payloadId) {
        const toolEl = toggle.closest('.tree-tool');
        if (toolEl) {
          toolEl.querySelectorAll('.tree-payload-value, .tree-code-content').forEach((el) => {
            const saved = savedScrollPositions.get(`${payloadId}::payload`);
            if (saved !== undefined) {
              el.scrollTop = saved;
            }
          });
          toolEl.querySelectorAll('.terminal-output').forEach((el) => {
            const saved = savedScrollPositions.get(`${payloadId}::terminal`);
            if (saved !== undefined) {
              el.scrollTop = saved;
            }
          });
        }
      }
    });
  }
  activityListEl.scrollTop = listScrollTop;

  activityListEl.querySelectorAll('.payload-toggle').forEach((button) => {
    button.addEventListener('click', () => {
      const key = button.dataset.payloadId;
      if (!key) {
        return;
      }
      if (expandedPayloadSteps.has(key)) {
        expandedPayloadSteps.delete(key);
      } else {
        expandedPayloadSteps.add(key);
      }
      renderActivity(runId, activity, commandGate);
    });
  });

  activityListEl.querySelectorAll('.tree-step-toggle').forEach((button) => {
    button.addEventListener('click', () => {
      const stepId = button.dataset.stepId;
      if (!stepId) {
        return;
      }
      if (expandedStepDetails.has(stepId)) {
        expandedStepDetails.delete(stepId);
      } else {
        expandedStepDetails.add(stepId);
      }
      renderActivity(runId, activity, commandGate);
    });
  });

  activityListEl.querySelectorAll('.tree-stream-toggle').forEach((button) => {
    button.addEventListener('click', (event) => {
      event.preventDefault();
      event.stopPropagation();
      const streamId = button.dataset.streamId;
      if (!streamId) {
        return;
      }
      if (collapsedStreamBlocks.has(streamId)) {
        collapsedStreamBlocks.delete(streamId);
        // Fast-forward typing animation so it doesn't replay on expand
        streamTypingState.forEach((state, key) => {
          if (state && state.text) {
            state.shown = state.text.length;
          }
        });
      } else {
        collapsedStreamBlocks.add(streamId);
      }
      renderActivity(runId, activity, commandGate);
    });
  });

  activityListEl.querySelectorAll('.report-step-open').forEach((button) => {
    button.addEventListener('click', () => {
      openReportWindow();
    });
  });

  activityListEl.querySelectorAll('.inline-command-approve').forEach((button) => {
    button.addEventListener('click', (event) => {
      event.preventDefault();
      event.stopPropagation();
      submitHitlAction(currentRunId, currentCommandGate, 'approve').catch(() => {});
    });
  });

  activityListEl.querySelectorAll('.inline-command-reject').forEach((button) => {
    button.addEventListener('click', (event) => {
      event.preventDefault();
      event.stopPropagation();
      submitHitlAction(currentRunId, currentCommandGate, 'reject').catch(() => {});
    });
  });

}

async function loadRules() {
  const response = await fetch('/api/rules');
  const payload = await response.json().catch(() => ({}));
  rules = Array.isArray(payload.rules) ? payload.rules : [];
  if (!response.ok) {
    renderRulesEmptyState(payload.warning || payload.error || 'Unable to load SIEM rules. Check your indexer configuration.');
    return;
  }
  if (!rules.length) {
    renderRulesEmptyState(payload.warning || 'No SIEM rules were found for this configuration.');
    return;
  }

  manualRule = null;
  selectedRuleId = rules[0].id;
  if (manualRuleIdEl) {
    manualRuleIdEl.disabled = false;
  }
  if (manualRuleApplyEl) {
    manualRuleApplyEl.disabled = false;
  }
  if (rulesEmptyMessageEl) {
    rulesEmptyMessageEl.innerHTML = '';
    rulesEmptyMessageEl.classList.add('hidden');
  }
  renderRules();
  renderSelectedRule();
}

function stopActiveStream() {
  if (activeStreamAbortController) {
    activeStreamAbortController.abort();
    activeStreamAbortController = null;
  }
  if (streamReconnectTimer) {
    clearTimeout(streamReconnectTimer);
    streamReconnectTimer = null;
  }
}

function rememberStreamEventIndex(value) {
  if (value === null || value === undefined) {
    return;
  }
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return;
  }
  lastStreamEventIndex = numeric;
  if (streamState) {
    streamState.lastEventIndex = numeric;
  }
  persistRunContext();
}

async function* iterateNdjsonResponse(response) {
  if (!response?.body || typeof response.body.getReader !== 'function') {
    return;
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';

  while (true) {
    const { value, done } = await reader.read();
    buffer += decoder.decode(value || new Uint8Array(), { stream: !done });

    let lineBreakIndex = buffer.indexOf('\n');
    while (lineBreakIndex >= 0) {
      const rawLine = buffer.slice(0, lineBreakIndex);
      buffer = buffer.slice(lineBreakIndex + 1);
      const line = rawLine.trim();
      if (line) {
        try {
          yield JSON.parse(line);
        } catch (_error) {
          // Ignore malformed partial stream lines.
        }
      }
      lineBreakIndex = buffer.indexOf('\n');
    }

    if (done) {
      break;
    }
  }

  const trailing = buffer.trim();
  if (trailing) {
    try {
      yield JSON.parse(trailing);
    } catch (_error) {
      // ignore malformed trailing stream line
    }
  }
}

function applyStreamEnvelope(payload) {
  if (!payload || typeof payload !== 'object') {
    return;
  }

  setRunContext(payload.runId || payload.run_id || '', payload.sessionId || payload.session_id || '');

  if (payload.type === 'stream_opened') {
    fineTuneStatusEl.textContent =
      payload.mode === 'resume' ? 'Reconnected to live workflow stream.' : 'Live workflow stream connected.';
    return;
  }

  if (payload.type === 'run_started') {
    fineTuneStatusEl.textContent = 'Workflow started. Streaming live agent events...';
    return;
  }

  if (payload.type === 'workflow_event') {
    const event = payload.event || {};
    rememberStreamEventIndex(event.event_index ?? event.eventIndex);
    applyWorkflowEvent(event);
    return;
  }

  if (payload.type === 'run_output') {
    const output = payload.output || {};
    rememberStreamEventIndex(output.event_index ?? output.eventIndex);
    applyRunOutputSnapshot(output);
    renderStreamState();
    return;
  }

  if (payload.type === 'snapshot') {
    const snapshot = payload.payload || {};
    updateRunPresentation(snapshot, normalizeActivity(snapshot.activity));
    renderActivity(payload.runId || currentRunId || '', normalizeActivity(snapshot.activity), null);
    return;
  }

  if (payload.type === 'error') {
    throw new Error(payload.error || payload.details || 'Streaming failed');
  }
}

function shouldKeepStreamAlive() {
  const status = normalizeRunStatus(streamState?.status || '');
  return Boolean(
    currentRunId &&
      currentRunSessionId &&
      status === 'running' &&
      !streamState?.workflowGate?.pending &&
      !streamState?.commandGate?.pending
  );
}

function scheduleStreamResume(reason = '') {
  if (!shouldKeepStreamAlive() || streamReconnectTimer) {
    return;
  }
  const delay = Math.min(10000, 1200 + streamReconnectAttempts * 1200);
  streamReconnectAttempts += 1;
  fineTuneStatusEl.textContent = reason || `Stream interrupted. Reconnecting...`;
  streamReconnectTimer = setTimeout(() => {
    streamReconnectTimer = null;
    startRunStream({
      runId: currentRunId,
      sessionId: currentRunSessionId,
      lastEventIndex: lastStreamEventIndex,
      resume: true
    }).catch(() => {});
  }, delay);
}

async function startRunStream(options = {}) {
  const resume = options.resume === true;
  const runId = String(options.runId || currentRunId || '').trim();
  const sessionId = String(options.sessionId || currentRunSessionId || '').trim();

  if (resume && (!runId || !sessionId)) {
    throw new Error('runId and sessionId are required to resume stream');
  }

  stopActiveStream();
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }

  const controller = new AbortController();
  activeStreamAbortController = controller;
  const response = resume
    ? await fetch(`/api/fine-tune/${encodeURIComponent(runId)}/resume`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sessionId,
          lastEventIndex: Number.isFinite(Number(options.lastEventIndex))
            ? Number(options.lastEventIndex)
            : lastStreamEventIndex
        }),
        signal: controller.signal
      })
    : await fetch('/api/fine-tune/stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ruleId: options.ruleId,
          ruleName: options.ruleName
        }),
        signal: controller.signal
      });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.error || 'Failed to open live workflow stream');
  }

  try {
    let sawLiveCommandPause = false;
    for await (const payload of iterateNdjsonResponse(response)) {
      applyStreamEnvelope(payload);
      if (streamState?.commandGate?.pending) {
        sawLiveCommandPause = true;
        awaitingPostUserInputRunId = '';
      }
    }
    if (awaitingPostUserInputRunId === runId && !sawLiveCommandPause) {
      if (streamState) {
        streamState.status = 'running';
        streamState.workflowGate = null;
        streamState.commandGate = null;
        streamState.phaseLabel = 'Waiting for Detection Engineer stream...';
        renderStreamState();
      }
      activeStreamAbortController = null;
      scheduleStreamResume('Waiting for Detection Engineer stream...');
      return;
    }
    if (!sawLiveCommandPause) {
      await hydrateRunFromSnapshot({ runId }).catch(() => {});
    }
    streamReconnectAttempts = 0;
    activeStreamAbortController = null;
    if (shouldKeepStreamAlive()) {
      scheduleStreamResume('Live stream closed. Reconnecting...');
    }
  } catch (error) {
    activeStreamAbortController = null;
    if (error?.name === 'AbortError') {
      return;
    }
    if (shouldKeepStreamAlive()) {
      scheduleStreamResume('Connection issue. Reconnecting to live stream...');
      return;
    }
    throw error;
  }
}

async function restoreRunFromStorage() {
  const context = readRunContextFromUrl();
  if (!context) {
    return false;
  }
  if (context.source === 'storage') {
    const shouldResume = window.confirm(
      'You have an unfinished workflow run. Click OK to resume it, or Cancel to start a new run.'
    );
    if (!shouldResume) {
      clearPersistedRunContext();
      fineTuneStatusEl.textContent = '';
      return false;
    }
  }

  if (!streamState) {
    streamState = createInitialStreamState();
  }
  setRunContext(context.runId, context.sessionId);
  streamState.status = 'running';
  streamState.workflowGate = null;
  streamState.commandGate = null;
  streamState.phaseLabel = 'Restoring previous workflow state...';
  workflowGateApproved = true;
  setRuleSelectionLocked(true);
  agentBlockEl.classList.remove('hidden');
  updateRunPresentation(
    {
      status: 'running',
      stage: 'planning',
      phaseLabel: 'Restoring previous workflow state...'
    },
    []
  );
  renderActivity(currentRunId, [], null);
  fineTuneStatusEl.textContent = 'Restoring previous workflow state...';
  lastStreamEventIndex = context.lastEventIndex;
  if (streamState) {
    streamState.lastEventIndex = context.lastEventIndex;
  }
  await hydrateRunFromSnapshot({ runId: currentRunId }).catch(() => {});
  const restoredStatus = normalizeRunStatus(streamState?.status || '');
  if (
    restoredStatus === 'paused' ||
    streamState?.workflowGate?.pending ||
    streamState?.commandGate?.pending
  ) {
    startPolling(currentRunId, currentRunSessionId);
    return true;
  }
  startRunStream({
    runId: currentRunId,
    sessionId: currentRunSessionId,
    lastEventIndex: lastStreamEventIndex,
    resume: true
  }).catch(() => {
    startPolling(currentRunId, currentRunSessionId);
  });
  return true;
}

function finalizeRun(statusText) {
  stopActiveStream();
  clearPersistedRunContext();
  fineTuneBtnEl.disabled = false;
  fineTuneBtnEl.innerHTML = fineTuneBtnDefaultHtml;
  fineTuneStatusEl.textContent = statusText;
  setRuleSelectionLocked(false);
}

function startPolling(runId, sessionId = '') {
  currentRunSessionId = sessionId || currentRunSessionId || '';
  setRunContext(runId, currentRunSessionId);
  lastPollingRenderSignature = '';
  let consecutivePollErrors = 0;
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }

  const poll = async () => {
    try {
      const query = currentRunSessionId ? `?sessionId=${encodeURIComponent(currentRunSessionId)}` : '';
      const response = await fetch(`/api/fine-tune/${encodeURIComponent(runId)}${query}`);
      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        const details = String(payload?.details || '').trim();
        const baseMessage = String(payload?.error || '').trim() || 'Failed to fetch fine-tuning status';
        const normalized = `${baseMessage} ${details}`.toLowerCase();
        if (
          response.status === 404 ||
          normalized.includes('run not found') ||
          normalized.includes('not found on backend')
        ) {
          clearPersistedRunContext();
          throw new Error('Run not found or expired. Please start a new run.');
        }
        throw new Error(baseMessage);
      }

      const payload = await response.json();
      consecutivePollErrors = 0;
      setRunContext(
        payload.runId || payload.run_id || runId,
        payload.sessionId || payload.session_id || currentRunSessionId
      );
      const runStatus = normalizeRunStatus(payload.status);
      const rawActivity = normalizeActivity(payload.activity);
      let { workflowGate, commandGate } = splitGates(payload);
      if (runStatus === 'completed' || runStatus === 'error') {
        workflowGate = null;
        commandGate = null;
      } else {
        ({ workflowGate, commandGate } = preserveLiveCommandGate(runId, workflowGate, commandGate));
      }
      currentWorkflowGate = workflowGate;
      currentCommandGate = commandGate;
      applyPollingCommandStateFromActivity(rawActivity);
      applyPollingCommandState(payload.step_executor_runs || payload.stepExecutorRuns || []);
      if (payload.step_executor_runs || payload.stepExecutorRuns) {
        const runs = payload.step_executor_runs || payload.stepExecutorRuns;
        applyExecutorRunsCollection(runs);
      }

      // Auto-detect approval from polling state: if the apply step is running/done, the gate was approved
      const applyStepFromPoll = rawActivity.find((s) => s.id === 'apply_detection_changes');
      if (
        applyStepFromPoll &&
        (applyStepFromPoll.status === 'running' || applyStepFromPoll.status === 'done') &&
        !workflowGate?.pending
      ) {
        workflowGateApproved = true;
      }

      // Hide Detection Rule Apply until workflow gate is approved
      const activity = rawActivity.filter((step) => {
        if (step.id === 'apply_detection_changes' && !workflowGateApproved && step.status !== 'done') {
          return false;
        }
        return true;
      });
      const renderSignature = buildPollingRenderSignature(payload, activity, workflowGate, commandGate);
      const shouldRender = renderSignature !== lastPollingRenderSignature;
      lastPollingRenderSignature = renderSignature;

      agentBlockEl.classList.remove('hidden');
      if (shouldRender) {
        updateRunPresentation(payload, activity);
        renderActivity(runId, activity, commandGate);
        renderReport(Boolean(payload.reportReady || payload.report_ready) ? payload.report : null);
        renderReportWindowFooter();
      }
      setRuleSelectionLocked(runStatus === 'running' || runStatus === 'paused');

      if (runStatus === 'completed') {
        if (pollTimer) {
          clearInterval(pollTimer);
          pollTimer = null;
        }
        finalizeRun('Fine-tuning completed.');
      }

      if (runStatus === 'error') {
        if (pollTimer) {
          clearInterval(pollTimer);
          pollTimer = null;
        }
        finalizeRun('Fine-tuning failed.');
      }
    } catch (error) {
      const message = String(error?.message || 'Failed to fetch fine-tuning status');
      const isFatalNotFound = message.toLowerCase().includes('run not found or expired');
      if (isFatalNotFound) {
        if (pollTimer) {
          clearInterval(pollTimer);
          pollTimer = null;
        }
        finalizeRun(message);
        return;
      }

      consecutivePollErrors += 1;
      if (consecutivePollErrors < 4) {
        fineTuneStatusEl.textContent = `Connection issue. Retrying... (${consecutivePollErrors}/3)`;
        return;
      }

      if (pollTimer) {
        clearInterval(pollTimer);
        pollTimer = null;
      }
      finalizeRun(message);
    }
  };

  poll().catch(() => {});
  pollTimer = setInterval(() => {
    poll().catch(() => {});
  }, 2200);
}

fineTuneBtnEl.addEventListener('click', async () => {
  const rule = currentRule();
  if (!rule) {
    return;
  }

  fineTuneBtnEl.disabled = true;
  fineTuneBtnEl.innerHTML = '<span class="material-symbols-outlined">sync</span>Processing...';
  fineTuneStatusEl.textContent = 'Starting fine-tuning run...';
  currentRunId = '';
  currentRunSessionId = '';
  lastStreamEventIndex = null;
  streamReconnectAttempts = 0;
  clearPersistedRunContext();
  seenStepIds.clear();
  expandedStepDetails.clear();
  expandedPayloadSteps.clear();
  collapsedStreamBlocks.clear();
  streamTypingState.clear();
  if (streamTypingTimer) {
    clearTimeout(streamTypingTimer);
    streamTypingTimer = null;
  }
  lastRenderedRunId = '';
  lastRenderedActivity = [];
  lastRenderedCommandGate = null;
  lastPollingRenderSignature = '';
  autoFocusedRunningStepKey = '';
  reportBoxEl.classList.remove('revealed');
  streamState = createInitialStreamState();
  currentWorkflowGate = null;
  currentCommandGate = null;
  commandHistory = [];
  workflowGateApproved = false;
  fulfilledUserInputGateRunId = '';
  awaitingPostUserInputRunId = '';
  recommendationInputText = '';
  setRuleSelectionLocked(true);
  renderReportWindowFooter();

  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
  stopActiveStream();

  agentBlockEl.classList.remove('hidden');
  renderReport(null);
  renderActivity('', [], null);
  updateRunPresentation(
    {
      status: 'running',
      progressPct: 3,
      stage: 'planning',
      phaseLabel: `Booting agent for ${rule.id}...`
    },
    []
  );

  try {
    fineTuneStatusEl.textContent = 'Opening live workflow stream...';
    await startRunStream({
      ruleId: rule.id,
      ruleName: rule.name,
      resume: false
    });
  } catch (error) {
    finalizeRun(error.message);
  }
});

if (reportWindowCloseEl) {
  reportWindowCloseEl.addEventListener('click', closeReportWindow);
}

if (reportWindowDownloadEl) {
  reportWindowDownloadEl.addEventListener('click', downloadReportAsMarkdown);
}

if (reportModalEl) {
  reportModalEl.addEventListener('click', (event) => {
    if (event.target === reportModalEl) {
      closeReportWindow();
    }
  });
}

if (reportWindowApproveEl) {
  reportWindowApproveEl.addEventListener('click', () => {
    submitHitlAction(currentRunId, currentWorkflowGate, 'approve').catch(() => {});
  });
}

if (reportWindowRejectEl) {
  reportWindowRejectEl.addEventListener('click', () => {
    submitHitlAction(currentRunId, currentWorkflowGate, 'reject').catch(() => {});
  });
}

if (reportWindowInputTextEl) {
  reportWindowInputTextEl.addEventListener('input', () => {
    recommendationInputText = reportWindowInputTextEl.value || '';
    renderReportWindowFooter();
  });
  reportWindowInputTextEl.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
      event.preventDefault();
      submitRecommendationSelection().catch(() => {});
    }
  });
}

if (reportWindowSubmitInputEl) {
  reportWindowSubmitInputEl.addEventListener('click', () => {
    submitRecommendationSelection().catch(() => {});
  });
}

document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') {
    closeReportWindow();
    closeSettingsModal();
  }
});

if (sideCollapseBtnEl) {
  const storedValue = localStorage.getItem(SIDEBAR_COLLAPSED_KEY);
  applySidebarCollapsed(storedValue === '1');
  sideCollapseBtnEl.addEventListener('click', () => {
    applySidebarCollapsed(true);
    localStorage.setItem(SIDEBAR_COLLAPSED_KEY, '1');
  });
}

if (sideExpandBtnEl) {
  sideExpandBtnEl.addEventListener('click', () => {
    applySidebarCollapsed(false);
    localStorage.setItem(SIDEBAR_COLLAPSED_KEY, '0');
  });
}

if (sideSignoutBtnEl) {
  sideSignoutBtnEl.addEventListener('click', async () => {
    try {
      await fetch('/api/auth/logout', { method: 'POST' });
    } catch (_error) {
      // ignore network errors on logout
    }
    clearAuthToken();
    redirectToLogin();
  });
}

if (sideSettingsBtnEl) {
  sideSettingsBtnEl.addEventListener('click', () => {
    openSettingsModal().catch((error) => {
      setSettingsStatus(error.message || 'Failed to open settings.', true);
    });
  });
}

if (settingsCloseBtnEl) {
  settingsCloseBtnEl.addEventListener('click', closeSettingsModal);
}

if (settingsCancelBtnEl) {
  settingsCancelBtnEl.addEventListener('click', closeSettingsModal);
}

if (settingsSaveBtnEl) {
  settingsSaveBtnEl.addEventListener('click', () => {
    saveSettingsFromModal().catch((error) => {
      setSettingsStatus(error.message || 'Failed to save settings.', true);
    });
  });
}

if (settingsModalEl) {
  settingsModalEl.addEventListener('click', (event) => {
    if (event.target === settingsModalEl) {
      closeSettingsModal();
    }
  });
}

if (settingsLoadModelsBtnEl) {
  settingsLoadModelsBtnEl.addEventListener('click', () => {
    loadSettingsModels(String(settingsAiModelEl?.value || '').trim()).catch((error) => {
      setSettingsStatus(error.message || 'Failed to load models.', true);
    });
  });
}

if (settingsAiProviderEl) {
  settingsAiProviderEl.addEventListener('change', () => {
    setSettingsStatus('');
    loadSettingsModels('').catch((error) => {
      setSettingsStatus(error.message || 'Failed to load models.', true);
    });
  });
}

if (settingsAiKeyEl) {
  settingsAiKeyEl.addEventListener('input', () => {
    setSettingsStatus('');
    scheduleSettingsModelLoad();
  });
  settingsAiKeyEl.addEventListener('blur', () => {
    loadSettingsModels(String(settingsAiModelEl?.value || '').trim()).catch((error) => {
      setSettingsStatus(error.message || 'Failed to load models.', true);
    });
  });
}

if (settingsSshImportBtnEl && settingsSshKeyFileEl) {
  settingsSshImportBtnEl.addEventListener('click', () => {
    settingsSshKeyFileEl.click();
  });
  settingsSshKeyFileEl.addEventListener('change', () => {
    const file = settingsSshKeyFileEl.files && settingsSshKeyFileEl.files[0] ? settingsSshKeyFileEl.files[0] : null;
    handleSettingsSshKeyUpload(file).catch((error) => {
      setSettingsStatus(error.message || 'Failed to import SSH key file.', true);
    }).finally(() => {
      settingsSshKeyFileEl.value = '';
    });
  });
}

if (settingsSshAuthModeEl) {
  settingsSshAuthModeEl.addEventListener('change', () => {
    setSettingsSshAuthMode(settingsSshAuthModeEl.value);
  });
}

if (settingsSshAuthEl) {
  settingsSshAuthEl.addEventListener('input', () => {
    if (settingsSshAuthMode !== 'key_file') {
      setSettingsSshAuthMode('password');
    }
  });
}

if (settingsSshKeyTextEl) {
  settingsSshKeyTextEl.addEventListener('input', () => {
    setSettingsSshAuthMode('key_file');
  });
}

if (settingsTestIndexerBtnEl) {
  settingsTestIndexerBtnEl.addEventListener('click', () => {
    testSettingsIndexerConnection().catch(() => {});
  });
}

if (settingsTestManagerBtnEl) {
  settingsTestManagerBtnEl.addEventListener('click', () => {
    testSettingsManagerConnection().catch(() => {});
  });
}

if (sideAvatarBtnEl && sideAvatarInputEl) {
  sideAvatarBtnEl.addEventListener('click', () => {
    sideAvatarInputEl.click();
  });
}

if (sideAvatarInputEl) {
  sideAvatarInputEl.addEventListener('change', () => {
    const file = sideAvatarInputEl.files && sideAvatarInputEl.files[0] ? sideAvatarInputEl.files[0] : null;
    uploadAvatarFromFile(file).catch((error) => {
      fineTuneStatusEl.textContent = error.message;
    }).finally(() => {
      sideAvatarInputEl.value = '';
    });
  });
}

if (manualRuleApplyEl) {
  manualRuleApplyEl.addEventListener('click', () => {
    applyManualRuleSelection().catch((error) => {
      fineTuneStatusEl.textContent = error.message;
    });
  });
}

if (manualRuleIdEl) {
  manualRuleIdEl.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
      event.preventDefault();
      applyManualRuleSelection().catch((error) => {
        fineTuneStatusEl.textContent = error.message;
      });
    }
  });
}

(async () => {
  try {
    await ensureAuthenticated();
    await loadUserProfile();
    await loadRules();
    await restoreRunFromStorage();
  } catch (error) {
    fineTuneStatusEl.textContent = error.message;
  }
})();
