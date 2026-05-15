const fs = require('fs')
const http = require('http')
const https = require('https')
const dns = require('dns').promises
const net = require('net')
const path = require('path')
const crypto = require('crypto')
const selfsigned = require('selfsigned')
const express = require('express')
const manifest = require('../config/manifest')
const { encrypt, decrypt } = require('../utils/crypto')
const { decodeFileStateToken, decodePlaybackStateToken } = require('../utils/opaqueState')
const { handleCatalog } = require('../handlers/catalog')
const { handleStream } = require('../handlers/stream')
const { handleMeta } = require('../handlers/meta')
const { ProwlarrClient } = require('../clients/prowlarr')
const { QBitClient } = require('../clients/qbittorrent')
const { normalizeSportsPosterTemplate } = require('../utils/sportsPosterTemplates')
const {
  ENTITLEMENT_SOURCE,
  FREE_SPORTS_POSTER_TEMPLATE,
  resolveSportsPosterEntitlement,
  verifyStampedSportsPosterEntitlement,
  clampSportsPosterTemplate
} = require('../utils/entitlement')
const { autoProvisionWindows, ensureWindowsLanAccess, discoverProwlarrConfig } = require('../utils/provision')
const { getLanIpv4Addresses, normalizeLocalHostname, startLanAlias } = require('../utils/lanAlias')
const { buildLocalModeUrls } = require('../utils/localInstallUrls')
const { isBlockedPrivateTargetHost, isPrivateIpv4, isPrivateIpv6 } = require('../utils/privateTargetHosts')
const { normalizeRelayUrl } = require('../utils/relayUrl')
const { stripRemoteSeedboxLanFields } = require('../utils/remoteSeedboxConfig')
const { resolveRuntimeDir } = require('../utils/runtimeDir')
const { ensureServerAdminToken } = require('../utils/serverAdminToken')
const { parseTorrentFileName, fetchTorrentPayload } = require('../utils/torrentPayload')
const { findVideoFile, hasPackedArchiveFiles, isSampleVideoName, isArchiveFileName, findPackedArchiveFiles } = require('../utils/streams')
const { findExtractedArchiveVideoPath, ensurePackedArchiveExtracted } = require('../utils/archiveExtraction')
const { buildPlaybackFileUrl } = require('../utils/fileServing')
const { normalizeLocalStorageRoots, findExistingLocalFilePath } = require('../utils/localStorageRoots')
const { PairStore } = require('../utils/pairStore')
const { StremioLinkStore } = require('../utils/stremioLinkStore')
const { RateLimiter } = require('../utils/rateLimiter')
const {
  AccountStore,
  normalizeAccountEmail,
  normalizeStremioUserId,
  hashStremioAuthKey
} = require('../utils/accountStore')
const { createAuthToken, verifyAuthToken, parseBearerToken } = require('../utils/authToken')
const { loadSecureJsonFile, saveSecureJsonFile } = require('../utils/secureJsonFile')
const { buildMetaPlaceholder } = require('../utils/metaPlaceholder')
const {
  redactSensitiveText,
  createRedactingLogger,
  installConsoleRedaction
} = require('../utils/logRedaction')

loadLocalEnv()

const EXPLICIT_SELF_HOST_SERVER_MODE = /^(1|true|yes|on)$/i.test(String(process.env.PVTKRRX_SELF_HOST_MODE || '').trim())
const IS_HOSTED_RELAY_RUNTIME = (
  !EXPLICIT_SELF_HOST_SERVER_MODE &&
  /^(1|true|yes|on)$/i.test(String(process.env.PVTKRRX_HOSTED_RELAY || '').trim())
)
const SELF_HOST_SERVER_MODE = !IS_HOSTED_RELAY_RUNTIME && EXPLICIT_SELF_HOST_SERVER_MODE
const TRUST_PROXY_ENABLED = /^(1|true|yes|on)$/i.test(String(
  process.env.PVTKRRX_TRUST_PROXY ||
  (IS_HOSTED_RELAY_RUNTIME ? 'true' : 'false')
).trim())
const parsedTrustProxyHops = parseInt(process.env.PVTKRRX_TRUST_PROXY_HOPS || '1', 10)
const TRUST_PROXY_HOPS = Number.isFinite(parsedTrustProxyHops) && parsedTrustProxyHops > 0
  ? parsedTrustProxyHops
  : 1
const EXPRESS_TRUST_PROXY_SETTING = TRUST_PROXY_ENABLED ? TRUST_PROXY_HOPS : false
const STREAM_WAIT_TIMEOUT_MS = parseInt(process.env.STREAM_WAIT_TIMEOUT_MS || '90000', 10)
const STREAM_WAIT_INTERVAL_MS = parseInt(process.env.STREAM_WAIT_INTERVAL_MS || '2000', 10)
const STREAM_RANGE_WAIT_TIMEOUT_MS = parseInt(process.env.STREAM_RANGE_WAIT_TIMEOUT_MS || '45000', 10)
const STREAM_RANGE_WAIT_INTERVAL_MS = parseInt(process.env.STREAM_RANGE_WAIT_INTERVAL_MS || '500', 10)
const STREAM_READY_START_FRACTION = parseStartFraction(
  process.env.STREAM_READY_START_PERCENT ||
  process.env.STREAM_READY_MIN_PROGRESS ||
  '0.5%'
)
const STREAM_READY_MIN_BYTES = parseByteCount(process.env.STREAM_READY_MIN_BYTES || '24MB', 24 * 1024 * 1024)
const STREAM_PRIORITIZE_LAST_PIECES = String(
  process.env.STREAM_PRIORITIZE_LAST_PIECES ||
  (SELF_HOST_SERVER_MODE ? 'false' : 'true')
).trim().toLowerCase() !== 'false'
const WATCHED_DELETE_THRESHOLD = Math.max(0.5, Math.min(0.99, parseFloat(process.env.PVTKRRX_WATCHED_DELETE_THRESHOLD || '0.95')))
const WATCHED_DELETE_GRACE_MS = Math.max(0, parseInt(process.env.PVTKRRX_WATCHED_DELETE_GRACE_MS || '180000', 10))
// Pairing should be hash-first and stable: desktop publishes LAN endpoint, hosted token hash resolves it.
// Keep TTL long enough to avoid noisy relay chatter; desktop still refreshes periodically.
const LAN_PAIR_TTL_SECONDS = Math.max(300, parseInt(process.env.PVTKRRX_LAN_PAIR_TTL_SECONDS || '21600', 10))
const parsedLanPairHeartbeatMs = parseInt(process.env.PVTKRRX_LAN_PAIR_HEARTBEAT_MS || '720000', 10)
const LAN_PAIR_HEARTBEAT_MS = Number.isFinite(parsedLanPairHeartbeatMs) ? parsedLanPairHeartbeatMs : 720000
const parsedLanPairFreshnessMs = parseInt(process.env.PVTKRRX_LAN_PAIR_FRESHNESS_MS || '', 10)
// Store TTL can stay long for repair/debug flows, but redirect decisions should stop trusting stale hosts quickly.
const LAN_PAIR_FRESHNESS_MS = Number.isFinite(parsedLanPairFreshnessMs) && parsedLanPairFreshnessMs > 0
  ? parsedLanPairFreshnessMs
  : Math.min(
    LAN_PAIR_TTL_SECONDS * 1000,
    Math.max(
      180000,
      LAN_PAIR_HEARTBEAT_MS + Math.max(180000, Math.floor(LAN_PAIR_HEARTBEAT_MS * 0.25))
    )
  )
const LAN_PAIR_BIND_PUBLIC_IP = String(process.env.PVTKRRX_LAN_PAIR_BIND_PUBLIC_IP || 'false').trim().toLowerCase() === 'true'
const LAN_PAIR_LOCK_HOST = String(process.env.PVTKRRX_LAN_PAIR_LOCK_HOST || 'true').trim().toLowerCase() !== 'false'
const LAN_PAIR_RATE_LIMIT_WINDOW_MS = Math.max(1000, parseInt(process.env.PVTKRRX_LAN_PAIR_RATE_LIMIT_WINDOW_MS || '60000', 10))
const AUTH_TOKEN_TTL_SECONDS = Math.max(900, parseInt(process.env.PVTKRRX_AUTH_TOKEN_TTL_SECONDS || '2592000', 10))
const STREMIO_API_BASE_URL = normalizeBaseUrl(process.env.PVTKRRX_STREMIO_API_BASE_URL || 'https://api.strem.io')
const STREMIO_API_TIMEOUT_MS = Math.max(2000, parseInt(process.env.PVTKRRX_STREMIO_API_TIMEOUT_MS || '10000', 10))
const STREMIO_AUTH_KEY_REGEX = /^[A-Za-z0-9._~+/=-]{16,1024}$/
const STREMIO_AUTH_KEY_CAPTURE_PATTERN = '[A-Za-z0-9._~+/=-]{16,1024}'
const STREMIO_AUTH_SCAN_DIRS_OVERRIDE = String(process.env.PVTKRRX_STREMIO_AUTH_SCAN_DIRS || '').trim()
const SENSITIVE_WEB_ORIGINS = parseOriginAllowlist(
  process.env.PVTKRRX_ALLOWED_WEB_ORIGINS || 'https://www.pvtkrrx.cc'
)
const CSRF_COOKIE_NAME = 'pvtkrrx_csrf'
const SECRET_CONFIG_FIELDS = Object.freeze([
  'jackettApiKey',
  'qbitUsername',
  'qbitPassword',
  'fileServerAuth',
  'sportsPosterMemberToken'
])
const watchedDeleteTimers = new Map()
const watchedDeleteInFlight = new Set()
const rateLimiters = {
  encrypt: new RateLimiter(LAN_PAIR_RATE_LIMIT_WINDOW_MS, Math.max(5, parseInt(process.env.PVTKRRX_ENCRYPT_MAX_PER_WINDOW || '30', 10))),
  testConnection: new RateLimiter(LAN_PAIR_RATE_LIMIT_WINDOW_MS, Math.max(5, parseInt(process.env.PVTKRRX_TEST_CONNECTION_MAX_PER_WINDOW || '20', 10))),
  auth: new RateLimiter(LAN_PAIR_RATE_LIMIT_WINDOW_MS, Math.max(5, parseInt(process.env.PVTKRRX_AUTH_MAX_PER_WINDOW || '20', 10))),
  sportsmeta: new RateLimiter(LAN_PAIR_RATE_LIMIT_WINDOW_MS, Math.max(10, parseInt(process.env.PVTKRRX_SPORTSMETA_MAX_PER_WINDOW || '60', 10))),
  heartbeat: new RateLimiter(LAN_PAIR_RATE_LIMIT_WINDOW_MS, Math.max(5, parseInt(process.env.PVTKRRX_LAN_PAIR_HEARTBEAT_MAX_PER_WINDOW || '30', 10))),
  status: new RateLimiter(LAN_PAIR_RATE_LIMIT_WINDOW_MS, Math.max(5, parseInt(process.env.PVTKRRX_LAN_PAIR_STATUS_MAX_PER_WINDOW || '60', 10)))
}
const DEFAULT_LOCAL_HOSTNAME = 'pvtkrrx.local'

function parseStartFraction(raw) {
  const text = String(raw || '').trim()
  if (!text) return 0.005
  const hasPercent = text.endsWith('%')
  const numeric = parseFloat(hasPercent ? text.slice(0, -1) : text)
  if (!Number.isFinite(numeric) || numeric <= 0) return 0.005

  let fraction
  if (hasPercent || numeric > 1) {
    fraction = numeric / 100
  } else {
    fraction = numeric
  }
  return Math.max(0.001, Math.min(0.99, fraction))
}

function parseByteCount(raw, fallback) {
  const text = String(raw || '').trim().toLowerCase()
  if (!text) return fallback

  const match = text.match(/^(\d+(?:\.\d+)?)\s*(b|kb|mb|gb)?$/i)
  if (!match) return fallback

  const value = Number.parseFloat(match[1])
  if (!Number.isFinite(value) || value <= 0) return fallback

  const unit = String(match[2] || 'b').toLowerCase()
  const multiplier = unit === 'gb'
    ? 1024 * 1024 * 1024
    : unit === 'mb'
      ? 1024 * 1024
      : unit === 'kb'
        ? 1024
        : 1

  return Math.max(1, Math.floor(value * multiplier))
}

function loadLocalEnv() {
  const envPath = path.join(__dirname, '..', '..', '.env')
  if (!fs.existsSync(envPath)) return

  const lines = fs.readFileSync(envPath, 'utf8').split(/\r?\n/)
  for (const raw of lines) {
    const line = raw.trim()
    if (!line || line.startsWith('#')) continue
    const idx = line.indexOf('=')
    if (idx === -1) continue
    const key = line.slice(0, idx).trim()
    let value = line.slice(idx + 1).trim()
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1)
    }
    if (!process.env[key]) process.env[key] = value
  }
}

// Keep Node/server console output on the same redaction policy Electron already uses.
installConsoleRedaction(console)

if (!process.env.ENCRYPTION_SECRET && process.env.NODE_ENV !== 'production') {
  process.env.ENCRYPTION_SECRET = 'pvtkrrx-local-dev-secret-change-me'
  console.warn('[PVTKRRX] ENCRYPTION_SECRET missing; using local development fallback secret.')
}

const runtimeDir = resolveRuntimeDir()
const serverAdminState = SELF_HOST_SERVER_MODE
  ? ensureServerAdminToken(runtimeDir, { env: process.env, createIfMissing: true })
  : {
      token: '',
      created: false,
      source: 'disabled',
      path: ''
    }
const localConfigPath = path.join(runtimeDir, 'local-config.json')
const lanPairStore = new PairStore({
  filePath: process.env.PVTKRRX_PAIR_STORE_FILE || path.join(runtimeDir, 'lan-pair-store.json')
})
const accountStore = new AccountStore({
  filePath: process.env.PVTKRRX_ACCOUNT_STORE_FILE || path.join(runtimeDir, 'accounts-store.json')
})
const stremioLinkStore = new StremioLinkStore({
  filePath: process.env.PVTKRRX_STREMIO_LINK_STORE_FILE || path.join(runtimeDir, 'stremio-link-store.json')
})
let bootLanAccessPromise = null
let localProviderWarmupPromise = null
let localConfigRepairPromise = null
let localConfigCache = {
  loadedAt: 0,
  exists: false,
  mtimeMs: 0,
  size: 0,
  value: null
}

if (serverAdminState.created && serverAdminState.path) {
  console.warn(`[self-host] Self-host password created at ${serverAdminState.path}`)
}

function cloneJsonValue(value) {
  if (value === null || value === undefined) return value
  return JSON.parse(JSON.stringify(value))
}

function getLocalConfigSignature() {
  try {
    const stat = fs.statSync(localConfigPath)
    return {
      exists: true,
      mtimeMs: Number(stat.mtimeMs || 0),
      size: Number(stat.size || 0)
    }
  } catch (_) {
    return {
      exists: false,
      mtimeMs: 0,
      size: 0
    }
  }
}

function rememberLocalConfigCache(value, signature = null) {
  const sig = signature || getLocalConfigSignature()
  localConfigCache = {
    loadedAt: Date.now(),
    exists: sig.exists === true,
    mtimeMs: Number(sig.mtimeMs || 0),
    size: Number(sig.size || 0),
    value: cloneJsonValue(value)
  }
}

function localConfigCacheMatches(signature) {
  return (
    localConfigCache.exists === (signature.exists === true) &&
    Number(localConfigCache.mtimeMs || 0) === Number(signature.mtimeMs || 0) &&
    Number(localConfigCache.size || 0) === Number(signature.size || 0)
  )
}

function loadLocalConfigFile(options = {}) {
  try {
    const now = Date.now()
    const signature = getLocalConfigSignature()
    if (!signature.exists) {
      rememberLocalConfigCache(null, signature)
      return null
    }

    if (options.force !== true && localConfigCache.loadedAt > 0 && localConfigCacheMatches(signature)) {
      localConfigCache.loadedAt = now
      return cloneJsonValue(localConfigCache.value)
    }

    const parsed = loadSecureJsonFile(localConfigPath, { defaultValue: null })
    if (!parsed || typeof parsed !== 'object') {
      rememberLocalConfigCache(null, signature)
      return null
    }
    const normalized = normalizeDiskBackedDesktopHomeRouteConfig(parsed)
    if (JSON.stringify(normalized) !== JSON.stringify(parsed)) {
      saveSecureJsonFile(localConfigPath, normalized)
      rememberLocalConfigCache(normalized)
      return cloneJsonValue(normalized)
    }
    rememberLocalConfigCache(normalized, signature)
    return cloneJsonValue(normalized)
  } catch (_) {
    return null
  }
}

function saveLocalConfigFile(config) {
  const normalized = normalizeDiskBackedDesktopHomeRouteConfig(config)
  saveSecureJsonFile(localConfigPath, normalized)
  rememberLocalConfigCache(normalized)
  return cloneJsonValue(normalized)
}

function detectLanAddresses() {
  return getLanIpv4Addresses()
}

function getMdnsHost() {
  const localConfig = loadLocalConfigFile()
  const configured = normalizeLocalHostname(String(localConfig?.localHostname || '').trim())
  const configuredCustom = localConfig?.localHostnameCustom === true
  const envConfigured = String(process.env.PVTKRRX_LOCAL_HOSTNAME || '').trim()
  // Force a stable default alias for all installs unless explicitly customized by the user.
  if (configuredCustom && configured) return configured
  if (configured === DEFAULT_LOCAL_HOSTNAME) return configured
  if (envConfigured) return normalizeLocalHostname(envConfigured)
  return DEFAULT_LOCAL_HOSTNAME
}

function normalizeBaseUrl(input) {
  const value = String(input || '').trim().replace(/\/+$/, '')
  if (!value) return ''
  return value
}

function parseUrlCandidate(input) {
  const value = String(input || '').trim()
  if (!value) return null
  try {
    return new URL(value)
  } catch (_) {
    return null
  }
}

function defaultPortForProtocol(protocol) {
  return protocol === 'https:' ? '443' : '80'
}

function isLikelyLocalServiceUrl(input) {
  const parsed = parseUrlCandidate(input)
  if (!parsed) return false
  const hostname = String(parsed.hostname || '').trim().toLowerCase()
  if (!hostname) return false
  if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1') return true
  if (hostname.endsWith('.local')) return true
  return isPrivateIpv4(hostname) || isPrivateIpv6(hostname)
}

function isCompatibleLocalServiceUrl(currentUrl, discoveredUrl) {
  const current = parseUrlCandidate(currentUrl)
  const discovered = parseUrlCandidate(discoveredUrl)
  if (!current || !discovered) return false
  if (current.origin === discovered.origin) return true
  const currentPort = current.port || defaultPortForProtocol(current.protocol)
  const discoveredPort = discovered.port || defaultPortForProtocol(discovered.protocol)
  return (
    current.protocol === discovered.protocol &&
    currentPort === discoveredPort &&
    isLikelyLocalServiceUrl(currentUrl) &&
    isLikelyLocalServiceUrl(discoveredUrl)
  )
}

async function ensureBootLanAccess(logger = console) {
  const safeLogger = createRedactingLogger(logger)
  if (process.platform !== 'win32' || IS_HOSTED_RELAY_RUNTIME) return null
  if (bootLanAccessPromise) return bootLanAccessPromise

  bootLanAccessPromise = (async () => {
    try {
      const result = await ensureWindowsLanAccess({
        openFirewall: true,
        ensureBonjour: true,
        installBonjourIfMissing: false,
        startIfStopped: true
      })

      if (result?.firewallOk) {
        safeLogger.log('[startup-network] Windows Firewall verified for TCP 7000/7001 and UDP 5353')
      } else {
        safeLogger.warn('[startup-network] Firewall verification failed; run PVTKRRX as Administrator once to repair LAN access')
      }

      if (result?.mdnsReady) {
        safeLogger.log('[startup-network] mDNS responder ready')
      } else if (result?.bonjour?.installed) {
        safeLogger.warn('[startup-network] Bonjour service detected but not running')
      } else {
        safeLogger.warn('[startup-network] Bonjour/mDNS service not detected; .local discovery may be limited')
      }

      return result
    } catch (err) {
      safeLogger.warn('[startup-network] LAN access check failed:', err.message)
      return null
    }
  })()

  return bootLanAccessPromise
}

function parseBooleanLoose(value, fallback = false) {
  if (typeof value === 'boolean') return value
  if (value === null || value === undefined || value === '') return fallback
  return parseBoolean(value)
}

function getAuthTokenSecret() {
  const explicit = String(process.env.AUTH_TOKEN_SECRET || '').trim()
  if (explicit) return explicit

  const fallback = String(process.env.ENCRYPTION_SECRET || '').trim()
  if (!fallback) return ''
  return crypto.createHash('sha256').update(`pvtkrrx-auth-token:${fallback}`).digest('base64url')
}

function sanitizePairId(value) {
  const id = String(value || '').trim().toLowerCase()
  if (!id) return ''
  if (!/^[a-z0-9_-]{8,64}$/.test(id)) return ''
  return id
}

function makePairId() {
  return crypto.randomBytes(9).toString('base64url').toLowerCase()
}

function sanitizePairKey(value) {
  const key = String(value || '').trim()
  if (!key) return ''
  if (!/^[A-Za-z0-9_-]{16,256}$/.test(key)) return ''
  return key
}

function makePairKey() {
  return crypto.randomBytes(24).toString('base64url')
}

function summarizePairId(value) {
  const pairId = sanitizePairId(value)
  if (!pairId) return 'unknown'
  if (pairId.length <= 12) return pairId
  return `${pairId.slice(0, 6)}...${pairId.slice(-4)}`
}

function sanitizePairOwnerId(value) {
  const ownerId = String(value || '').trim()
  if (!ownerId) return ''
  if (!/^[A-Za-z0-9_-]{16,256}$/.test(ownerId)) return ''
  return ownerId
}

function makePairOwnerId() {
  return crypto.randomBytes(24).toString('base64url')
}

function hashPairKey(value) {
  return crypto.createHash('sha256').update(String(value || '')).digest('hex')
}

function sanitizeStremioAuthKey(value) {
  const key = String(value || '').trim()
  if (!key) return ''
  if (!STREMIO_AUTH_KEY_REGEX.test(key)) return ''
  return key
}

function derivePairIdFromStremioUserId(stremioUserId) {
  const userId = normalizeStremioUserId(stremioUserId)
  if (!userId) return ''
  const digest = crypto.createHash('sha256').update(userId).digest('hex')
  return `s_${digest.slice(0, 22)}`
}

function parsePathList(value) {
  const raw = String(value || '').trim()
  if (!raw) return []
  return raw
    .split(new RegExp(`[${path.delimiter === ';' ? ';' : ':'}\\n\\r]+`, 'g'))
    .map(entry => String(entry || '').trim())
    .filter(Boolean)
}

function extractStremioAuthKeysFromBlob(blob) {
  const raw = String(blob || '')
  if (!raw) return []
  const normalized = raw.replace(/\x00/g, '')
  const compact = normalized.replace(/[\x01-\x08\x0B\x0C\x0E-\x1F]+/g, '')
  if (!compact.includes('stremio.com') && !compact.includes('strem.io')) return []

  const matches = []
  const seen = new Set()
  const pushCandidate = (value) => {
    const key = sanitizeStremioAuthKey(value)
    if (!key || seen.has(key)) return
    seen.add(key)
    matches.push(key)
  }

  pushCandidate(compact)

  for (const regex of [
    new RegExp(`authKey=(${STREMIO_AUTH_KEY_CAPTURE_PATTERN})`, 'ig'),
    new RegExp(`"authKey"\\s*[:=]\\s*"(${STREMIO_AUTH_KEY_CAPTURE_PATTERN})"`, 'ig'),
    new RegExp(`"auth_key"\\s*[:=]\\s*"(${STREMIO_AUTH_KEY_CAPTURE_PATTERN})"`, 'ig'),
    new RegExp(`"auth"\\s*[:=]\\s*\\{[^{}]{0,400}"key"\\s*[:=]\\s*"(${STREMIO_AUTH_KEY_CAPTURE_PATTERN})"`, 'igs')
  ]) {
    let match = null
    while ((match = regex.exec(compact))) {
      pushCandidate(match[1])
    }
  }

  // Chromium/WebView2 LevelDB payloads often interleave control bytes into the
  // profile JSON, which breaks strict `"auth":{"key":"..."}` matching even
  // though the token is still present in plaintext nearby.
  const candidateRegex = new RegExp(`(${STREMIO_AUTH_KEY_CAPTURE_PATTERN})`, 'g')
  let candidateMatch = null
  while ((candidateMatch = candidateRegex.exec(compact))) {
    const candidate = candidateMatch[1]
    const before = compact.slice(Math.max(0, candidateMatch.index - 120), candidateMatch.index)
    if (/auth.{0,40}key.{0,20}$/is.test(before)) {
      pushCandidate(candidate)
    }
  }

  return matches
}

function getStremioAuthScanSources() {
  const explicitDirs = parsePathList(STREMIO_AUTH_SCAN_DIRS_OVERRIDE)
  if (explicitDirs.length) {
    return explicitDirs.map(dir => ({
      label: 'Override',
      profile: 'Override',
      levelDbDir: dir
    }))
  }

  const localAppData = String(process.env.LOCALAPPDATA || '').trim()
  if (!localAppData) return []

  const sources = []
  const seenDirs = new Set()
  const pushSource = (label, profile, levelDbDir) => {
    const dir = String(levelDbDir || '').trim()
    if (!dir || seenDirs.has(dir)) return
    if (!fs.existsSync(dir)) return
    seenDirs.add(dir)
    sources.push({ label, profile, levelDbDir: dir })
  }

  pushSource(
    'Stremio Desktop',
    'Default',
    path.join(localAppData, 'Programs', 'Stremio', 'stremio-shell-ng.exe.WebView2', 'EBWebView', 'Default', 'Local Storage', 'leveldb')
  )

  const browserRoots = [
    {
      label: 'Brave',
      root: path.join(localAppData, 'BraveSoftware', 'Brave-Browser', 'User Data')
    },
    {
      label: 'Chrome',
      root: path.join(localAppData, 'Google', 'Chrome', 'User Data')
    },
    {
      label: 'Edge',
      root: path.join(localAppData, 'Microsoft', 'Edge', 'User Data')
    }
  ]

  for (const browser of browserRoots) {
    if (!fs.existsSync(browser.root)) continue
    let entries = []
    try {
      entries = fs.readdirSync(browser.root, { withFileTypes: true })
    } catch (_) {
      continue
    }
    entries
      .filter(entry => entry.isDirectory() && /^(Default|Profile \d+)$/i.test(entry.name))
      .sort((a, b) => {
        if (a.name === 'Default') return -1
        if (b.name === 'Default') return 1
        return a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: 'base' })
      })
      .slice(0, 6)
      .forEach((entry) => {
        pushSource(
          browser.label,
          entry.name,
          path.join(browser.root, entry.name, 'Local Storage', 'leveldb')
        )
      })
  }

  return sources
}

function discoverLocalStremioAuthKeyCandidates() {
  const candidates = []
  const seenKeys = new Set()
  const filesPerSourceLimit = 16

  for (const source of getStremioAuthScanSources()) {
    let entries = []
    try {
      entries = fs.readdirSync(source.levelDbDir, { withFileTypes: true })
    } catch (_) {
      continue
    }

    const files = entries
      .filter(entry => entry.isFile() && (/\.ldb$/i.test(entry.name) || /\.log$/i.test(entry.name) || /^MANIFEST-/i.test(entry.name)))
      .map((entry) => {
        const filePath = path.join(source.levelDbDir, entry.name)
        try {
          const stat = fs.statSync(filePath)
          return {
            name: entry.name,
            filePath,
            mtimeMs: Number(stat.mtimeMs || 0),
            size: Number(stat.size || 0)
          }
        } catch (_) {
          return null
        }
      })
      .filter(Boolean)
      .sort((a, b) => (b.mtimeMs - a.mtimeMs) || (b.size - a.size) || a.name.localeCompare(b.name))
      .slice(0, filesPerSourceLimit)

    for (const file of files) {
      let blob = ''
      try {
        blob = fs.readFileSync(file.filePath).toString('latin1')
      } catch (_) {
        continue
      }

      const matches = extractStremioAuthKeysFromBlob(blob)
      for (const authKey of matches) {
        if (seenKeys.has(authKey)) continue
        seenKeys.add(authKey)
        candidates.push({
          authKey,
          sourceLabel: source.profile && source.profile !== 'Default'
            ? `${source.label} (${source.profile})`
            : source.label,
          sourceType: source.label,
          profile: source.profile,
          filePath: file.filePath,
          updatedAt: file.mtimeMs
        })
      }
    }
  }

  return candidates.sort((a, b) => (b.updatedAt - a.updatedAt) || a.sourceLabel.localeCompare(b.sourceLabel))
}

function getLocalStremioDesktopInstallCandidates() {
  const localAppData = String(process.env.LOCALAPPDATA || '').trim()
  if (!localAppData) return []

  const seen = new Set()
  return [
    path.join(localAppData, 'Programs', 'Stremio', 'stremio.exe'),
    path.join(localAppData, 'Programs', 'Stremio', 'Stremio.exe'),
    path.join(localAppData, 'Programs', 'Stremio', 'stremio-shell-ng.exe')
  ].filter((candidate) => {
    const filePath = String(candidate || '').trim()
    if (!filePath || seen.has(filePath)) return false
    seen.add(filePath)
    return true
  })
}

function getLocalStremioDesktopStatus() {
  const installCandidates = getLocalStremioDesktopInstallCandidates()
  const installPaths = installCandidates.filter(candidate => fs.existsSync(candidate))
  const authSources = getStremioAuthScanSources()
  const desktopStorageDetected = authSources.some(source => source.label === 'Stremio Desktop')
  const sessionCandidates = discoverLocalStremioAuthKeyCandidates()

  return {
    installed: installPaths.length > 0 || desktopStorageDetected,
    installPath: installPaths[0] || '',
    desktopStorageDetected,
    signedInSessionFound: sessionCandidates.length > 0,
    signedInSourceLabel: sessionCandidates[0]?.sourceLabel || '',
    signedInSessionCount: sessionCandidates.length,
    authTokenReady: authSecretAvailable(),
    downloadUrl: 'https://www.stremio.com/downloads'
  }
}

async function fetchStremioUserByAuthKey(authKey) {
  const key = sanitizeStremioAuthKey(authKey)
  if (!key) return null
  const endpoint = `${STREMIO_API_BASE_URL}/api/getUser`
  const res = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json'
    },
    body: JSON.stringify({ authKey: key }),
    signal: AbortSignal.timeout(STREMIO_API_TIMEOUT_MS)
  })
  if (!res.ok) {
    if (res.status === 400 || res.status === 401 || res.status === 403 || res.status === 404) {
      return null
    }
    throw new Error(`stremio getUser failed (${res.status})`)
  }

  const body = await res.json().catch(() => null)
  if (!body || typeof body !== 'object') return null
  const payload = body.result && typeof body.result === 'object' ? body.result : body
  const stremioUserId = normalizeStremioUserId(payload?._id || payload?.id || '')
  if (!stremioUserId) return null
  const email = normalizeAccountEmail(payload?.email || '')
  return {
    stremioUserId,
    email: isValidEmail(email) ? email : ''
  }
}

function createHttpError(statusCode, message, detail = '') {
  const err = new Error(message)
  err.statusCode = statusCode
  if (detail) err.detail = detail
  return err
}

async function createLinkedStremioAuthSession(authKey, authSecret) {
  const safeAuthKey = sanitizeStremioAuthKey(authKey)
  if (!safeAuthKey) {
    throw createHttpError(400, 'Invalid Stremio AuthKey')
  }

  const stremioUser = await fetchStremioUserByAuthKey(safeAuthKey)
  if (!stremioUser || !stremioUser.stremioUserId) {
    throw createHttpError(401, 'Stremio AuthKey verification failed')
  }

  const authKeyHash = hashStremioAuthKey(safeAuthKey)
  let user = await accountStore.getUserByStremioUserId(stremioUser.stremioUserId)
  if (!user) {
    user = await accountStore.createOrLinkStremioUser({
      stremioUserId: stremioUser.stremioUserId,
      email: stremioUser.email,
      authKeyHash
    })
  } else {
    const next = {
      ...user,
      stremio: {
        ...(user.stremio && typeof user.stremio === 'object' ? user.stremio : {}),
        userId: stremioUser.stremioUserId,
        authKeyHash,
        linkedAt: Number(user?.stremio?.linkedAt || Date.now()),
        lastVerifiedAt: Date.now()
      }
    }
    if (stremioUser.email && isValidEmail(stremioUser.email)) {
      next.email = stremioUser.email
    }
    user = await accountStore.saveUser(next)
  }

  const recommendedPairId = derivePairIdFromStremioUserId(stremioUser.stremioUserId)
  const token = createAuthToken({
    sub: user.id
  }, authSecret, AUTH_TOKEN_TTL_SECONDS)

  return {
    ok: true,
    token,
    stremio: {
      linked: true,
      userId: stremioUser.stremioUserId,
      recommendedPairId
    }
  }
}

function normalizeClientIp(value) {
  let ip = String(value || '').trim()
  if (!ip) return ''
  if (ip.startsWith('::ffff:')) ip = ip.slice(7)
  const zoneIndex = ip.indexOf('%')
  if (zoneIndex !== -1) ip = ip.slice(0, zoneIndex)
  return ip.replace(/[^a-fA-F0-9:.]/g, '').toLowerCase()
}

function getSocketIp(req) {
  return normalizeClientIp(String(req.socket?.remoteAddress || req.connection?.remoteAddress || ''))
}

function getTrustedProxyIp(req) {
  if (!TRUST_PROXY_ENABLED) return ''
  const expressIp = normalizeClientIp(String(req.ip || ''))
  if (expressIp) return expressIp
  const forwarded = String(req.headers?.['x-forwarded-for'] || '')
    .split(',')[0]
    .trim()
  return normalizeClientIp(forwarded)
}

function isLoopbackIp(ip) {
  return ip === '127.0.0.1' || ip === '::1' || ip === '0:0:0:0:0:0:0:1'
}

function getClientIp(req) {
  return getTrustedProxyIp(req) || getSocketIp(req)
}

function isSameHostRequest(req) {
  if (IS_HOSTED_RELAY_RUNTIME) return false
  const clientIp = getSocketIp(req)
  if (!clientIp) return false
  if (isLoopbackIp(clientIp)) return true
  try {
    return getLanIpv4Addresses().includes(clientIp)
  } catch (_) {
    return false
  }
}

function hashClientIp(req) {
  const ip = getClientIp(req)
  if (!ip) return ''
  return crypto.createHash('sha256').update(ip).digest('hex')
}

function requestClientLabel(req) {
  return getClientIp(req) || req.ip || req.socket?.remoteAddress || '?'
}

function isLikelyLanHost(hostname) {
  const host = String(hostname || '').trim().toLowerCase()
  if (!host) return false
  if (host.endsWith('.local')) return true
  return isPrivateIpv4(host) || isPrivateIpv6(host)
}

async function resolveTargetAddresses(parsedUrl) {
  const host = String(parsedUrl?.hostname || '').trim()
  if (!host) return []
  if (net.isIP(host)) return [normalizeClientIp(host)].filter(Boolean)

  const results = await dns.lookup(host, { all: true, verbatim: true })
  return results
    .map(entry => normalizeClientIp(entry?.address || ''))
    .filter(Boolean)
}

async function validateHostedConnectionTarget(parsedUrl) {
  if (!parsedUrl) return null
  if (isBlockedPrivateTargetHost(parsedUrl.hostname)) {
    throw createHttpError(403, 'Hosted connection tests cannot probe loopback, LAN, or private-resolution targets')
  }

  let addresses = []
  try {
    addresses = await resolveTargetAddresses(parsedUrl)
  } catch (_) {
    throw createHttpError(403, 'Hosted connection tests require resolvable public targets')
  }
  if (!addresses.length) {
    throw createHttpError(403, 'Hosted connection tests require resolvable public targets')
  }
  if (addresses.some(address => isBlockedPrivateTargetHost(address))) {
    throw createHttpError(403, 'Hosted connection tests cannot probe loopback, LAN, or private-resolution targets')
  }
}

function parseHttpUrlCandidate(input) {
  const raw = String(input || '').trim()
  if (!raw) return null
  try {
    const parsed = new URL(raw)
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null
    return parsed
  } catch (_) {
    return null
  }
}

function sanitizeLanBaseUrl(input) {
  const raw = String(input || '').trim()
  if (!raw) return ''
  try {
    const parsed = new URL(raw)
    const protocol = String(parsed.protocol || '').toLowerCase()
    if (protocol !== 'http:' && protocol !== 'https:') return ''
    if (!isLikelyLanHost(parsed.hostname)) return ''
    return normalizeBaseUrl(parsed.origin)
  } catch (_) {
    return ''
  }
}

function normalizePairEndpoints(endpoints) {
  if (!Array.isArray(endpoints)) return []
  const out = []
  const seen = new Set()
  for (const entry of endpoints) {
    const baseUrl = sanitizeLanBaseUrl(entry?.baseUrl || '')
    if (!baseUrl) continue
    if (seen.has(baseUrl)) continue
    seen.add(baseUrl)
    out.push({
      baseUrl,
      source: String(entry?.source || '').trim() || 'unknown'
    })
  }
  return out
}

function summarizeEndpointSources(endpoints) {
  const labels = []
  const seen = new Set()
  for (const entry of Array.isArray(endpoints) ? endpoints : []) {
    const label = String(entry?.source || '').trim() || 'unknown'
    if (seen.has(label)) continue
    seen.add(label)
    labels.push(label)
  }
  return labels.length ? labels.join(',') : 'none'
}

function buildLanPairEndpoints(port, httpsPort) {
  const mdnsHost = getMdnsHost()
  const lanIps = detectLanAddresses()
  const entries = []
  for (const ip of lanIps) {
    const urls = buildLocalModeUrls(ip, port, httpsPort)
    entries.push({ baseUrl: normalizeBaseUrl(urls.httpManifest.replace(/\/local\/manifest\.json\?mode=local$/i, '')), source: 'lan-ip' })
  }
  const mdnsUrls = buildLocalModeUrls(mdnsHost, port, httpsPort)
  entries.push({ baseUrl: normalizeBaseUrl(mdnsUrls.httpManifest.replace(/\/local\/manifest\.json\?mode=local$/i, '')), source: 'mdns' })
  const loopbackUrls = buildLocalModeUrls('127.0.0.1', port, httpsPort)
  entries.push({ baseUrl: normalizeBaseUrl(loopbackUrls.httpManifest.replace(/\/local\/manifest\.json\?mode=local$/i, '')), source: 'loopback' })
  return normalizePairEndpoints(entries)
}

function ensureLanPairConfig(config = {}, options = {}) {
  const recommendedPairId = derivePairIdFromStremioUserId(config?.stremioUserId || '')
  const pairId = sanitizePairId(config.lanPairId) || recommendedPairId || makePairId()
  const pairKey = sanitizePairKey(config.lanPairKey) || makePairKey()
  const pairOwnerId = options.includeLocalSecrets === true
    ? (sanitizePairOwnerId(config.lanPairOwnerId) || makePairOwnerId())
    : sanitizePairOwnerId(config.lanPairOwnerId)
  const relayUrl = normalizeRelayUrl(config.lanPairRelayUrl || options.lanPairRelayUrl)
  const pairEnabledFallback = typeof options.defaultEnabled === 'boolean' ? options.defaultEnabled : false
  const pairRequiredFallback = typeof options.defaultRequired === 'boolean' ? options.defaultRequired : false
  const pairEnabled = parseBooleanLoose(config.lanPairEnabled, pairEnabledFallback)
  const pairRequired = parseBooleanLoose(config.lanPairRequired, pairRequiredFallback)

  return {
    ...config,
    lanPairEnabled: pairEnabled,
    lanPairRequired: pairRequired,
    lanPairId: pairId,
    lanPairKey: pairKey,
    ...(pairOwnerId ? { lanPairOwnerId: pairOwnerId } : {}),
    lanPairRelayUrl: relayUrl
  }
}

function normalizeRouteProfile(value) {
  const profile = String(value || '').trim().toLowerCase()
  if (profile === 'local' || profile === 'lan' || profile === 'online' || profile === 'hybrid') {
    return profile
  }
  return ''
}

function normalizeDiskBackedDesktopHomeRouteConfig(config = {}) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) return config
  if (SELF_HOST_SERVER_MODE) return config

  const explicitProfile = normalizeRouteProfile(config.routeProfile)
  if (explicitProfile === 'local' || explicitProfile === 'online' || explicitProfile === 'hybrid') {
    return config
  }
  if (config.lanPairEnabled === false) return config

  const hasHomeRouteSignals = (
    typeof config.lanPairEnabled === 'boolean' ||
    typeof config.lanPairRequired === 'boolean' ||
    Boolean(config.lanPairId) ||
    Boolean(config.lanPairKey) ||
    Boolean(config.lanPairRelayUrl) ||
    Boolean(config.stremioUserId)
  )
  if (!hasHomeRouteSignals) return config

  return {
    ...config,
    routeProfile: 'hybrid',
    lanPairEnabled: true,
    lanPairRequired: false
  }
}

function resolveHostedProfile(config = {}) {
  const explicit = normalizeRouteProfile(config?.routeProfile)
  if (explicit === 'lan' || explicit === 'online' || explicit === 'hybrid') return explicit

  const hasLegacyLanPairState = Boolean(config?.lanPairId || config?.lanPairKey || config?.lanPairRelayUrl)
  const lanEnabled = typeof config?.lanPairEnabled === 'boolean'
    ? config.lanPairEnabled
    : hasLegacyLanPairState
  if (!lanEnabled) return 'online'
  if (typeof config?.lanPairRequired === 'boolean') {
    return config.lanPairRequired ? 'lan' : 'hybrid'
  }
  return hasLegacyLanPairState ? 'lan' : 'hybrid'
}

function shouldBindLanPairToRequest(config = {}) {
  return LAN_PAIR_BIND_PUBLIC_IP || resolveHostedProfile(config) === 'hybrid'
}

function stripLegacySportsMetadataConfigFields(config = {}) {
  const next = { ...(config && typeof config === 'object' ? config : {}) }
  delete next.sportsDbApiKey
  delete next.sportsDbCacheHours
  delete next.sportsImagePackagePath
  delete next.sportsImagePackagePaths
  return next
}

function normalizeAddonConfig(config = {}, options = {}) {
  const normalized = {
    ...stripLegacySportsMetadataConfigFields(config),
    additionalStorageRoots: normalizeLocalStorageRoots(config.additionalStorageRoots)
  }
  // Sports-Posters entitlement gate.
  // Save path: caller passes options.entitlement (resolved from the
  //   authenticated owner/admin/account). The stamped source survives
  //   on the encrypted token so the runtime knows what was approved.
  // Read path (no options.entitlement): re-verify the stamped source
  //   against the current env. Owner/admin revocations apply
  //   immediately; manual_grant / member_token / trial trust the stamp
  //   until the token is regenerated.
  normalized.sportsPosterMemberToken = ''
  const requestedTemplate = String(config.sportsPosterTemplate || '').trim()
  const stampedSource = String(config.entitlementSource || '').trim()
  const stampedHash = String(config.entitlementOwnerEmailHash || '').trim()

  let entitlement
  if (options.entitlement && typeof options.entitlement === 'object') {
    entitlement = options.entitlement
  } else {
    entitlement = verifyStampedSportsPosterEntitlement({
      requestedTemplate,
      stampedSource,
      stampedHash
    })
  }

  normalized.sportsPosterTemplate = clampSportsPosterTemplate(requestedTemplate, entitlement)
  normalized.entitlementSource = entitlement.source || ENTITLEMENT_SOURCE.NONE
  if (entitlement.ownerEmailHash) {
    normalized.entitlementOwnerEmailHash = entitlement.ownerEmailHash
  } else {
    delete normalized.entitlementOwnerEmailHash
  }
  const explicitProfile = normalizeRouteProfile(normalized.routeProfile)
  const localProfile = explicitProfile === 'local'
  const callerControlsLanPairDefaults =
    typeof options.defaultEnabled === 'boolean' ||
    typeof options.defaultRequired === 'boolean'
  const hasHostedProfileSignal = (
    explicitProfile === 'lan' ||
    explicitProfile === 'online' ||
    explicitProfile === 'hybrid' ||
    typeof normalized.lanPairEnabled === 'boolean' ||
    typeof normalized.lanPairRequired === 'boolean' ||
    (!callerControlsLanPairDefaults && (
      Boolean(normalized.lanPairId) ||
      Boolean(normalized.lanPairKey) ||
      Boolean(normalized.lanPairRelayUrl)
    ))
  )
  const hostedProfile = localProfile || !hasHostedProfileSignal ? '' : resolveHostedProfile(normalized)
  normalized.routeProfile = localProfile
    ? 'local'
    : (hostedProfile || explicitProfile || '')

  const lanPairExplicitlyDisabled = normalized.lanPairEnabled === false ||
    (normalized.lanPairRequired === false && hostedProfile !== 'hybrid')
  if (hostedProfile === 'online' && lanPairExplicitlyDisabled && options.defaultEnabled !== true) {
    return stripRemoteSeedboxLanFields({
      ...normalized,
      routeProfile: 'online',
      lanPairEnabled: false,
      lanPairRequired: false
    }, {
      keepRelayUrl: true,
      keepRouteProfile: true
    })
  }
  const shouldNormalizeLanPair = (
    hostedProfile === 'lan' ||
    hostedProfile === 'hybrid' ||
    typeof options.defaultEnabled === 'boolean' ||
    typeof options.defaultRequired === 'boolean' ||
    typeof normalized.lanPairEnabled === 'boolean' ||
    typeof normalized.lanPairRequired === 'boolean' ||
    Boolean(normalized.lanPairId) ||
    Boolean(normalized.lanPairKey) ||
    Boolean(normalized.lanPairRelayUrl) ||
    Boolean(normalized.stremioUserId)
  )
  if (!shouldNormalizeLanPair) return normalized

  const defaultEnabled = hostedProfile === 'online'
    ? false
    : (hostedProfile === 'hybrid' || hostedProfile === 'lan')
      ? true
      : options.defaultEnabled
  const defaultRequired = hostedProfile === 'hybrid'
    ? false
    : hostedProfile === 'lan'
      ? true
      : options.defaultRequired

  return ensureLanPairConfig(normalized, {
    ...options,
    defaultEnabled,
    defaultRequired
  })
}

function normalizeRetainedSecretFields(value) {
  const out = {}
  if (!value || typeof value !== 'object' || Array.isArray(value)) return out
  for (const field of SECRET_CONFIG_FIELDS) {
    out[field] = value[field] === true
  }
  return out
}

function stripEphemeralConfigFields(config = {}) {
  const next = { ...(config && typeof config === 'object' ? config : {}) }
  delete next.sourceConfigToken
  delete next.savedSecrets
  delete next.retainSecretFields
  return next
}

function mergeRetainedSecrets(config = {}, existingConfig = null) {
  const next = stripEphemeralConfigFields(config)
  const existing = existingConfig && typeof existingConfig === 'object' ? existingConfig : null
  if (!existing) return next

  const retain = normalizeRetainedSecretFields(config?.retainSecretFields)
  for (const field of SECRET_CONFIG_FIELDS) {
    if (retain[field] && !String(next[field] || '').trim() && String(existing[field] || '').trim()) {
      next[field] = existing[field]
    }
  }

  if (!sanitizePairKey(next.lanPairKey) && sanitizePairKey(existing.lanPairKey)) {
    next.lanPairKey = existing.lanPairKey
  }
  if (!sanitizePairOwnerId(next.lanPairOwnerId) && sanitizePairOwnerId(existing.lanPairOwnerId)) {
    next.lanPairOwnerId = existing.lanPairOwnerId
  }
  if (!String(next.entitlementSource || '').trim() && String(existing.entitlementSource || '').trim()) {
    next.entitlementSource = existing.entitlementSource
  }
  if (!String(next.entitlementOwnerEmailHash || '').trim() && String(existing.entitlementOwnerEmailHash || '').trim()) {
    next.entitlementOwnerEmailHash = existing.entitlementOwnerEmailHash
  }

  return next
}

function loadConfigFromSourceToken(sourceToken) {
  const token = String(sourceToken || '').trim()
  if (!token) return null
  const secret = String(process.env.ENCRYPTION_SECRET || '').trim()
  if (!secret) return null
  try {
    return normalizeAddonConfig(decrypt(token, secret))
  } catch (_) {
    return null
  }
}

async function hydrateAccountLinkForConfig(config = {}) {
  const next = { ...(config && typeof config === 'object' ? config : {}) }
  if (String(next.accountUserId || '').trim()) return next

  const stremioUserId = normalizeStremioUserId(next.stremioUserId || '')
  if (!stremioUserId) return next

  const user = await accountStore.getUserByStremioUserId(stremioUserId)
  if (!user) return next

  next.accountUserId = String(user.id || '').trim()
  next.accountProvider = String(next.accountProvider || user.authProvider || 'stremio-authkey').trim()
  next.accountLinkedAt = Number(next.accountLinkedAt || user?.stremio?.linkedAt || Date.now())
  return next
}

function configLooksHostedTakeoverCapable(config = {}) {
  const hostedProfile = resolveHostedProfile(config)
  return hostedProfile === 'online'
}

function buildHostedTakeoverConfig(config = {}) {
  return normalizeAddonConfig(stripRemoteSeedboxLanFields({
    ...(config && typeof config === 'object' ? config : {}),
    routeProfile: 'online',
    lanPairEnabled: false,
    lanPairRequired: false
  }))
}

async function resolveAccountUserForConfig(config = {}, options = {}) {
  const accountUserId = String(config?.accountUserId || '').trim()
  const stremioUserId = normalizeStremioUserId(config?.stremioUserId || '')
  const createIfMissing = options.createIfMissing === true

  let user = null
  if (accountUserId) {
    user = await accountStore.getUserById(accountUserId)
  }
  if (!user && stremioUserId) {
    user = await accountStore.getUserByStremioUserId(stremioUserId)
  }
  if (!user && createIfMissing && stremioUserId) {
    user = await accountStore.createOrLinkStremioUser({ stremioUserId })
  }
  return user
}

async function resolveSportsPosterEntitlementForConfig(config = {}, options = {}) {
  const requestedTemplate =
    options.requestedTemplate !== undefined
      ? options.requestedTemplate
      : config?.sportsPosterTemplate
  const explicitUser = options.user && typeof options.user === 'object' ? options.user : null
  const user = explicitUser || (await resolveAccountUserForConfig(config))
  return resolveSportsPosterEntitlement({
    user,
    config,
    requestedTemplate,
    selfHostAdmin: options.selfHostAdmin === true
  })
}

async function applySportsPosterEntitlement(config = {}, options = {}) {
  const next = config && typeof config === 'object' ? { ...config } : {}
  const entitlement = await resolveSportsPosterEntitlementForConfig(next, {
    requestedTemplate: options.requestedTemplate,
    user: options.user,
    selfHostAdmin: options.selfHostAdmin === true
  })
  next.sportsPosterTemplate = clampSportsPosterTemplate(
    options.requestedTemplate !== undefined
      ? options.requestedTemplate
      : next.sportsPosterTemplate,
    entitlement
  )
  next.entitlementSource = entitlement.source || ENTITLEMENT_SOURCE.NONE
  if (entitlement.ownerEmailHash) {
    next.entitlementOwnerEmailHash = entitlement.ownerEmailHash
  } else {
    delete next.entitlementOwnerEmailHash
  }
  return { config: next, entitlement }
}

async function persistAccountHostedTakeoverConfig(config = {}) {
  if (!configLooksHostedTakeoverCapable(config)) {
    return { saved: false, reason: 'not-hosted-capable' }
  }

  const secret = String(process.env.ENCRYPTION_SECRET || '').trim()
  if (!secret) return { saved: false, reason: 'missing-secret' }

  const user = await resolveAccountUserForConfig(config, { createIfMissing: true })
  if (!user) return { saved: false, reason: 'missing-account' }

  const takeoverConfig = buildHostedTakeoverConfig(config)
  const next = {
    ...user,
    pvtkrrx: {
      ...(user?.pvtkrrx && typeof user.pvtkrrx === 'object' ? user.pvtkrrx : {}),
      hostedTakeoverConfigToken: encrypt(takeoverConfig, secret),
      hostedTakeoverUpdatedAt: Date.now()
    }
  }

  const savedUser = await accountStore.saveUser(next)
  return {
    saved: true,
    userId: String(savedUser?.id || '').trim(),
    takeoverConfig
  }
}

async function loadAccountHostedTakeoverConfig(config = {}) {
  if (resolveHostedProfile(config) !== 'hybrid') return null

  const secret = String(process.env.ENCRYPTION_SECRET || '').trim()
  if (!secret) return null

  const user = await resolveAccountUserForConfig(config)
  if (!user) return null

  const takeoverToken = String(user?.pvtkrrx?.hostedTakeoverConfigToken || '').trim()
  if (!takeoverToken) return null

  try {
    const takeoverConfig = normalizeAddonConfig(decrypt(takeoverToken, secret))
    return normalizeAddonConfig({
      ...takeoverConfig,
      routeProfile: 'hybrid',
      lanPairEnabled: true,
      lanPairRequired: false,
      lanPairId: sanitizePairId(config?.lanPairId) || sanitizePairId(takeoverConfig?.lanPairId),
      lanPairKey: sanitizePairKey(config?.lanPairKey) || sanitizePairKey(takeoverConfig?.lanPairKey),
      lanPairOwnerId: sanitizePairOwnerId(config?.lanPairOwnerId) || sanitizePairOwnerId(takeoverConfig?.lanPairOwnerId),
      lanPairRelayUrl: normalizeRelayUrl(config?.lanPairRelayUrl || takeoverConfig?.lanPairRelayUrl || ''),
      stremioUserId: normalizeStremioUserId(config?.stremioUserId || takeoverConfig?.stremioUserId),
      accountUserId: String(config?.accountUserId || user?.id || '').trim(),
      accountProvider: String(
        config?.accountProvider ||
        takeoverConfig?.accountProvider ||
        user?.authProvider ||
        'stremio-authkey'
      ).trim(),
      accountLinkedAt: Number(
        config?.accountLinkedAt ||
        takeoverConfig?.accountLinkedAt ||
        user?.stremio?.linkedAt ||
        Date.now()
      )
    })
  } catch (_) {
    return null
  }
}

function buildConfigReadback(config = {}) {
  const safe = config && typeof config === 'object' ? { ...config } : {}
  const savedSecrets = {
    jackettApiKey: Boolean(String(safe.jackettApiKey || '').trim()),
    qbitUsername: Boolean(String(safe.qbitUsername || '').trim()),
    qbitPassword: Boolean(String(safe.qbitPassword || '').trim()),
    fileServerAuth: Boolean(String(safe.fileServerAuth || '').trim()),
    sportsPosterMemberToken: false,
    lanPairKey: Boolean(String(safe.lanPairKey || '').trim())
  }

  // Re-verify the stamped entitlement so the frontend reflects the
  // CURRENT server-side decision (env-removed owners get downgraded
  // immediately) instead of trusting whatever was on disk.
  const verifiedEntitlement = verifyStampedSportsPosterEntitlement({
    requestedTemplate: safe.sportsPosterTemplate,
    stampedSource: safe.entitlementSource,
    stampedHash: safe.entitlementOwnerEmailHash
  })

  for (const field of SECRET_CONFIG_FIELDS) delete safe[field]
  delete safe.accountUserId
  delete safe.lanPairKey
  delete safe.lanPairOwnerId
  delete safe.sourceConfigToken
  delete safe.retainSecretFields
  delete safe.entitlementOwnerEmailHash

  return {
    ...safe,
    savedSecrets,
    sportsPosterTemplate: verifiedEntitlement.resolvedTemplate,
    entitlement: {
      source: verifiedEntitlement.source,
      allowed: verifiedEntitlement.allowed,
      allowedSportsPosterTemplates: verifiedEntitlement.allowedTemplates,
      resolvedSportsPosterTemplate: verifiedEntitlement.resolvedTemplate
    }
  }
}

function resolveExistingConfigForBody(body = {}, options = {}) {
  const preferLocal = options.preferLocal === true
  const localConfig = preferLocal ? loadLocalConfigFile() : null
  const tokenConfig = loadConfigFromSourceToken(body?.sourceConfigToken)
  return localConfig || tokenConfig || (preferLocal ? tokenConfig : null)
}

function chooseLanPairEndpoint(state) {
  const endpoints = normalizePairEndpoints(state?.endpoints || [])
  if (!endpoints.length) return null
  const score = (entry) => {
    let points = 0
    if (entry.source === 'lan-ip') points += 60
    if (entry.source === 'mdns') points += 20
    if (entry.source === 'loopback') points -= 100
    try {
      const host = new URL(entry.baseUrl).hostname
      if (isPrivateIpv4(host) && host !== '127.0.0.1') points += 20
      if (host.endsWith('.local')) points += 5
      if (host === '127.0.0.1' || host === 'localhost') points -= 100
    } catch (_) {}
    return points
  }
  return endpoints
    .map((entry, index) => ({ entry, index }))
    .sort((a, b) => score(b.entry) - score(a.entry) || a.index - b.index)[0]
    ?.entry || null
}

function buildLanRedirectUrl(req, baseUrl) {
  const origin = sanitizeLanBaseUrl(baseUrl)
  if (!origin) return ''
  const raw = String(req.originalUrl || '')
  const qIndex = raw.indexOf('?')
  const pathname = qIndex === -1 ? raw : raw.slice(0, qIndex)
  const query = qIndex === -1 ? '' : raw.slice(qIndex)
  const localPath = pathname.replace(/^\/[^/]+/, '/local')
  const params = new URLSearchParams(query.startsWith('?') ? query.slice(1) : query)
  params.set('mode', 'local')
  const queryText = params.toString()
  return `${origin}${localPath}${queryText ? `?${queryText}` : ''}`
}

function sanitizeHostForUrl(value) {
  const host = String(value || '')
    .trim()
    .replace(/[^a-zA-Z0-9.\-:]/g, '')
  return host || ''
}

function normalizeOrigin(value) {
  const raw = String(value || '').trim()
  if (!raw) return ''
  try {
    const parsed = new URL(raw)
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return ''
    return `${parsed.protocol}//${parsed.host}`.toLowerCase()
  } catch (_) {
    return ''
  }
}

function parseOriginAllowlist(raw) {
  const out = new Set()
  const parts = String(raw || '').split(',')
  for (const part of parts) {
    const origin = normalizeOrigin(part)
    if (origin) out.add(origin)
  }
  return out
}

function requestHostname(req) {
  const hostHeader = String(req.get('host') || '')
  if (hostHeader.startsWith('[')) {
    const end = hostHeader.indexOf(']')
    if (end > 1) return hostHeader.slice(1, end).trim().toLowerCase()
  }
  return String(hostHeader.split(':')[0] || '').trim().toLowerCase()
}

function isLocalNetworkRequest(req) {
  if (IS_HOSTED_RELAY_RUNTIME) return false
  const clientIp = getSocketIp(req)
  return Boolean(clientIp) && (isLoopbackIp(clientIp) || isLikelyLanHost(clientIp))
}

function isConfigReadbackPath(pathName) {
  return /^\/[^/]+\/config\.json$/i.test(String(pathName || ''))
}

function isSensitiveCorsRoute(req) {
  const pathName = String(req.path || '')
  return (
    pathName === '/encrypt' ||
    pathName === '/test-connection' ||
    pathName === '/local-config' ||
    pathName === '/server-config' ||
    pathName === '/auto-provision' ||
    pathName === '/network-info' ||
    pathName === '/local/lan-token' ||
    pathName === '/local/pair-status' ||
    /\/qbit\//i.test(pathName) ||
    isConfigReadbackPath(pathName) ||
    pathName.startsWith('/pair/') ||
    pathName.startsWith('/auth/')
  )
}

function isAllowedSensitiveOriginValue(req, rawValue) {
  const origin = normalizeOrigin(rawValue)
  if (!origin) return false

  const currentOrigin = normalizeOrigin(getPublicBaseUrl(req))
  if (currentOrigin && origin === currentOrigin) return true
  if (SENSITIVE_WEB_ORIGINS.has(origin)) return true

  try {
    const host = String(new URL(origin).hostname || '').toLowerCase()
    if (host === '::1') return true
    if (isLikelyLanHost(host)) return true
  } catch (_) {}
  return false
}

function isAllowedSensitiveOrigin(req) {
  const rawOrigin = String(req.headers.origin || '').trim()
  if (!rawOrigin) return true
  return isAllowedSensitiveOriginValue(req, rawOrigin)
}

function parseRequestCookies(req) {
  const out = {}
  const raw = String(req.headers.cookie || '').trim()
  if (!raw) return out
  for (const part of raw.split(';')) {
    const idx = part.indexOf('=')
    if (idx <= 0) continue
    const key = part.slice(0, idx).trim()
    const value = part.slice(idx + 1).trim()
    if (!key) continue
    out[key] = decodeURIComponent(value)
  }
  return out
}

function timingSafeEqualText(a, b) {
  const left = Buffer.from(String(a || ''), 'utf8')
  const right = Buffer.from(String(b || ''), 'utf8')
  if (left.length !== right.length || left.length === 0) return false
  return crypto.timingSafeEqual(left, right)
}

function isDiskBackedConfigAlias(configValue) {
  const normalized = String(configValue || '').trim().toLowerCase()
  return normalized === 'local' || (SELF_HOST_SERVER_MODE && normalized === 'selfhost')
}

function isSelfHostConfigAlias(configValue) {
  return SELF_HOST_SERVER_MODE && String(configValue || '').trim().toLowerCase() === 'selfhost'
}

function hasServerAdminToken(req) {
  if (!SELF_HOST_SERVER_MODE) return false
  const presented = String(req?.headers?.['x-pvtkrrx-admin-token'] || '').trim()
  return timingSafeEqualText(presented, serverAdminState.token)
}

function requireServerAdminToken(req, res, next) {
  if (!SELF_HOST_SERVER_MODE) {
    return res.status(404).json({ error: 'Self-host server mode is not enabled' })
  }
  if (isSameHostRequest(req) || hasServerAdminToken(req)) return next()
  return res.status(401).json({ error: 'Valid self-host password required' })
}

function ensureCsrfCookie(req, res) {
  const cookies = parseRequestCookies(req)
  const existing = String(cookies[CSRF_COOKIE_NAME] || '').trim()
  if (/^[A-Za-z0-9_-]{24,256}$/.test(existing)) return existing

  const token = crypto.randomBytes(24).toString('base64url')
  const parts = [
    `${CSRF_COOKIE_NAME}=${encodeURIComponent(token)}`,
    'Path=/',
    'SameSite=Strict',
    'Max-Age=86400'
  ]
  const proto = String(req.headers['x-forwarded-proto'] || req.protocol || '').toLowerCase()
  if (proto.includes('https')) parts.push('Secure')
  res.append('Set-Cookie', parts.join('; '))
  return token
}

function requireCsrfToken(req, res, next) {
  const cookies = parseRequestCookies(req)
  const cookieToken = String(cookies[CSRF_COOKIE_NAME] || '').trim()
  const headerToken = String(req.headers['x-pvtkrrx-csrf'] || '').trim()
  if (cookieToken && headerToken && timingSafeEqualText(cookieToken, headerToken)) return next()
  return res.status(403).json({ error: 'CSRF validation failed' })
}

function requireLocalNetworkRoute(req, res, next) {
  if (isSameHostRequest(req)) return next()
  return res.status(403).json({ error: 'Open configure on the Windows host PC.' })
}

function requireLocalConfigReadback(req, res, next) {
  const configAlias = String(req.params?.config || '').trim().toLowerCase()
  if (configAlias === 'local') {
    if (isSameHostRequest(req)) return next()
    return res.status(403).json({ error: 'Local config prefill is only available on the Windows host PC.' })
  }
  if (configAlias === 'selfhost') {
    return requireServerAdminToken(req, res, next)
  }
  return next()
}

function requireLocalQbitControl(req, res, next) {
  if (req.params.config === 'local' && isSameHostRequest(req)) return next()
  return res.status(403).json({ error: 'qBittorrent control route is local-only' })
}

function getPublicBaseUrl(req) {
  const configured = parseUrlCandidate(process.env.PVTKRRX_PUBLIC_BASE_URL || '')
  if (configured && (configured.protocol === 'http:' || configured.protocol === 'https:')) {
    return normalizeBaseUrl(configured.origin)
  }
  const forwardedProto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim()
  const protocol = forwardedProto || req.protocol || 'http'
  return `${protocol}://${req.get('host')}`
}

function getPlaybackBaseUrl(req) {
  const configured = parseUrlCandidate(process.env.PVTKRRX_PLAYBACK_BASE_URL || '')
  if (configured && (configured.protocol === 'http:' || configured.protocol === 'https:')) {
    return normalizeBaseUrl(configured.origin)
  }
  return getPublicBaseUrl(req)
}

function getConfigIssues(config, options = {}) {
  const safeConfig = config && typeof config === 'object' ? config : {}
  const issues = []
  const requestBaseUrl = normalizeBaseUrl(options.requestBaseUrl || '')
  const requestOrigin = normalizeOrigin(requestBaseUrl)
  const relayOrigin = normalizeOrigin(String(safeConfig.lanPairRelayUrl || '').trim())
  const selfHostDiskConfig = options.selfHostDiskConfig === true
  const localDiskConfig = options.localDiskConfig === true
  const hostedProfile = resolveHostedProfile(safeConfig)
  const usingHostedProfile = hostedProfile === 'online' || hostedProfile === 'hybrid'
  const missingFileServerUrl = !String(safeConfig.fileServerUrl || '').trim()
  const relayTargetsDifferentOrigin = Boolean(requestOrigin && relayOrigin && relayOrigin !== requestOrigin)

  if (usingHostedProfile && missingFileServerUrl && !selfHostDiskConfig && !localDiskConfig && (IS_HOSTED_RELAY_RUNTIME || relayTargetsDifferentOrigin)) {
    issues.push({
      code: 'HOSTED_FILE_SERVER_REQUIRED',
      message: 'Hosted profile needs an HTTPS File Server URL for completed-file playback. Add your seedbox file server URL or use a direct-host/LAN profile.'
    })
  }

  // Defence-in-depth: a Remote Seedbox hosted-relay token (routeProfile='online'
  // by explicit user intent) must carry publicly reachable backend URLs.
  // Loopback/private hosts only make sense on a same-box self-host where the
  // /server-config path is used, not the /encrypt hosted-relay path this
  // check gates. Only fire when the incoming request itself is arriving at
  // a public origin (or we're on the public relay runtime), so that localhost
  // smoke tests and loopback-origin self-installs are not penalised.
  const requestHostname = (() => {
    if (!requestOrigin) return ''
    try {
      return String(new URL(requestOrigin).hostname || '').toLowerCase()
    } catch (_) {
      return ''
    }
  })()
  const requestArrivesOnPublicRelay = IS_HOSTED_RELAY_RUNTIME ||
    (Boolean(requestHostname) && !isBlockedPrivateTargetHost(requestHostname))
  const explicitRemoteSeedboxIntent = normalizeRouteProfile(safeConfig.routeProfile) === 'online' &&
    safeConfig.lanPairEnabled === false
  if (
    requestArrivesOnPublicRelay &&
    explicitRemoteSeedboxIntent &&
    !selfHostDiskConfig &&
    !localDiskConfig
  ) {
    const remoteSeedboxUrlFields = [
      ['Prowlarr URL', String(safeConfig.jackettUrl || '').trim()],
      ['qBittorrent URL', String(safeConfig.qbitUrl || '').trim()],
      ['File Server URL', String(safeConfig.fileServerUrl || '').trim()]
    ]
    for (const [label, value] of remoteSeedboxUrlFields) {
      if (!value) continue
      let hostname = ''
      try {
        hostname = String(new URL(value).hostname || '').toLowerCase()
      } catch (_) {
        continue
      }
      if (hostname && isBlockedPrivateTargetHost(hostname)) {
        issues.push({
          code: 'REMOTE_SEEDBOX_REQUIRES_PUBLIC_URL',
          message: `${label} points at ${hostname}, which is a private/loopback address. Remote Seedbox through the hosted relay needs a publicly reachable URL. Use PC Local or LAN Bridge for this machine's services, or enter the public URL of your separate seedbox.`
        })
        break
      }
    }
  }

  return issues
}

function isLoopbackHost(req) {
  const hostname = requestHostname(req)
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1'
}

function getInstallMode(req) {
  const mode = String(req.query.mode || '').toLowerCase()
  if (mode === 'local' || mode === 'hosted') return mode
  return isLoopbackHost(req) ? 'local' : 'hosted'
}

function shouldRejectPcLocalManifestRequest(req) {
  return (
    String(req.params?.config || '').toLowerCase() === 'local' &&
    !isLoopbackHost(req) &&
    !isLocalNetworkRequest(req)
  )
}

function parseBoolean(value) {
  const normalized = String(value || '').trim().toLowerCase()
  return normalized === '1' || normalized === 'true' || normalized === 'yes' || normalized === 'on'
}

function authSecretAvailable() {
  return Boolean(getAuthTokenSecret())
}

function isValidEmail(email) {
  const value = normalizeAccountEmail(email)
  if (!value) return false
  if (value.length < 5 || value.length > 254) return false
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)
}


function publicUserModel(user) {
  if (!user || typeof user !== 'object') return null
  const stremio = user.stremio && typeof user.stremio === 'object' ? user.stremio : {}
  return {
    stremio: {
      linked: Boolean(stremio.userId),
      userId: String(stremio.userId || ''),
      linkedAt: Number(stremio.linkedAt || 0),
      lastVerifiedAt: Number(stremio.lastVerifiedAt || 0)
    }
  }
}

async function requireAuthUser(req, res, next) {
  if (!authSecretAvailable()) {
    return res.status(500).json({ error: 'AUTH_TOKEN_SECRET not configured' })
  }
  const authSecret = getAuthTokenSecret()
  const token = parseBearerToken(req.headers.authorization || '')
  if (!token) return res.status(401).json({ error: 'Missing bearer token' })
  const payload = verifyAuthToken(token, authSecret)
  if (!payload) return res.status(401).json({ error: 'Invalid or expired token' })
  const userId = String(payload.sub || '').trim()
  if (!userId) return res.status(401).json({ error: 'Invalid token subject' })
  const user = await accountStore.getUserById(userId)
  if (!user) return res.status(401).json({ error: 'Account not found' })
  req.authUser = user
  req.authTokenPayload = payload
  next()
}

// Billing/subscription gating removed — addon is free.
// Kept as pass-through so route signatures don't change.
async function requireConfigSubscription(req, res, next) {
  return next()
}

function parseCacheSeconds(value, fallback, min = 0, max = 3600) {
  const raw = Number.parseInt(String(value ?? ''), 10)
  const safeFallback = Number.isFinite(fallback) ? fallback : 0
  if (!Number.isFinite(raw) || raw <= 0) return Math.max(min, Math.min(max, safeFallback))
  return Math.max(min, Math.min(max, raw))
}

function setPublicCacheHeaders(res, browserMaxAgeSeconds, options = {}) {
  const browserMaxAge = parseCacheSeconds(browserMaxAgeSeconds, 0, 0, 31536000)
  const sMaxAge = parseCacheSeconds(options.sMaxAge, browserMaxAge, 0, 31536000)
  const staleWhileRevalidate = parseCacheSeconds(
    options.staleWhileRevalidate,
    Math.max(sMaxAge, 60),
    0,
    31536000
  )
  const staleIfError = parseCacheSeconds(
    options.staleIfError,
    0,
    0,
    31536000
  )
  const directives = [
    'public',
    `max-age=${browserMaxAge}`,
    `s-maxage=${sMaxAge}`,
    `stale-while-revalidate=${staleWhileRevalidate}`
  ]
  if (staleIfError > 0) directives.push(`stale-if-error=${staleIfError}`)
  if (options.immutable) directives.push('immutable')
  res.setHeader('Cache-Control', directives.join(', '))
}

function applyHostedRouteCacheHeaders(req, res, browserMaxAgeSeconds, options = {}) {
  if (isDiskBackedConfigAlias(req.params?.config) || req.localConfigMissing) {
    res.setHeader('Cache-Control', 'no-store')
    return
  }
  setPublicCacheHeaders(res, browserMaxAgeSeconds, options)
}

function autoDeleteWatchedEnabled(config) {
  if (typeof config?.autoDeleteWatched === 'boolean') return config.autoDeleteWatched
  return parseBoolean(process.env.PVTKRRX_AUTO_DELETE_WATCHED)
}

function watchedDeleteGraceMs(config) {
  const cfgSeconds = Number.parseInt(String(config?.watchedDeleteGraceSeconds || ''), 10)
  if (Number.isFinite(cfgSeconds) && cfgSeconds >= 0) return cfgSeconds * 1000
  return WATCHED_DELETE_GRACE_MS
}

function scheduleWatchedCleanup(config, hash, reason = 'watched-threshold') {
  const normalizedHash = String(hash || '').toLowerCase()
  if (!normalizedHash) return
  if (!autoDeleteWatchedEnabled(config)) return
  if (watchedDeleteInFlight.has(normalizedHash)) return

  const existing = watchedDeleteTimers.get(normalizedHash)
  if (existing?.timer) clearTimeout(existing.timer)

  const delay = watchedDeleteGraceMs(config)
  const timer = setTimeout(async () => {
    watchedDeleteTimers.delete(normalizedHash)
    if (watchedDeleteInFlight.has(normalizedHash)) return
    watchedDeleteInFlight.add(normalizedHash)
    try {
      const qbit = new QBitClient(config.qbitUrl, config.qbitUsername, config.qbitPassword)
      await qbit.delete(normalizedHash, true)
      console.log(`[watch-cleanup] removed torrent ${normalizedHash.slice(0, 8)} (${reason})`)
    } catch (err) {
      console.warn(`[watch-cleanup] failed ${normalizedHash.slice(0, 8)}: ${err.message}`)
    } finally {
      watchedDeleteInFlight.delete(normalizedHash)
    }
  }, delay)

  if (typeof timer.unref === 'function') timer.unref()
  watchedDeleteTimers.set(normalizedHash, { timer, reason, scheduledAt: Date.now(), delay })
}

function getManifest(req) {
  const mode = getInstallMode(req)
  let profile = 'online'
  if (mode === 'local') {
    profile = 'local'
  } else if (isSelfHostConfigAlias(req?.params?.config)) {
    profile = 'selfhost'
  } else if (req?.params?.config && req.params.config !== 'local') {
    profile = resolveHostedProfile(req?.config || {})
  }

  const idSuffix = profile
  const nameLabel = profile === 'local'
    ? 'PC Local'
    : profile === 'selfhost'
      ? 'Self-Hosted Server'
    : profile === 'hybrid'
      ? 'LAN Bridge'
    : profile === 'lan'
      ? 'LAN Bridge'
      : 'Remote Seedbox'
  const defaultLogoUrl = `${getPublicBaseUrl(req)}/logo.png`
  // Keep local profile self-contained; hosted/lan profiles can use manifest logo URL.
  const logoUrl = profile === 'local'
    ? defaultLogoUrl
    : String(manifest.logo || defaultLogoUrl)

  const sourceTag = profile === 'local' ? '🖥️'
    : profile === 'lan' ? '🖥️'
    : SELF_HOST_SERVER_MODE ? '☁️'
    : ''
  const displayName = sourceTag ? `PVTKRR ${sourceTag}` : 'PVTKRR'

  const nextManifest = {
    ...manifest,
    behaviorHints: { ...(manifest.behaviorHints || {}) },
    id: `com.kepners.pvtkrrx.${idSuffix}`,
    name: displayName,
    logo: logoUrl
  }

  if (profile === 'local') {
    return {
      ...nextManifest,
      description: 'PC Local route for the Windows PC running PVTKRR. Uses your configured Prowlarr/qBittorrent setup and serves sports, movies, TV, and library from this local runtime.'
    }
  }

  if (profile === 'lan') {
    return {
      ...nextManifest,
      description: 'Legacy LAN Bridge route for other home devices. Requires the paired Windows host to be online on the home network and redirects playback into that host.'
    }
  }

  if (profile === 'hybrid') {
    return {
      ...nextManifest,
      description: 'LAN Bridge route for TVs, phones, and other home devices on the same Stremio account. Uses the paired Windows host at home and can fall back to configured public endpoints away from home.'
    }
  }

  if (profile === 'selfhost') {
    return {
      ...nextManifest,
      description: 'Self-hosted server route for your own VPS or seedbox. Uses this server runtime and its saved Prowlarr/qBittorrent config for sports, movies, TV, and library playback.'
    }
  }

  return {
    ...nextManifest,
    description: 'Remote Seedbox route for public away-from-home playback. Uses your configured public endpoints and ready-file paths for sports, movies, TV, and library streams.'
  }
}

async function warmLocalProviders(config, logger = console, reason = 'boot') {
  const safeLogger = createRedactingLogger(logger)
  const snapshot = config && typeof config === 'object' ? { ...config } : null
  if (!snapshot) {
    safeLogger.log(`[startup-warm] skipped (${reason}): no local config`)
    return null
  }

  const qbitUrl = String(snapshot.qbitUrl || '').trim()
  const jackettUrl = String(snapshot.jackettUrl || '').trim()
  const jackettApiKey = String(snapshot.jackettApiKey || '').trim()
  if (!qbitUrl && (!jackettUrl || !jackettApiKey)) {
    safeLogger.log(`[startup-warm] skipped (${reason}): qBittorrent/Prowlarr not configured`)
    return null
  }

  safeLogger.log(`[startup-warm] starting (${reason})`)
  const tasks = []

  if (qbitUrl) {
    tasks.push((async () => {
      const qbit = new QBitClient(qbitUrl, snapshot.qbitUsername, snapshot.qbitPassword)
      const torrents = await qbit.torrents('all')
      const total = Array.isArray(torrents) ? torrents.length : 0
      const completed = Array.isArray(torrents)
        ? torrents.filter(t => Number(t?.progress || 0) >= 0.999).length
        : 0
      const active = Math.max(0, total - completed)
      safeLogger.log(`[startup-warm] qBittorrent ready (${total} torrents, ${completed} completed, ${active} active)`)
      return { service: 'qbit', total, completed, active }
    })().catch((err) => {
      safeLogger.warn(`[startup-warm] qBittorrent warm-up failed: ${err.message}`)
      return { service: 'qbit', error: err.message }
    }))
  }

  if (jackettUrl && jackettApiKey) {
    tasks.push((async () => {
      const prowlarr = new ProwlarrClient(jackettUrl, jackettApiKey)
      const indexers = await prowlarr.caps()
      const count = Array.isArray(indexers) ? indexers.length : 0
      safeLogger.log(`[startup-warm] Prowlarr ready (${count} indexers)`)
      return { service: 'prowlarr', count }
    })().catch((err) => {
      safeLogger.warn(`[startup-warm] Prowlarr warm-up failed: ${err.message}`)
      return { service: 'prowlarr', error: err.message }
    }))
  }

  return Promise.all(tasks)
}

function scheduleLocalProviderWarmup(config = loadLocalConfigFile(), logger = console, reason = 'boot') {
  const snapshot = config && typeof config === 'object' ? { ...config } : null
  if (!snapshot) return Promise.resolve(null)
  if (localProviderWarmupPromise) return localProviderWarmupPromise

  localProviderWarmupPromise = warmLocalProviders(snapshot, logger, reason)
    .catch(() => null)
    .finally(() => {
      localProviderWarmupPromise = null
    })

  return localProviderWarmupPromise
}

function shouldRepairLocalProwlarrConfig(config = {}) {
  const jackettUrl = String(config?.jackettUrl || '').trim()
  const jackettApiKey = String(config?.jackettApiKey || '').trim()
  return Boolean(jackettUrl && !jackettApiKey && isLikelyLocalServiceUrl(jackettUrl))
}

async function repairLocalProwlarrConfig(config = loadLocalConfigFile(), logger = console, reason = 'boot') {
  const snapshot = config && typeof config === 'object' ? { ...config } : null
  if (!snapshot || process.platform !== 'win32' || IS_HOSTED_RELAY_RUNTIME) return snapshot
  if (!shouldRepairLocalProwlarrConfig(snapshot)) return snapshot
  if (localConfigRepairPromise) return localConfigRepairPromise

  const safeLogger = createRedactingLogger(logger)
  localConfigRepairPromise = (async () => {
    const discovered = await discoverProwlarrConfig()
    const discoveredUrl = String(discovered?.url || '').trim()
    const discoveredApiKey = String(discovered?.apiKey || '').trim()
    if (!discoveredUrl || !discoveredApiKey) {
      safeLogger.warn(`[config-repair] skipped (${reason}): local Prowlarr API key not available`)
      return snapshot
    }

    const currentUrl = String(snapshot.jackettUrl || '').trim()
    if (!isCompatibleLocalServiceUrl(currentUrl, discoveredUrl)) {
      safeLogger.warn(`[config-repair] skipped (${reason}): configured Prowlarr URL does not match discovered local service`)
      return snapshot
    }

    const repaired = normalizeAddonConfig({
      ...snapshot,
      jackettApiKey: discoveredApiKey
    }, {
      defaultEnabled: true,
      defaultRequired: true,
      includeLocalSecrets: true
    })

    if (JSON.stringify(repaired) !== JSON.stringify(snapshot)) {
      saveLocalConfigFile(repaired)
      safeLogger.log(`[config-repair] restored local Prowlarr API key (${reason})`)
    }

    return repaired
  })().catch((err) => {
    safeLogger.warn(`[config-repair] failed (${reason}): ${err.message}`)
    return snapshot
  }).finally(() => {
    localConfigRepairPromise = null
  })

  return localConfigRepairPromise
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms))
}

function extractInfoHashFromLink(link) {
  const raw = String(link || '')
  if (!raw) return ''

  const magnetMatch = raw.match(/[?&]xt=urn:btih:([a-zA-Z0-9]+)/i)
  if (magnetMatch && magnetMatch[1]) return magnetMatch[1].toLowerCase()

  const hashMatch = raw.match(/\b[a-fA-F0-9]{40}\b/)
  if (hashMatch && hashMatch[0]) return hashMatch[0].toLowerCase()
  return ''
}

function extractTrackerHost(link) {
  try {
    const url = new URL(String(link || ''))
    return String(url.hostname || '').toLowerCase()
  } catch (_) {
    return ''
  }
}

function pickLikelyNewTorrent(torrents, knownHashes, trackerHost) {
  if (!Array.isArray(torrents) || !torrents.length) return null
  const known = knownHashes || new Set()
  const host = String(trackerHost || '')
  const scored = torrents
    .filter(t => t?.hash)
    .map(t => {
      const hash = String(t.hash || '').toLowerCase()
      const isNew = !known.has(hash)
      let score = 0
      if (isNew) score += 1000
      if (host && String(t.tracker || '').toLowerCase().includes(host)) score += 100
      score += Number(t.added_on || 0)
      return { torrent: t, score }
    })
    .sort((a, b) => b.score - a.score)
  return scored[0]?.torrent || null
}

function normalizeTorrentPath(relPath) {
  return String(relPath || '').replace(/[\\/]+/g, '/').replace(/^\/+/, '')
}

function findTorrentFileByPath(files, relPath) {
  const target = normalizeTorrentPath(relPath).toLowerCase()
  if (!target) return null

  const direct = files.find(f => normalizeTorrentPath(f.name).toLowerCase() === target)
  if (direct) return direct

  const targetBase = path.basename(target)
  return files.find(f => path.basename(normalizeTorrentPath(f.name).toLowerCase()) === targetBase) || null
}

function resolveTorrentFilePath(torrent, relPath, additionalStorageRoots = []) {
  return findExistingLocalFilePath(torrent, relPath, additionalStorageRoots)
}

function getReadableBytes(fileEntry, torrent, diskBytes) {
  const complete = Number(torrent?.progress || 0) >= 0.999 || Number(fileEntry?.progress || 0) >= 0.999
  if (complete) return diskBytes

  const entrySize = Number(fileEntry?.size || 0)
  const fileProgress = Number(fileEntry?.progress || torrent?.progress || 0)
  let estimated = Math.floor(entrySize * fileProgress)
  if (!Number.isFinite(estimated) || estimated < 0) estimated = 0

  // Keep a small safety margin so range reads never outrun currently downloaded pieces.
  const margin = 2 * 1024 * 1024
  estimated = Math.max(0, estimated - margin)

  return Math.max(0, Math.min(diskBytes, estimated))
}

function getPlaybackReadyByteThreshold(fileEntry) {
  const size = Number(fileEntry?.size || 0)
  if (!size) return 0
  return Math.min(size, Math.max(1, STREAM_READY_MIN_BYTES, Math.floor(size * STREAM_READY_START_FRACTION)))
}

function isPlaybackReady(fileEntry, readableBytes) {
  const required = getPlaybackReadyByteThreshold(fileEntry)
  if (!required) return false
  return readableBytes >= required || Number(fileEntry?.progress || 0) >= 0.999
}

async function primeTorrentForStreaming(qbit, torrent, videoFile, allFiles = null) {
  const hash = String(torrent?.hash || '').toLowerCase()
  if (!hash) return

  const seqEnabled = torrent?.seq_dl === true
  const firstLastEnabled = torrent?.f_l_piece_prio === true
  const playbackComplete = Number(torrent?.progress || 0) >= 0.999 || Number(videoFile?.progress || 0) >= 0.999
  const shouldPrioritizeLastPieces = STREAM_PRIORITIZE_LAST_PIECES && !playbackComplete
  const files = Array.isArray(allFiles) ? allFiles : []
  const archiveFiles = findPackedArchiveFiles(files)
  const archiveMode = archiveFiles.length > 0 && (!videoFile?.name || isArchiveFileName(videoFile.name))

  if (!seqEnabled) {
    try {
      await qbit.toggleSequentialDownload(hash)
    } catch (err) {
      console.warn(`[streaming-prime] sequential toggle failed ${hash.slice(0, 8)}: ${err.message}`)
    }
  }
  // "first + last" can make the piece map appear scattered.
  // Keep it optional so local playback can stay head-first by default.
  if (shouldPrioritizeLastPieces && !firstLastEnabled) {
    try {
      await qbit.toggleFirstLastPiecePrio(hash)
    } catch (err) {
      console.warn(`[streaming-prime] first/last toggle failed ${hash.slice(0, 8)}: ${err.message}`)
    }
  } else if (!shouldPrioritizeLastPieces && firstLastEnabled) {
    try {
      await qbit.toggleFirstLastPiecePrio(hash)
    } catch (err) {
      console.warn(`[streaming-prime] first/last untoggle failed ${hash.slice(0, 8)}: ${err.message}`)
    }
  }

  const activeIds = archiveMode
    ? archiveFiles
      .filter(f => Number.isInteger(f?.index))
      .map(f => f.index)
    : (videoFile && Number.isInteger(videoFile.index))
      ? [videoFile.index]
      : []

  if (activeIds.length > 0) {
    try {
      const activeIdSet = new Set(activeIds)
      const otherFileIds = files
        .filter(f => Number.isInteger(f?.index) && !activeIdSet.has(f.index))
        .map(f => f.index)
      if (otherFileIds.length > 0) {
        await qbit.setFilePriority(hash, otherFileIds, 0)
      }
      await qbit.setFilePriority(hash, activeIds, 7)
    } catch (err) {
      console.warn(`[streaming-prime] file priority failed ${hash.slice(0, 8)}: ${err.message}`)
    }
  }
}

async function statPlayableFile(filePath) {
  const target = String(filePath || '').trim()
  if (!target) return null
  try {
    const stat = await fs.promises.stat(target)
    return stat?.isFile?.() ? stat : null
  } catch (_) {
    return null
  }
}

async function loadTorrentPlaybackState(qbit, hash, targetPath, additionalStorageRoots = []) {
  if (!hash) return null
  const list = await qbit.torrentsByHashes(hash, 'all')
  const torrent = Array.isArray(list) && list.length ? list[0] : null
  if (!torrent) return null

  const files = await qbit.files(torrent.hash)
  if (!Array.isArray(files) || files.length === 0) {
    return {
      torrent,
      files: [],
      file: null,
      resolvedFilePath: '',
      fileExists: false,
      diskSize: 0,
      readableBytes: 0,
      ready: false
    }
  }
  const targetFile = findTorrentFileByPath(files, targetPath)
  const preferredVideoFile = findVideoFile(files)
  const archiveFiles = findPackedArchiveFiles(files)
  const packedArchive = archiveFiles.length > 0
  const archiveReady = packedArchive && archiveFiles.every(file => Number(file?.progress || 0) >= 0.999)
  let extractedFilePath = packedArchive && archiveReady ? findExtractedArchiveVideoPath(torrent) : ''
  if (!extractedFilePath && packedArchive && archiveReady) {
    try {
      const extraction = await ensurePackedArchiveExtracted(torrent, files, additionalStorageRoots)
      if (extraction?.status === 'ready' && extraction.path) {
        extractedFilePath = extraction.path
      }
    } catch (err) {
      console.warn(`[archive-extract] ${String(torrent?.hash || '').slice(0, 8)}: ${err.message}`)
    }
  }

  // If a previous URL points to a Sample file, upgrade to the primary video when available.
  // For packed scene releases (RAR + Sample), avoid selecting Sample as main playback target.
  let chosenFile = null
  if (targetFile && !isSampleVideoName(targetFile.name)) {
    chosenFile = targetFile
  } else if (preferredVideoFile) {
    chosenFile = preferredVideoFile
  } else if (extractedFilePath) {
    const extractedStat = await statPlayableFile(extractedFilePath)
    const extractedSize = Number(extractedStat?.size || 0)
    chosenFile = {
      name: path.basename(extractedFilePath),
      size: extractedSize,
      progress: 1,
      extracted: true
    }
  } else if (targetFile && !packedArchive) {
    chosenFile = targetFile
  }

  const resolvedFilePath = chosenFile?.extracted
    ? extractedFilePath
    : resolveTorrentFilePath(torrent, chosenFile?.name || targetPath, additionalStorageRoots)
  const resolvedFileStat = await statPlayableFile(resolvedFilePath)
  const fileExists = Boolean(resolvedFileStat)
  const diskSize = fileExists ? Number(resolvedFileStat.size || 0) : 0
  const readableBytes = chosenFile?.extracted ? diskSize : getReadableBytes(chosenFile, torrent, diskSize)
  return {
    torrent,
    files,
    file: chosenFile,
    resolvedFilePath,
    fileExists,
    diskSize,
    readableBytes,
    packedArchive,
    archiveReady,
    ready: isPlaybackReady(chosenFile, readableBytes)
  }
}

async function mintHostedConfigToken(relayUrl, payload) {
  const relayBase = normalizeRelayUrl(relayUrl)
  const target = `${relayBase}/encrypt`

  let response
  try {
    response = await fetch(target, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'PVTKRRX-local-runtime'
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(15000)
    })
  } catch (err) {
    const wrapped = new Error(`Hosted relay token request failed: ${err.message}`)
    wrapped.statusCode = 502
    throw wrapped
  }

  const raw = await response.text()
  let data = {}
  if (raw) {
    try {
      data = JSON.parse(raw)
    } catch (_) {
      data = { error: raw.slice(0, 300) }
    }
  }

  if (!response.ok) {
    const wrapped = new Error(String(data.error || `Hosted relay token request failed (${response.status})`))
    wrapped.statusCode = response.status >= 500 ? 502 : response.status
    throw wrapped
  }

  const token = String(data.token || '').trim()
  if (!token) {
    const wrapped = new Error('Hosted relay token response missing token')
    wrapped.statusCode = 502
    throw wrapped
  }

  return {
    relayBase,
    token
  }
}

async function withConfig(req, res, next) {
  req.localConfigMissing = false
  req.configIssues = []
  req.cloudTakeoverConfig = null
  if (isDiskBackedConfigAlias(req.params.config)) {
    try {
      const localConfig = loadLocalConfigFile()
      if (!localConfig) {
        // Allow local manifest/configure bootstrap even before credentials are saved.
        req.localConfigMissing = true
        req.config = {}
        return next()
      }
      const repairedLocal = await repairLocalProwlarrConfig(localConfig, console, 'local-request')
      const normalizedLocal = normalizeAddonConfig(repairedLocal, {
        defaultEnabled: true,
        defaultRequired: true,
        includeLocalSecrets: true
      })
      if (JSON.stringify(normalizedLocal) !== JSON.stringify(repairedLocal)) {
        saveLocalConfigFile(normalizedLocal)
      }
      req.config = normalizedLocal
      req.configIssues = getConfigIssues(req.config, {
        requestBaseUrl: getPublicBaseUrl(req),
        localDiskConfig: String(req.params?.config || '').trim().toLowerCase() === 'local',
        selfHostDiskConfig: isSelfHostConfigAlias(req.params.config)
      })
      return next()
    } catch (err) {
      return res.status(500).json({ error: 'Failed to load disk-backed config' })
    }
  }

  const secret = process.env.ENCRYPTION_SECRET
  if (!secret) return res.status(500).json({ error: 'ENCRYPTION_SECRET not configured' })

  try {
    req.config = normalizeAddonConfig(decrypt(req.params.config, secret))
    req.cloudTakeoverConfig = await loadAccountHostedTakeoverConfig(req.config)
    req.configIssues = getConfigIssues(req.cloudTakeoverConfig || req.config, {
      requestBaseUrl: getPublicBaseUrl(req)
    })
    next()
  } catch (err) {
    res.status(400).json({ error: 'Invalid config token' })
  }
}

async function withLegacyRootLocalConfig(req, res, next) {
  req.params = {
    ...(req.params || {}),
    config: 'local'
  }
  req.legacyRootCompat = true
  return withConfig(req, res, next)
}

function isMagnetLink(link) {
  return String(link || '').trim().toLowerCase().startsWith('magnet:')
}

function isLanPairStateFresh(state, now = Date.now()) {
  if (!state || typeof state !== 'object') return false

  const updatedAt = Number(state.updatedAt || 0)
  if (!Number.isFinite(updatedAt) || updatedAt <= 0) return false
  if ((now - updatedAt) > LAN_PAIR_FRESHNESS_MS) return false

  const expiresAt = Number(state.expiresAt || 0)
  if (Number.isFinite(expiresAt) && expiresAt > 0 && expiresAt <= now) return false

  return true
}

async function resolveLanPair(config, req) {
  const enabled = parseBooleanLoose(config?.lanPairEnabled, false)
  if (!enabled) return { enabled: false, online: false, reason: 'disabled' }

  const pairId = sanitizePairId(config?.lanPairId)
  const pairKey = sanitizePairKey(config?.lanPairKey)
  if (!pairId || !pairKey) return { enabled: true, online: false, reason: 'missing-config' }

  const state = await lanPairStore.get(pairId)
  if (!state) return { enabled: true, online: false, reason: 'offline' }
  if (hashPairKey(pairKey) !== String(state.keyHash || '')) {
    return { enabled: true, online: false, reason: 'key-mismatch' }
  }
  if (!isLanPairStateFresh(state)) {
    return { enabled: true, online: false, reason: 'stale-heartbeat', state }
  }
  if (shouldBindLanPairToRequest(config)) {
    const stateIpHash = String(state.clientIpHash || '')
    const requestIpHash = hashClientIp(req)
    if (stateIpHash && requestIpHash && stateIpHash !== requestIpHash) {
      return { enabled: true, online: false, reason: 'network-mismatch' }
    }
  }

  const endpoint = chooseLanPairEndpoint(state)
  if (!endpoint) return { enabled: true, online: false, reason: 'no-endpoint' }

  return {
    enabled: true,
    online: true,
    endpoint,
    state
  }
}

function lanPairOfflineResponse(req, res, routeKind) {
  res.setHeader('Cache-Control', 'no-store')
  res.setHeader('X-PVTKRRX-LAN-Pair', 'offline')

  if (routeKind === 'catalog') return res.json({ metas: [], cacheMaxAge: 0 })
  if (routeKind === 'stream') return res.json({ streams: [], cacheMaxAge: 0 })
  if (routeKind === 'meta') {
    return res.json({
      meta: buildMetaPlaceholder({
        id: req.params?.id,
        type: req.params?.type,
        name: 'PVTKRRX host offline',
        description: 'LAN pair offline. Open PVTKRRX desktop on the host PC and retry.'
      })
    })
  }
  return res.status(503).json({
    error: 'LAN pair offline. Open PVTKRRX desktop on the host PC.'
  })
}

function applyCloudTakeoverConfig(req, res, routeKind, reason) {
  if (!req?.cloudTakeoverConfig || typeof req.cloudTakeoverConfig !== 'object') return false

  req.config = req.cloudTakeoverConfig
  req.configIssues = getConfigIssues(req.config, {
    requestBaseUrl: getPublicBaseUrl(req)
  })
  res.setHeader('X-PVTKRRX-Cloud-Takeover', 'linked-account')
  console.log(
    `[lan-pair] ${routeKind} cloud-takeover reason=${String(reason || 'offline')} from=${requestClientLabel(req)}`
  )
  return true
}

function maybeLanPairRedirect(routeKind) {
  return async (req, res, next) => {
    try {
      if (req.params.config === 'local') return next()
      if (isLoopbackHost(req)) return next()

      const resolution = await resolveLanPair(req.config || {}, req)
      req.lanPair = resolution
      const hostedProfile = resolveHostedProfile(req.config || {})
      const hybridProfile = hostedProfile === 'hybrid'

      if (!resolution.enabled) return next()

      if (!resolution.online) {
        if (routeKind === 'meta') {
          console.log(
            `[lan-pair] ${routeKind} fallback reason=${resolution.reason || 'unknown'} from=${requestClientLabel(req)}`
          )
          if (hybridProfile) {
            res.setHeader('X-PVTKRRX-LAN-Pair', 'fallback')
            res.setHeader('X-PVTKRRX-Route-Decision', 'cloud')
            res.setHeader('X-PVTKRRX-Route-Reason', String(resolution.reason || 'offline'))
            applyCloudTakeoverConfig(req, res, routeKind, resolution.reason || 'offline')
          }
          return next()
        }
        console.log(
          `[lan-pair] ${routeKind} offline reason=${resolution.reason || 'unknown'} from=${requestClientLabel(req)}`
        )
        if (parseBooleanLoose(req.config?.lanPairRequired, false)) {
          return lanPairOfflineResponse(req, res, routeKind)
        }
        if (hybridProfile) {
          res.setHeader('X-PVTKRRX-LAN-Pair', 'fallback')
          res.setHeader('X-PVTKRRX-Route-Decision', 'cloud')
          res.setHeader('X-PVTKRRX-Route-Reason', String(resolution.reason || 'offline'))
          applyCloudTakeoverConfig(req, res, routeKind, resolution.reason || 'offline')
        }
        return next()
      }

      const redirectUrl = buildLanRedirectUrl(req, resolution.endpoint.baseUrl)
      if (!redirectUrl) {
        if (parseBooleanLoose(req.config?.lanPairRequired, false)) {
          return lanPairOfflineResponse(req, res, routeKind)
        }
        if (hybridProfile) {
          res.setHeader('X-PVTKRRX-LAN-Pair', 'fallback')
          res.setHeader('X-PVTKRRX-Route-Decision', 'cloud')
          res.setHeader('X-PVTKRRX-Route-Reason', 'no-redirect-url')
          applyCloudTakeoverConfig(req, res, routeKind, 'no-redirect-url')
        }
        return next()
      }

      res.setHeader('Cache-Control', 'no-store')
      res.setHeader('X-PVTKRRX-LAN-Pair', 'redirect')
      res.setHeader('X-PVTKRRX-Route-Decision', 'lan')
      res.setHeader('X-PVTKRRX-Route-Reason', 'online')
      console.log(
        `[lan-pair] ${routeKind} redirect source=${String(resolution.endpoint?.source || 'unknown')} from=${requestClientLabel(req)}`
      )
      res.redirect(307, redirectUrl)
    } catch (err) {
      if (parseBooleanLoose(req.config?.lanPairRequired, false)) {
        return lanPairOfflineResponse(req, res, routeKind)
      }
      if (resolveHostedProfile(req.config || {}) === 'hybrid') {
        res.setHeader('X-PVTKRRX-LAN-Pair', 'fallback')
        res.setHeader('X-PVTKRRX-Route-Decision', 'cloud')
        res.setHeader('X-PVTKRRX-Route-Reason', 'resolve-error')
        applyCloudTakeoverConfig(req, res, routeKind, 'resolve-error')
      }
      next()
    }
  }
}

module.exports = {
  // State / Singletons
  runtimeDir,
  localConfigPath,
  lanPairStore,
  accountStore,
  stremioLinkStore,
  rateLimiters,
  watchedDeleteTimers,
  watchedDeleteInFlight,

  // Constants
  STREAM_WAIT_TIMEOUT_MS,
  STREAM_WAIT_INTERVAL_MS,
  STREAM_RANGE_WAIT_TIMEOUT_MS,
  STREAM_RANGE_WAIT_INTERVAL_MS,
  STREAM_READY_START_FRACTION,
  STREAM_READY_MIN_BYTES,
  STREAM_PRIORITIZE_LAST_PIECES,
  WATCHED_DELETE_THRESHOLD,
  WATCHED_DELETE_GRACE_MS,
  LAN_PAIR_TTL_SECONDS,
  LAN_PAIR_FRESHNESS_MS,
  LAN_PAIR_BIND_PUBLIC_IP,
  LAN_PAIR_LOCK_HOST,
  LAN_PAIR_RATE_LIMIT_WINDOW_MS,
  AUTH_TOKEN_TTL_SECONDS,
  STREMIO_API_BASE_URL,
  STREMIO_API_TIMEOUT_MS,
  STREMIO_AUTH_KEY_REGEX,
  STREMIO_AUTH_KEY_CAPTURE_PATTERN,
  STREMIO_AUTH_SCAN_DIRS_OVERRIDE,
  IS_HOSTED_RELAY_RUNTIME,
  SELF_HOST_SERVER_MODE,
  TRUST_PROXY_ENABLED,
  EXPRESS_TRUST_PROXY_SETTING,
  SENSITIVE_WEB_ORIGINS,
  CSRF_COOKIE_NAME,
  SECRET_CONFIG_FIELDS,
  DEFAULT_LOCAL_HOSTNAME,

  // Functions
  parseStartFraction,
  loadLocalEnv,
  loadLocalConfigFile,
  saveLocalConfigFile,
  detectLanAddresses,
  getMdnsHost,
  normalizeBaseUrl,
  parseUrlCandidate,
  defaultPortForProtocol,
  isLikelyLocalServiceUrl,
  isCompatibleLocalServiceUrl,
  ensureBootLanAccess,
  parseBooleanLoose,
  getAuthTokenSecret,
  sanitizePairId,
  makePairId,
  sanitizePairKey,
  makePairKey,
  summarizePairId,
  sanitizePairOwnerId,
  makePairOwnerId,
  hashPairKey,
  sanitizeStremioAuthKey,
  derivePairIdFromStremioUserId,
  parsePathList,
  extractStremioAuthKeysFromBlob,
  getStremioAuthScanSources,
  discoverLocalStremioAuthKeyCandidates,
  getLocalStremioDesktopInstallCandidates,
  getLocalStremioDesktopStatus,
  fetchStremioUserByAuthKey,
  createHttpError,
  createLinkedStremioAuthSession,
  normalizeClientIp,
  getSocketIp,
  getTrustedProxyIp,
  isLoopbackIp,
  getClientIp,
  isSameHostRequest,
  hashClientIp,
  requestClientLabel,
  isLikelyLanHost,
  resolveTargetAddresses,
  validateHostedConnectionTarget,
  parseHttpUrlCandidate,
  sanitizeLanBaseUrl,
  normalizePairEndpoints,
  summarizeEndpointSources,
  buildLanPairEndpoints,
  ensureLanPairConfig,
  normalizeAddonConfig,
  normalizeRetainedSecretFields,
  stripEphemeralConfigFields,
  mergeRetainedSecrets,
  loadConfigFromSourceToken,
  hydrateAccountLinkForConfig,
  resolveAccountUserForConfig,
  resolveSportsPosterEntitlementForConfig,
  applySportsPosterEntitlement,
  persistAccountHostedTakeoverConfig,
  buildConfigReadback,
  resolveExistingConfigForBody,
  chooseLanPairEndpoint,
  buildLanRedirectUrl,
  sanitizeHostForUrl,
  normalizeOrigin,
  parseOriginAllowlist,
  requestHostname,
  isLocalNetworkRequest,
  isConfigReadbackPath,
  isSensitiveCorsRoute,
  isAllowedSensitiveOriginValue,
  isAllowedSensitiveOrigin,
  parseRequestCookies,
  timingSafeEqualText,
  isDiskBackedConfigAlias,
  isSelfHostConfigAlias,
  hasServerAdminToken,
  ensureCsrfCookie,
  requireCsrfToken,
  requireServerAdminToken,
  requireLocalNetworkRoute,
  requireLocalConfigReadback,
  requireLocalQbitControl,
  getPublicBaseUrl,
  getPlaybackBaseUrl,
  getConfigIssues,
  isLoopbackHost,
  getInstallMode,
  shouldRejectPcLocalManifestRequest,
  parseBoolean,
  authSecretAvailable,
  isValidEmail,
  publicUserModel,
  requireAuthUser,
  requireConfigSubscription,
  parseCacheSeconds,
  setPublicCacheHeaders,
  applyHostedRouteCacheHeaders,
  autoDeleteWatchedEnabled,
  watchedDeleteGraceMs,
  scheduleWatchedCleanup,
  getManifest,
  warmLocalProviders,
  scheduleLocalProviderWarmup,
  shouldRepairLocalProwlarrConfig,
  repairLocalProwlarrConfig,
  sleep,
  extractInfoHashFromLink,
  extractTrackerHost,
  pickLikelyNewTorrent,
  normalizeTorrentPath,
  findTorrentFileByPath,
  resolveTorrentFilePath,
  getReadableBytes,
  getPlaybackReadyByteThreshold,
  isPlaybackReady,
  primeTorrentForStreaming,
  loadTorrentPlaybackState,
  mintHostedConfigToken,
  withConfig,
  withLegacyRootLocalConfig,
  isMagnetLink,
  parseTorrentFileName,
  fetchTorrentPayload,
  configLooksHostedTakeoverCapable,
  buildHostedTakeoverConfig,
  loadAccountHostedTakeoverConfig,
  isLanPairStateFresh,
  resolveLanPair,
  lanPairOfflineResponse,
  maybeLanPairRedirect,

  // Re-exported imports (needed by routes/middleware)
  manifest,
  encrypt,
  decrypt,
  decodeFileStateToken,
  decodePlaybackStateToken,
  handleCatalog,
  handleStream,
  handleMeta,
  ProwlarrClient,
  QBitClient,
  autoProvisionWindows,
  ensureWindowsLanAccess,
  discoverProwlarrConfig,
  getLanIpv4Addresses,
  normalizeLocalHostname,
  startLanAlias,
  buildLocalModeUrls,
  isBlockedPrivateTargetHost,
  isPrivateIpv4,
  isPrivateIpv6,
  normalizeRelayUrl,
  stripRemoteSeedboxLanFields,
  resolveRuntimeDir,
  findVideoFile,
  hasPackedArchiveFiles,
  isSampleVideoName,
  buildPlaybackFileUrl,
  normalizeLocalStorageRoots,
  findExistingLocalFilePath,
  PairStore,
  RateLimiter,
  AccountStore,
  normalizeAccountEmail,
  normalizeStremioUserId,
  hashStremioAuthKey,
  createAuthToken,
  verifyAuthToken,
  parseBearerToken,
  loadSecureJsonFile,
  saveSecureJsonFile,
  redactSensitiveText,
  createRedactingLogger,
  installConsoleRedaction,
  serverAdminState
}
