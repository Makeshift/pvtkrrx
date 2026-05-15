const fs = require('fs')
const crypto = require('crypto')
const http = require('http')
const https = require('https')
const path = require('path')
const pkg = require('./package.json')
const selfsigned = require('selfsigned')
const express = require('express')
const shared = require('./src/lib/shared')
const { isCompletedTorrent } = require('./src/utils/torrentState')
const { inspectTorrentPayload } = require('./src/utils/torrentPayload')
const { ensurePackedArchiveExtracted } = require('./src/utils/archiveExtraction')
const {
  getQbitPostProcessScriptPath,
  ensureQbitPostProcessScript,
  buildQbitAutorunProgram,
  describeQbitAutorunMode,
  findTorrentForPostProcess
} = require('./src/utils/qbitAutomation')
const { getBrowserConfig, trackEvent } = require('./src/utils/analytics')
const { scheduleSportsCatalogPrewarm } = require('./src/utils/sportsCatalogPrewarm')

// Legacy direct TheSportsDB paths (sports-image cache, 15-min autofill job,
// /sports/image proxy, and the experimental internal SportsMeta handler) were
// removed on 2026-04-22. SportsMeta is the single owner of sports metadata and
// artwork — PVTKRRX consumes it via https://sportsmeta.pvtkrrx.cc only.

// Destructure everything routes need from the shared module.
// Shared module initializes env, console redaction, stores, and rate limiters at load time.
const {
  // State & singletons
  lanPairStore, accountStore, stremioLinkStore, rateLimiters,
  watchedDeleteTimers, watchedDeleteInFlight,
  IS_HOSTED_RELAY_RUNTIME, SELF_HOST_SERVER_MODE, EXPRESS_TRUST_PROXY_SETTING, DEFAULT_LOCAL_HOSTNAME,
  STREAM_WAIT_TIMEOUT_MS, STREAM_WAIT_INTERVAL_MS,
  STREAM_RANGE_WAIT_TIMEOUT_MS, STREAM_RANGE_WAIT_INTERVAL_MS,
  STREAM_READY_START_FRACTION, STREAM_PRIORITIZE_LAST_PIECES,
  WATCHED_DELETE_THRESHOLD, WATCHED_DELETE_GRACE_MS,
  LAN_PAIR_TTL_SECONDS, LAN_PAIR_BIND_PUBLIC_IP, LAN_PAIR_LOCK_HOST,
  SECRET_CONFIG_FIELDS, SENSITIVE_WEB_ORIGINS, manifest,
  // Crypto & tokens
  encrypt, decrypt, decodeFileStateToken, decodePlaybackStateToken,
  // Handlers
  handleCatalog, handleStream, handleMeta,
  // Clients
  ProwlarrClient, QBitClient,
  // Provisioning
  autoProvisionWindows, normalizeLocalHostname, startLanAlias,
  // URL & network helpers
  buildLocalModeUrls, normalizeRelayUrl, stripRemoteSeedboxLanFields,
  buildPlaybackFileUrl, normalizeLocalStorageRoots,
  findVideoFile, hasPackedArchiveFiles, isSampleVideoName,
  // Account
  normalizeStremioUserId, createAuthToken,
  // Logging
  redactSensitiveText, createRedactingLogger,
  // Config & pair helpers
  loadLocalConfigFile, saveLocalConfigFile, detectLanAddresses, getMdnsHost,
  normalizeBaseUrl, normalizeAddonConfig, mergeRetainedSecrets,
  hydrateAccountLinkForConfig, resolveAccountUserForConfig,
  resolveSportsPosterEntitlementForConfig, applySportsPosterEntitlement,
  buildConfigReadback, resolveExistingConfigForBody,
  getConfigIssues, getPublicBaseUrl, getPlaybackBaseUrl, loadConfigFromSourceToken,
  persistAccountHostedTakeoverConfig,
  ensureLanPairConfig, normalizeRetainedSecretFields, stripEphemeralConfigFields,
  // Pair helpers
  sanitizePairId, sanitizePairKey, sanitizePairOwnerId,
  summarizePairId, hashPairKey, normalizePairEndpoints,
  summarizeEndpointSources, buildLanPairEndpoints,
  chooseLanPairEndpoint, buildLanRedirectUrl, isLanPairStateFresh,
  // Request & security helpers
  getClientIp, isSameHostRequest, hashClientIp, requestClientLabel,
  isSensitiveCorsRoute, isAllowedSensitiveOrigin, normalizeOrigin,
  ensureCsrfCookie, requestHostname, isLoopbackHost, getInstallMode,
  shouldRejectPcLocalManifestRequest, parseHttpUrlCandidate,
  sanitizeHostForUrl, validateHostedConnectionTarget, hasServerAdminToken,
  isLocalNetworkRequest, parseBooleanLoose,
  // Middleware
  requireCsrfToken, requireLocalNetworkRoute, requireLocalConfigReadback,
  requireLocalQbitControl, requireServerAdminToken, requireAuthUser, requireConfigSubscription,
  withConfig, withLegacyRootLocalConfig,
  // Auth
  getAuthTokenSecret, authSecretAvailable, isValidEmail, publicUserModel,
  discoverLocalStremioAuthKeyCandidates, getLocalStremioDesktopStatus,
  createLinkedStremioAuthSession,
  // Manifest & cache
  getManifest, parseCacheSeconds, setPublicCacheHeaders, applyHostedRouteCacheHeaders,
  // Warmup
  ensureBootLanAccess, warmLocalProviders, scheduleLocalProviderWarmup,
  repairLocalProwlarrConfig,
  // Playback helpers
  sleep, extractInfoHashFromLink, extractTrackerHost,
  pickLikelyNewTorrent, normalizeTorrentPath, findTorrentFileByPath,
  resolveTorrentFilePath, getReadableBytes, isPlaybackReady,
  primeTorrentForStreaming, loadTorrentPlaybackState,
  autoDeleteWatchedEnabled, watchedDeleteGraceMs, scheduleWatchedCleanup,
  isMagnetLink, parseTorrentFileName, fetchTorrentPayload,
  mintHostedConfigToken, resolveLanPair, lanPairOfflineResponse, maybeLanPairRedirect,
  serverAdminState
} = shared

const app = express()
app.set('trust proxy', EXPRESS_TRUST_PROXY_SETTING)
app.use(express.json({
  limit: '1mb',
  verify: (req, _res, buf) => {
    req.rawBody = Buffer.from(buf)
  }
}))

function getSportsArtworkBaseUrl(req) {
  const requestBaseUrl = getPublicBaseUrl(req)
  const configAlias = String(req.params?.config || '').trim().toLowerCase()
  const relayBase = normalizeRelayUrl(req.config?.lanPairRelayUrl || '')
  if (configAlias === 'local' && !isSameHostRequest(req) && relayBase) {
    return relayBase
  }
  return requestBaseUrl
}

// ─── CORS ───────────────────────────────────────────────────
app.use((req, res, next) => {
  const sensitiveCorsRoute = isSensitiveCorsRoute(req)
  const sensitiveOriginAllowed = !sensitiveCorsRoute || isAllowedSensitiveOrigin(req)
  const rawOrigin = String(req.headers.origin || '').trim()
  const requestOrigin = normalizeOrigin(rawOrigin)
  const responseOrigin = rawOrigin === 'null' ? 'null' : (requestOrigin || rawOrigin)

  if (rawOrigin) {
    if (sensitiveCorsRoute) {
      if (responseOrigin && sensitiveOriginAllowed) {
        res.setHeader('Access-Control-Allow-Origin', responseOrigin)
        res.setHeader('Vary', 'Origin')
      }
    } else {
      if (responseOrigin) {
        res.setHeader('Access-Control-Allow-Origin', responseOrigin)
        res.setHeader('Vary', 'Origin')
      } else {
        res.setHeader('Access-Control-Allow-Origin', '*')
      }
    }
  } else if (sensitiveCorsRoute) {
    if (requestOrigin && sensitiveOriginAllowed) {
      res.setHeader('Access-Control-Allow-Origin', requestOrigin)
      res.setHeader('Vary', 'Origin')
    }
  } else {
    res.setHeader('Access-Control-Allow-Origin', '*')
  }

  res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, POST, OPTIONS')
  const requestedHeaders = String(req.headers['access-control-request-headers'] || '').trim()
  const defaultHeaders = [
    'Content-Type',
    'Authorization',
    'Range',
    'Accept',
    'Stremio-Protocol-Version',
    'Access-Control-Request-Private-Network'
  ]
  res.setHeader('Access-Control-Allow-Headers', requestedHeaders || defaultHeaders.join(', '))
  if (String(req.headers['access-control-request-private-network'] || '').toLowerCase() === 'true') {
    res.setHeader('Access-Control-Allow-Private-Network', 'true')
  }
  res.setHeader('Access-Control-Max-Age', '600')
  res.setHeader('X-Content-Type-Options', 'nosniff')
  res.setHeader('X-Frame-Options', 'DENY')
  res.setHeader('Referrer-Policy', 'no-referrer')
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()')
  if (String(req.headers['x-forwarded-proto'] || req.protocol || '').toLowerCase().includes('https')) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
  }

  if (req.method === 'OPTIONS') {
    if (sensitiveCorsRoute && !sensitiveOriginAllowed) return res.sendStatus(403)
    return res.sendStatus(204)
  }
  if (sensitiveCorsRoute && !sensitiveOriginAllowed) {
    return res.status(403).json({ error: 'Origin not allowed' })
  }
  next()
})

// ─── Static routes ──────────────────────────────────────────
const publicDir = path.join(__dirname, 'public')
const configPage = path.join(publicDir, 'configure.html')
const configPageTemplate = fs.readFileSync(configPage, 'utf8')
const runbooksPage = path.join(publicDir, 'runbooks.html')
const sportsPage = path.join(publicDir, 'sports.html')
const clockrrPage = path.join(publicDir, 'clockrr.html')
const blogPage = path.join(publicDir, 'blog.html')
const faqPage = path.join(publicDir, 'faq.html')
const healthPage = path.join(publicDir, 'health.html')
const STREMIO_LINK_SESSION_TTL_SECONDS = Math.max(300, parseInt(process.env.PVTKRRX_STREMIO_LINK_SESSION_TTL_SECONDS || '1800', 10))
const GITHUB_OWNER = 'Kepners'
const GITHUB_REPO = 'pvtkrrx'
const GITHUB_RELEASES_LATEST_URL = `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/releases/latest`
const GITHUB_RELEASES_PAGE_URL = `https://github.com/${GITHUB_OWNER}/${GITHUB_REPO}/releases`
const PUBLIC_DOWNLOAD_BASE_URL = normalizeBaseUrl(
  process.env.PVTKRRX_PUBLIC_DOWNLOAD_BASE_URL ||
  'https://www.pvtkrrx.cc'
) || 'https://www.pvtkrrx.cc'
const SPORTSMETA_CHECKOUT_BASE_URL = normalizeBaseUrl(
  process.env.PVTKRRX_SPORTSMETA_CHECKOUT_BASE_URL ||
  process.env.PVTKRRX_SPORTSMETA_BASE_URL ||
  'https://sportsmeta.pvtkrrx.cc'
) || 'https://sportsmeta.pvtkrrx.cc'
const SPORTSMETA_CHECKOUT_TIMEOUT_MS = Math.max(
  2000,
  parseInt(process.env.PVTKRRX_SPORTSMETA_CHECKOUT_TIMEOUT_MS || '10000', 10)
)
const VERSION_STATUS_CACHE_MS = Math.max(60000, parseInt(process.env.PVTKRRX_VERSION_STATUS_CACHE_MS || '300000', 10))
let versionStatusCache = {
  fetchedAt: 0,
  data: null,
  promise: null,
  release: null
}

function analyticsRouteLabelFromProfile(profile) {
  const normalized = String(profile || '').trim().toLowerCase()
  if (normalized === 'local') return 'pc_local'
  if (normalized === 'lan' || normalized === 'hybrid') return 'lan_bridge'
  return 'remote_seedbox'
}

function queueAnalyticsEvent(req, eventName, data = {}, options = {}) {
  void trackEvent({
    hostname: requestHostname(req),
    selfHostServerMode: SELF_HOST_SERVER_MODE,
    eventName,
    url: options.url || req.path || '/',
    data: {
      runtime_surface: SELF_HOST_SERVER_MODE ? 'selfhost' : 'hosted',
      app_version: String(pkg.version || '0.0.0'),
      ...data
    },
    dedupeKey: options.dedupeKey,
    dedupeWindowMs: options.dedupeWindowMs
  })
}

function normalizeSportsPostersInterval(value) {
  const normalized = String(value || '').trim().toLowerCase()
  if (normalized === 'monthly') return 'month'
  if (normalized === 'annually' || normalized === 'annual' || normalized === 'yearly') return 'year'
  if (normalized === 'month' || normalized === 'year') return normalized
  return ''
}

app.use(express.static(publicDir, {
  maxAge: '1d',
  setHeaders: (res, filePath) => {
    const lowerPath = String(filePath || '').toLowerCase()
    if (lowerPath.endsWith('.html')) {
      setPublicCacheHeaders(res, 60, { sMaxAge: 900, staleWhileRevalidate: 86400 })
      return
    }
    setPublicCacheHeaders(res, 86400, { sMaxAge: 604800, staleWhileRevalidate: 2592000, immutable: true })
  }
}))

function canServeConfigureUi(req) {
  if (SELF_HOST_SERVER_MODE) return true
  return isSameHostRequest(req)
}

app.get('/configure', (req, res) => {
  if (!canServeConfigureUi(req)) {
    return res.redirect(302, '/#routes')
  }
  ensureCsrfCookie(req, res)
  setPublicCacheHeaders(res, 60, { sMaxAge: 900, staleWhileRevalidate: 86400 })
  sendConfigurePage(req, res)
})
app.get('/:config/configure', (req, res) => {
  if (!canServeConfigureUi(req)) {
    return res.redirect(302, '/#routes')
  }
  ensureCsrfCookie(req, res)
  setPublicCacheHeaders(res, 60, { sMaxAge: 900, staleWhileRevalidate: 86400 })
  sendConfigurePage(req, res)
})
app.get('/sports', (req, res) => {
  setPublicCacheHeaders(res, 60, { sMaxAge: 900, staleWhileRevalidate: 86400 })
  res.sendFile(sportsPage)
})
app.get('/clockrr', (req, res) => {
  setPublicCacheHeaders(res, 60, { sMaxAge: 900, staleWhileRevalidate: 86400 })
  res.sendFile(clockrrPage)
})
app.get('/blog', (req, res) => {
  setPublicCacheHeaders(res, 60, { sMaxAge: 900, staleWhileRevalidate: 86400 })
  res.sendFile(blogPage)
})
app.get('/faq', (req, res) => {
  setPublicCacheHeaders(res, 60, { sMaxAge: 900, staleWhileRevalidate: 86400 })
  res.sendFile(faqPage)
})
app.post('/sports/billing/checkout', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store')

  const clientIp = getClientIp(req)
  const limit = rateLimiters.sportsmeta.consume(`${clientIp || 'unknown'}:checkout`)
  if (!limit.allowed) {
    res.setHeader('Retry-After', String(limit.retryAfterSeconds))
    return res.status(429).json({ ok: false, error: 'too_many_requests' })
  }

  const interval = normalizeSportsPostersInterval(req.body?.interval || req.body?.billingInterval)
  if (!interval) {
    return res.status(400).json({ ok: false, error: 'invalid_interval' })
  }

  const checkoutEndpoint = `${SPORTSMETA_CHECKOUT_BASE_URL}/billing/checkout`
  try {
    const upstream = await fetch(checkoutEndpoint, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'accept': 'application/json'
      },
      body: JSON.stringify({
        tierId: 'posters',
        interval
      }),
      signal: AbortSignal.timeout(SPORTSMETA_CHECKOUT_TIMEOUT_MS)
    })

    const text = await upstream.text()
    let payload = {}
    try {
      payload = text ? JSON.parse(text) : {}
    } catch (_) {
      payload = { ok: false, error: 'invalid_sportsmeta_response' }
    }

    if (!upstream.ok) {
      return res.status(upstream.status).json({
        ok: false,
        error: payload.error || 'sportsmeta_checkout_failed',
        message: payload.message || ''
      })
    }

    return res.status(200).json({
      ok: Boolean(payload.ok),
      url: String(payload.url || ''),
      sessionId: String(payload.sessionId || '')
    })
  } catch (err) {
    console.warn(`[sports-checkout] SportsMeta checkout proxy failed: ${err.message}`)
    return res.status(502).json({
      ok: false,
      error: 'sportsmeta_checkout_unavailable',
      message: 'Sports checkout is temporarily unavailable.'
    })
  }
})
app.get('/runbooks', (req, res) => {
  setPublicCacheHeaders(res, 60, { sMaxAge: 900, staleWhileRevalidate: 86400 })
  res.sendFile(runbooksPage)
})
app.get('/seedbox-runbooks', (req, res) => {
  setPublicCacheHeaders(res, 60, { sMaxAge: 900, staleWhileRevalidate: 86400 })
  res.sendFile(runbooksPage)
})
app.get('/analytics-config.json', (req, res) => {
  res.setHeader('Cache-Control', 'no-store')
  res.json(getBrowserConfig({
    hostname: requestHostname(req),
    selfHostServerMode: SELF_HOST_SERVER_MODE
  }))
})
app.get('/app-config.json', (req, res) => {
  res.setHeader('Cache-Control', 'no-store')
  res.json(buildRuntimeAppConfig(req))
})

app.get(['/version-status.json', '/version.json'], async (_req, res) => {
  res.setHeader('Cache-Control', 'no-store')
  try {
    res.json(await getVersionStatus())
  } catch (err) {
    const fallback = buildVersionStatusPayload(null, err?.message || 'Unable to check release status')
    res.status(200).json(fallback)
  }
})

async function handleDesktopDownloadRedirect(req, res, assetKind = 'setup') {
  let release = null
  try {
    release = await getLatestRelease()
  } catch (_) {}

  const redirect = buildDesktopDownloadRedirectTarget(release, assetKind)
  const releaseTag = String(release?.tag_name || release?.name || '').trim()
  const downloadSource = normalizeDownloadSource(req.query?.source)

  queueAnalyticsEvent(req, 'desktop_download_requested', {
    asset_kind: assetKind,
    asset_name: String(redirect.asset?.name || ''),
    release_tag: releaseTag,
    resolved_target: redirect.resolvedTarget,
    source: downloadSource || 'unknown'
  }, {
    url: `/download/windows/${assetKind}`
  })

  res.setHeader('Cache-Control', 'no-store')
  return res.redirect(302, redirect.redirectUrl)
}

app.get(['/download/windows', '/download/windows/setup', '/download/latest/windows/setup'], async (req, res) => {
  try {
    await handleDesktopDownloadRedirect(req, res, 'setup')
  } catch (err) {
    res.redirect(302, GITHUB_RELEASES_PAGE_URL)
  }
})

app.get(['/download/windows/portable', '/download/latest/windows/portable'], async (req, res) => {
  try {
    await handleDesktopDownloadRedirect(req, res, 'portable')
  } catch (err) {
    res.redirect(302, GITHUB_RELEASES_PAGE_URL)
  }
})

app.get(['/install-selfhost.sh', '/install.sh'], (req, res) => {
  const scriptPath = path.join(__dirname, 'scripts', 'install-selfhost.sh')
  if (!fs.existsSync(scriptPath)) {
    return res.status(404).type('text/plain').send('install launcher not found')
  }

  queueAnalyticsEvent(req, 'selfhost_installer_requested', {
    source: 'public_launcher'
  }, {
    url: '/install-selfhost.sh'
  })

  res.setHeader('Cache-Control', 'no-store')
  res.setHeader('Content-Disposition', 'inline; filename="install-selfhost.sh"')
  res.type('text/x-shellscript')
  res.send(fs.readFileSync(scriptPath, 'utf8'))
})

function buildRuntimeAppConfig(req) {
  return {
    selfHostServerMode: SELF_HOST_SERVER_MODE,
    serverConfigAlias: SELF_HOST_SERVER_MODE ? 'selfhost' : '',
    serverConfigConfigured: SELF_HOST_SERVER_MODE ? Boolean(loadLocalConfigFile()) : false,
    publicBaseUrl: getPublicBaseUrl(req),
    stremioLinkingAvailable: authSecretAvailable(),
    desktopLocalOnly: parseBooleanLoose(process.env.PVTKRRX_DESKTOP_LOCAL_ONLY)
  }
}

function getConfigureBodyClasses(runtimeConfig = {}) {
  const classes = ['runtime-config-pending']
  if (runtimeConfig.selfHostServerMode === true) {
    classes.push('selfhost-seedbox-only')
  }
  if (runtimeConfig.desktopLocalOnly === true) {
    classes.push('desktop-local-only')
  }
  return classes.join(' ')
}

function sendConfigurePage(req, res) {
  const runtimeConfig = buildRuntimeAppConfig(req)
  const runtimeBootstrapJson = JSON.stringify(runtimeConfig).replace(/</g, '\\u003c')
  const runtimeHeadExtras = `<script>window.__PVTKRRX_RUNTIME_BOOTSTRAP__=${runtimeBootstrapJson};</script>`
  const runtimeBodyClass = getConfigureBodyClasses(runtimeConfig)
  res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive')
  res.setHeader('Cache-Control', 'no-store')
  res.type('html').send(
    configPageTemplate
      .replace('</head>', `${runtimeHeadExtras}</head>`)
      .replace('<body>', `<body class="${runtimeBodyClass}">`)
  )
}

function normalizeVersionString(value) {
  return String(value || '').trim().replace(/^v/i, '').split('+')[0].split('-')[0]
}

function normalizeReleaseAssetName(value) {
  return String(value || '').trim().toLowerCase()
}

function sanitizeExternalHttpsUrl(value, fallback = '') {
  const raw = String(value || '').trim()
  if (!raw) return String(fallback || '').trim()
  try {
    const parsed = new URL(raw)
    if (parsed.protocol !== 'https:') return String(fallback || '').trim()
    return parsed.toString()
  } catch (_) {
    return String(fallback || '').trim()
  }
}

function buildTrackedDownloadUrl(routePath) {
  const base = String(PUBLIC_DOWNLOAD_BASE_URL || 'https://www.pvtkrrx.cc').trim().replace(/\/+$/, '')
  const pathValue = String(routePath || '').trim()
  if (!pathValue) return base
  return `${base}${pathValue.startsWith('/') ? pathValue : `/${pathValue}`}`
}

function getLatestReleaseAssets(release) {
  const assets = Array.isArray(release?.assets) ? release.assets : []
  const executableAssets = assets.filter((asset) => {
    const name = normalizeReleaseAssetName(asset?.name)
    if (!name.endsWith('.exe')) return false
    if (name.endsWith('.blockmap')) return false
    return true
  })

  const setup = executableAssets.find((asset) => normalizeReleaseAssetName(asset?.name).includes('setup')) || null
  const portable = executableAssets.find((asset) => {
    const name = normalizeReleaseAssetName(asset?.name)
    return !name.includes('setup')
  }) || null

  return { setup, portable }
}

function normalizeDownloadSource(value) {
  const normalized = String(value || '').trim().toLowerCase().replace(/[^a-z0-9_-]/g, '_')
  return normalized.slice(0, 40)
}

function buildDesktopDownloadRedirectTarget(release, assetKind = 'setup') {
  const { setup, portable } = getLatestReleaseAssets(release)
  const selectedAsset = assetKind === 'portable' ? portable : setup
  const releasePageUrl = sanitizeExternalHttpsUrl(release?.html_url, GITHUB_RELEASES_PAGE_URL)
  const assetUrl = sanitizeExternalHttpsUrl(selectedAsset?.browser_download_url, '')

  if (assetUrl) {
    return {
      asset: selectedAsset,
      redirectUrl: assetUrl,
      resolvedTarget: 'github_asset'
    }
  }

  return {
    asset: selectedAsset,
    redirectUrl: releasePageUrl,
    resolvedTarget: 'release_page'
  }
}

function parseVersionParts(value) {
  return normalizeVersionString(value)
    .split('.')
    .map(part => Number.parseInt(part, 10))
    .filter(part => Number.isFinite(part))
}

function compareVersionStrings(left, right) {
  const leftParts = parseVersionParts(left)
  const rightParts = parseVersionParts(right)
  const totalParts = Math.max(leftParts.length, rightParts.length)
  for (let index = 0; index < totalParts; index += 1) {
    const leftValue = Number.isFinite(leftParts[index]) ? leftParts[index] : 0
    const rightValue = Number.isFinite(rightParts[index]) ? rightParts[index] : 0
    if (leftValue !== rightValue) {
      return leftValue > rightValue ? 1 : -1
    }
  }
  return 0
}

function buildVersionStatusPayload(release = null, error = '') {
  const currentVersion = normalizeVersionString(pkg.version || '0.0.0') || '0.0.0'
  const latestVersion = normalizeVersionString(release?.tag_name || release?.name || currentVersion) || currentVersion
  const latestReleaseUrl = sanitizeExternalHttpsUrl(release?.html_url, GITHUB_RELEASES_PAGE_URL)
  const latestReleaseName = String(release?.name || release?.tag_name || `v${latestVersion}`).trim()
  const latestTag = String(release?.tag_name || `v${latestVersion}`).trim()
  const latestReleaseAssets = getLatestReleaseAssets(release)
  const updateAvailable = !error && compareVersionStrings(currentVersion, latestVersion) < 0
  const status = error
    ? 'unavailable'
    : (updateAvailable ? 'update-available' : 'up-to-date')
  const message = error
    ? `Release check unavailable: ${error}`
    : (updateAvailable
      ? `Update available: v${latestVersion}`
      : `Up to date: v${currentVersion}`)

  return {
    ok: !error,
    source: 'github',
    status,
    message,
    currentVersion,
    currentTag: `v${currentVersion}`,
    latestVersion,
    latestTag,
    latestReleaseName,
    latestReleaseUrl,
    latestPublishedAt: String(release?.published_at || ''),
    releaseAssetCount: Array.isArray(release?.assets) ? release.assets.length : 0,
    hasWindowsSetupDownload: Boolean(latestReleaseAssets.setup),
    latestWindowsSetupAssetName: String(latestReleaseAssets.setup?.name || ''),
    latestWindowsSetupDownloadUrl: buildTrackedDownloadUrl('/download/windows/setup'),
    hasWindowsPortableDownload: Boolean(latestReleaseAssets.portable),
    latestWindowsPortableAssetName: String(latestReleaseAssets.portable?.name || ''),
    latestWindowsPortableDownloadUrl: buildTrackedDownloadUrl('/download/windows/portable'),
    updateAvailable,
    checkedAt: new Date().toISOString(),
    error: error || ''
  }
}

async function refreshVersionStatusCache() {
  let payload
  try {
    const response = await fetch(GITHUB_RELEASES_LATEST_URL, {
      headers: {
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'PVTKRRX'
      },
      signal: AbortSignal.timeout(6000)
    })
    if (!response.ok) {
      throw new Error(`GitHub release check returned HTTP ${response.status}`)
    }
    const release = await response.json()
    versionStatusCache.release = release
    payload = buildVersionStatusPayload(release)
  } catch (err) {
    payload = buildVersionStatusPayload(versionStatusCache.release, String(err?.message || err || 'Unknown release check error'))
    if (versionStatusCache.data) {
      payload = {
        ...versionStatusCache.data,
        status: 'unavailable',
        ok: false,
        error: payload.error,
        message: payload.message,
        checkedAt: payload.checkedAt
      }
    }
  }

  versionStatusCache.data = payload
  versionStatusCache.fetchedAt = Date.now()
  versionStatusCache.promise = null
  return payload
}

async function getVersionStatus() {
  const now = Date.now()
  if (versionStatusCache.data && (now - versionStatusCache.fetchedAt) < VERSION_STATUS_CACHE_MS) {
    return versionStatusCache.data
  }
  if (versionStatusCache.promise) {
    return versionStatusCache.promise
  }

  versionStatusCache.promise = refreshVersionStatusCache()

  return versionStatusCache.promise
}

async function getLatestRelease() {
  const now = Date.now()
  if (versionStatusCache.release && (now - versionStatusCache.fetchedAt) < VERSION_STATUS_CACHE_MS) {
    return versionStatusCache.release
  }
  if (versionStatusCache.promise) {
    await versionStatusCache.promise
    return versionStatusCache.release
  }

  versionStatusCache.promise = refreshVersionStatusCache()
  await versionStatusCache.promise
  return versionStatusCache.release
}

function sanitizeStremioLinkSessionToken(value) {
  const text = String(value || '').trim()
  if (!text) return ''
  if (!/^[A-Za-z0-9_-]{16,160}$/.test(text)) return ''
  return text
}

function makeStremioLinkSessionToken() {
  return crypto.randomBytes(24).toString('base64url')
}

function normalizeStremioLinkInstallMode(value) {
  return String(value || '').trim().toLowerCase() === 'local' ? 'local' : 'hosted'
}

function normalizeStremioLinkInstallTarget(value) {
  const normalized = String(value || '').trim().toLowerCase()
  return normalized === 'pc' || normalized === 'lan' || normalized === 'seedbox'
    ? normalized
    : 'seedbox'
}

function normalizeStremioLinkConfigAlias(value) {
  const normalized = String(value || '').trim().toLowerCase()
  if (normalized === 'local' || normalized === 'selfhost') return normalized
  return ''
}

function resolveStremioLinkSource(body = {}) {
  const sourceConfigToken = String(body?.sourceConfigToken || '').trim()
  if (sourceConfigToken) {
    return {
      kind: 'token',
      sourceConfigToken,
      configAlias: ''
    }
  }

  const configAlias = normalizeStremioLinkConfigAlias(body?.configAlias)
  if (configAlias) {
    return {
      kind: 'disk',
      sourceConfigToken: '',
      configAlias
    }
  }

  return {
    kind: 'none',
    sourceConfigToken: '',
    configAlias: ''
  }
}

function stremioLinkSourceMatchesConfig(session = {}, configValue = '') {
  const expectedToken = String(session?.sourceConfigToken || '').trim()
  const expectedAlias = normalizeStremioLinkConfigAlias(session?.configAlias)
  const actual = String(configValue || '').trim()
  if (expectedToken) return actual === expectedToken
  if (expectedAlias) return actual === expectedAlias
  return false
}

function canAccessStremioLinkSource(req, source = {}) {
  if (source.kind !== 'disk') return true
  if (source.configAlias === 'local') return isSameHostRequest(req)
  if (source.configAlias === 'selfhost') {
    return SELF_HOST_SERVER_MODE && (isSameHostRequest(req) || hasServerAdminToken(req))
  }
  return true
}

function getStremioLinkSourceError(req, source = {}) {
  if (source.kind !== 'disk') return null
  if (source.configAlias === 'local') {
    return {
      statusCode: 403,
      payload: { error: 'Open configure on the Windows host PC to link the local addon profile.' }
    }
  }
  if (source.configAlias === 'selfhost') {
    if (!SELF_HOST_SERVER_MODE) {
      return {
        statusCode: 404,
        payload: { error: 'Self-host server mode is not enabled' }
      }
    }
    return {
      statusCode: 401,
      payload: { error: 'Valid self-host password required' }
    }
  }
  return null
}

function getStremioLinkSessionTtlSeconds(session = {}) {
  const expiresAt = Number(session?.expiresAt || 0)
  if (!expiresAt) return STREMIO_LINK_SESSION_TTL_SECONDS
  return Math.max(30, Math.ceil((expiresAt - Date.now()) / 1000))
}

async function saveStremioLinkSession(session = {}) {
  const sessionToken = sanitizeStremioLinkSessionToken(session?.sessionToken)
  if (!sessionToken) return false
  const next = {
    ...session,
    sessionToken
  }
  return stremioLinkStore.set(sessionToken, next, getStremioLinkSessionTtlSeconds(next))
}

function appendQueryParams(urlText, params = {}) {
  const raw = String(urlText || '').trim()
  if (!raw) return ''
  try {
    const url = new URL(raw)
    for (const [key, value] of Object.entries(params)) {
      const text = String(value || '').trim()
      if (!text) continue
      url.searchParams.set(key, text)
    }
    return url.toString()
  } catch (_) {
    return raw
  }
}

function buildStremioLinkConfigureUrl(req, session = {}) {
  const sourceConfigToken = String(session?.sourceConfigToken || '').trim()
  const configAlias = normalizeStremioLinkConfigAlias(session?.configAlias)
  const installTarget = normalizeStremioLinkInstallTarget(session?.installTarget)
  const baseUrl = getPublicBaseUrl(req)
  const pathName = sourceConfigToken
    ? `/${encodeURIComponent(sourceConfigToken)}/configure`
    : (configAlias ? `/${encodeURIComponent(configAlias)}/configure` : '/configure')
  return appendQueryParams(`${baseUrl}${pathName}`, {
    linkSession: sanitizeStremioLinkSessionToken(session?.sessionToken),
    target: installTarget
  })
}

function buildStremioLinkInstallUrls(req, session = {}, options = {}) {
  const sourceConfigToken = String(session?.sourceConfigToken || '').trim()
  const configAlias = normalizeStremioLinkConfigAlias(session?.configAlias)
  const installMode = normalizeStremioLinkInstallMode(session?.installMode)
  const sessionToken = sanitizeStremioLinkSessionToken(session?.sessionToken)
  const includeLinkSession = options?.includeLinkSession !== false

  if (configAlias === 'local') {
    const port = parseInt(process.env.PORT || '7000', 10)
    const httpsPort = parseInt(process.env.HTTPS_PORT || '7001', 10)
    const loopback = buildLocalModeUrls('127.0.0.1', port, httpsPort)
    const addonUrl = includeLinkSession
      ? appendQueryParams(loopback.httpManifest, { linkSession: sessionToken })
      : loopback.httpManifest
    return {
      mode: 'local',
      addonUrl,
      stremioUrl: ''
    }
  }

  const configSegment = sourceConfigToken || configAlias
  if (!configSegment) {
    return {
      mode: installMode,
      addonUrl: '',
      stremioUrl: ''
    }
  }

  const baseUrl = getPublicBaseUrl(req)
  const addonUrl = appendQueryParams(
    `${baseUrl}/${encodeURIComponent(configSegment)}/manifest.json`,
    includeLinkSession
      ? {
          mode: installMode,
          linkSession: sessionToken
        }
      : {
          mode: installMode
        }
  )
  let stremioUrl = ''
  try {
    const parsed = new URL(addonUrl)
    stremioUrl = `stremio://${parsed.host}${parsed.pathname}${parsed.search}`
  } catch (_) {}

  return {
    mode: installMode,
    addonUrl,
    stremioUrl
  }
}

function buildStremioLinkSessionResponse(req, session = {}) {
  const install = buildStremioLinkInstallUrls(req, session)
  const linkedInstall = String(session?.linkedConfigToken || '').trim()
    ? buildStremioLinkInstallUrls(req, {
        ...session,
        sourceConfigToken: session.linkedConfigToken,
        configAlias: ''
      }, {
        includeLinkSession: false
      })
    : null

  return {
    ok: true,
    sessionToken: sanitizeStremioLinkSessionToken(session?.sessionToken),
    status: String(session?.status || 'pending').trim() || 'pending',
    createdAt: Number(session?.createdAt || 0),
    expiresAt: Number(session?.expiresAt || 0),
    installSeenAt: Number(session?.installSeenAt || 0),
    linkedAt: Number(session?.linkedAt || 0),
    configAlias: normalizeStremioLinkConfigAlias(session?.configAlias),
    persistedConfigSaved: session?.persistedConfigSaved === true,
    configureUrl: buildStremioLinkConfigureUrl(req, session),
    browserLinkUrl: `${getPublicBaseUrl(req)}/auth/stremio/link/${encodeURIComponent(String(session?.sessionToken || '').trim())}`,
    install,
    linkedInstall,
    stremio: {
      linked: Boolean(String(session?.stremioUserId || '').trim()),
      userId: String(session?.stremioUserId || '').trim(),
      recommendedPairId: String(session?.recommendedPairId || '').trim()
    }
  }
}

async function persistStremioLinkSessionConfig(session = {}, linkPayload = {}) {
  const stremioUserId = normalizeStremioUserId(linkPayload?.stremio?.userId || '')
  if (!stremioUserId) {
    return {
      linkedConfigToken: '',
      persistedConfigSaved: false
    }
  }

  const accountLinkedAt = Date.now()
  const baseLinkFields = {
    accountProvider: 'stremio-authkey',
    accountLinkedAt,
    stremioUserId
  }

  let persistedConfigSaved = false
  const configAlias = normalizeStremioLinkConfigAlias(session?.configAlias)
  if (configAlias === 'local' || configAlias === 'selfhost') {
    const existingDiskConfig = loadLocalConfigFile()
    if (existingDiskConfig && typeof existingDiskConfig === 'object') {
      const savedDiskConfig = await hydrateAccountLinkForConfig(normalizeAddonConfig({
        ...existingDiskConfig,
        ...baseLinkFields
      }, configAlias === 'local'
        ? { defaultEnabled: true, defaultRequired: true, includeLocalSecrets: true }
        : { includeLocalSecrets: true }
      ))
      saveLocalConfigFile(savedDiskConfig)
      persistedConfigSaved = true
    }
  }

  let linkedConfigToken = ''
  const sourceConfigToken = String(session?.sourceConfigToken || '').trim()
  if (sourceConfigToken) {
    const existingTokenConfig = loadConfigFromSourceToken(sourceConfigToken)
    if (existingTokenConfig && typeof existingTokenConfig === 'object') {
      const linkedTokenConfig = await hydrateAccountLinkForConfig(normalizeAddonConfig({
        ...existingTokenConfig,
        ...baseLinkFields
      }))
      const tokenPayload = linkedTokenConfig.lanPairEnabled === false
        ? stripRemoteSeedboxLanFields(linkedTokenConfig)
        : linkedTokenConfig
      linkedConfigToken = encrypt(tokenPayload, process.env.ENCRYPTION_SECRET)
    }
  }

  return {
    linkedConfigToken,
    persistedConfigSaved
  }
}

async function observeStremioLinkManifestHit(req) {
  const sessionToken = sanitizeStremioLinkSessionToken(req.query?.linkSession)
  if (!sessionToken) return

  const session = await stremioLinkStore.get(sessionToken)
  if (!session || !stremioLinkSourceMatchesConfig(session, req.params?.config)) return

  const next = {
    ...session,
    installSeenAt: Date.now(),
    installSeenRoute: String(req.params?.config || '').trim(),
    installSeenClient: requestClientLabel(req)
  }
  if (String(next.status || '').trim() !== 'linked') {
    next.status = 'install-seen'
  }
  await saveStremioLinkSession(next)
}

app.get('/auth/stremio/link/:sessionToken', async (req, res) => {
  const sessionToken = sanitizeStremioLinkSessionToken(req.params.sessionToken)
  if (!sessionToken) return res.status(400).json({ error: 'Invalid link session token' })

  const session = await stremioLinkStore.get(sessionToken)
  if (!session) return res.status(404).json({ error: 'Link session not found or expired' })

  res.redirect(302, buildStremioLinkConfigureUrl(req, session))
})

app.get('/auth/stremio/link-session/:sessionToken', async (req, res) => {
  const sessionToken = sanitizeStremioLinkSessionToken(req.params.sessionToken)
  if (!sessionToken) return res.status(400).json({ error: 'Invalid link session token' })

  const session = await stremioLinkStore.get(sessionToken)
  if (!session) return res.status(404).json({ error: 'Link session not found or expired' })

  res.setHeader('Cache-Control', 'no-store')
  res.json(buildStremioLinkSessionResponse(req, session))
})

app.post('/auth/stremio/link-session', requireCsrfToken, async (req, res) => {
  if (!authSecretAvailable()) {
    return res.status(500).json({ error: 'AUTH_TOKEN_SECRET not configured' })
  }

  const clientIp = getClientIp(req)
  const limit = rateLimiters.auth.consume(clientIp || 'unknown')
  if (!limit.allowed) {
    res.setHeader('Retry-After', String(limit.retryAfterSeconds))
    return res.status(429).json({ error: 'too many requests' })
  }

  const source = resolveStremioLinkSource(req.body)
  if (!canAccessStremioLinkSource(req, source)) {
    const denied = getStremioLinkSourceError(req, source)
    return res.status(denied?.statusCode || 403).json(denied?.payload || { error: 'Link session denied' })
  }

  const session = {
    sessionToken: makeStremioLinkSessionToken(),
    createdAt: Date.now(),
    expiresAt: Date.now() + STREMIO_LINK_SESSION_TTL_SECONDS * 1000,
    status: 'pending',
    sourceConfigToken: source.sourceConfigToken,
    configAlias: source.configAlias,
    installMode: normalizeStremioLinkInstallMode(req.body?.installMode),
    installTarget: normalizeStremioLinkInstallTarget(req.body?.installTarget),
    linkedConfigToken: '',
    persistedConfigSaved: false,
    stremioUserId: '',
    recommendedPairId: ''
  }

  await saveStremioLinkSession(session)
  queueAnalyticsEvent(req, 'stremio_link_session_created', {
    config_surface: source.configAlias ? 'disk' : 'token',
    install_mode: session.installMode || 'hosted',
    install_target: session.installTarget || 'unknown'
  }, {
    url: '/auth/stremio/link-session'
  })
  res.setHeader('Cache-Control', 'no-store')
  res.json(buildStremioLinkSessionResponse(req, session))
})
// Legacy PVTKRRX-owned sports artwork endpoints removed 2026-04-22.
// SportsMeta (https://sportsmeta.pvtkrrx.cc/asset/...) is now authoritative
// for sport posters, backgrounds, logos, and default/free SVG fallbacks. Any
// client still pointing at these paths should refresh its catalog cache.
app.get([
  '/thumb/sports/:info.png',
  '/thumb/sports/:variant/:info.png',
  '/thumb/sports/:info.svg',
  '/thumb/sports/:variant/:info.svg',
  '/image/sports/:variant/:token'
], (_req, res) => {
  res.status(410).send('pvtkrrx sports artwork moved to sportsmeta.pvtkrrx.cc')
})

// Sports artwork raster proxy. SportsMeta returns image/svg+xml for every
// asset URL and Stremio mobile/tablet clients do not render SVG posters, so
// PVTKRRX fetches the SVG and rasterizes it to PNG per variant. Keeps the
// emitted poster/background/logo URLs on the same public host as the catalog
// and meta responses.
const {
  handleDefaultSportsArtwork,
  handleCanonicalSportsArtwork
} = require('./src/handlers/sportsArtworkProxy')

app.get('/sports-artwork/default/:variant/:sport', async (req, res) => {
  try {
    await handleDefaultSportsArtwork(req, res, {})
  } catch (err) {
    console.warn(`[sports-artwork] default handler error: ${err.message}`)
    if (!res.headersSent) res.status(502).type('text/plain').send('sports artwork error')
  }
})

app.get('/sports-artwork/id/:variant/:canonicalId', async (req, res) => {
  try {
    await handleCanonicalSportsArtwork(req, res, {})
  } catch (err) {
    console.warn(`[sports-artwork] canonical handler error: ${err.message}`)
    if (!res.headersSent) res.status(502).type('text/plain').send('sports artwork error')
  }
})

// ─── POST /encrypt — server-side config encryption ─────────
app.post('/encrypt', async (req, res) => {
  const secret = process.env.ENCRYPTION_SECRET
  if (!secret) return res.status(500).json({ error: 'ENCRYPTION_SECRET not configured' })
  const clientIp = getClientIp(req)
  const limit = rateLimiters.encrypt.consume(clientIp || 'unknown')
  if (!limit.allowed) {
    res.setHeader('Retry-After', String(limit.retryAfterSeconds))
    return res.status(429).json({ error: 'too many requests' })
  }
  if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
    return res.status(400).json({ error: 'Invalid config payload' })
  }

  const existingConfig = resolveExistingConfigForBody(req.body)
  const mergedConfig = mergeRetainedSecrets(req.body, existingConfig)
  const requestedSportsTemplate = String(req.body?.sportsPosterTemplate || '').trim()
  const hydratedConfig = await hydrateAccountLinkForConfig(normalizeAddonConfig(mergedConfig))
  const { config: normalizedConfig, entitlement: encryptEntitlement } =
    await applySportsPosterEntitlement(hydratedConfig, { requestedTemplate: requestedSportsTemplate })
  const issues = getConfigIssues(normalizedConfig, {
    requestBaseUrl: getPublicBaseUrl(req)
  })
  if (issues.length > 0) {
    return res.status(400).json({
      error: issues[0].message,
      issueCode: issues[0].code,
      notifyUser: true
    })
  }

  try {
    const tokenPayload = normalizedConfig.lanPairEnabled === false
      ? stripRemoteSeedboxLanFields(normalizedConfig)
      : normalizedConfig
    const token = encrypt(tokenPayload, secret)
    let cloudTakeoverSaved = false
    try {
      const persistedTakeover = await persistAccountHostedTakeoverConfig(normalizedConfig)
      cloudTakeoverSaved = persistedTakeover?.saved === true
    } catch (persistErr) {
      console.warn('[encrypt] hosted takeover profile save failed:', persistErr.message)
    }
    queueAnalyticsEvent(req, 'config_generated', {
      route: analyticsRouteLabelFromProfile(normalizedConfig.routeProfile),
      route_profile: normalizedConfig.routeProfile || 'online',
      linked: Boolean(String(normalizedConfig.stremioUserId || '').trim()),
      entitlement_source: encryptEntitlement?.source || 'none'
    }, {
      url: '/encrypt'
    })
    res.json({
      token,
      cloudTakeoverSaved,
      entitlement: {
        source: encryptEntitlement?.source || 'none',
        allowed: Boolean(encryptEntitlement?.allowed),
        allowedSportsPosterTemplates: encryptEntitlement?.allowedTemplates || ['ticket-stub'],
        resolvedSportsPosterTemplate: encryptEntitlement?.resolvedTemplate || 'ticket-stub'
      }
    })
  } catch (err) {
    res.status(400).json({ error: 'Encryption failed' })
  }
})

// Save local-mode config to disk so Stremio can use a stable /local manifest URL.
app.post('/local-config', requireLocalNetworkRoute, async (req, res) => {
  const cfg = req.body || {}
  if (!cfg.qbitUrl) {
    return res.status(400).json({ error: 'qBit URL is required for local config' })
  }

  try {
    const existingConfig = resolveExistingConfigForBody(cfg, { preferLocal: true })
    const mergedConfig = mergeRetainedSecrets(cfg, existingConfig)
    const localHostname = normalizeLocalHostname(cfg.localHostname || DEFAULT_LOCAL_HOSTNAME)
    const localHostnameCustom = localHostname !== DEFAULT_LOCAL_HOSTNAME
    const requestedSportsTemplate = String(cfg?.sportsPosterTemplate || '').trim()
    const hydratedConfig = await hydrateAccountLinkForConfig(normalizeAddonConfig({
      ...mergedConfig,
      localHostname,
      localHostnameCustom
    }, {
      defaultEnabled: true,
      defaultRequired: true,
      includeLocalSecrets: true
    }))
    const { config: saved } = await applySportsPosterEntitlement(hydratedConfig, {
      requestedTemplate: requestedSportsTemplate
    })
    const persisted = saveLocalConfigFile(saved)
    scheduleLocalProviderWarmup(persisted, console, 'local-config-save').catch(err => {
      console.warn('[config-save] Provider warmup failed:', err.message)
    })
    scheduleSportsCatalogPrewarm(persisted, console, 'local-config-save', {
      defaultEnabled: SELF_HOST_SERVER_MODE
    }).catch(err => {
      console.warn('[config-save] Sports prewarm failed:', err.message)
    })
    res.json({
      ok: true,
      ...buildConfigReadback(persisted),
      localHostname
    })
  } catch (err) {
    res.status(500).json({ error: 'Failed to save local config' })
  }
})

// Save self-hosted server config to disk so the server keeps a stable /selfhost manifest URL.
app.post('/server-config', requireCsrfToken, requireServerAdminToken, async (req, res) => {
  const cfg = req.body && typeof req.body === 'object' && !Array.isArray(req.body)
    ? req.body
    : {}

  try {
    const existingConfig = resolveExistingConfigForBody(cfg, { preferLocal: true })
    const mergedConfig = mergeRetainedSecrets(cfg, existingConfig)
    const requestedSportsTemplate = String(cfg?.sportsPosterTemplate || '').trim()
    const hydratedConfig = await hydrateAccountLinkForConfig(normalizeAddonConfig(mergedConfig, {
      includeLocalSecrets: true
    }))
    const { config: saved } = await applySportsPosterEntitlement(hydratedConfig, {
      requestedTemplate: requestedSportsTemplate,
      selfHostAdmin: true
    })
    const persisted = saveLocalConfigFile(saved)
    scheduleLocalProviderWarmup(persisted, console, 'server-config-save').catch(err => {
      console.warn('[server-config-save] Provider warmup failed:', err.message)
    })
    scheduleSportsCatalogPrewarm(persisted, console, 'server-config-save', {
      defaultEnabled: SELF_HOST_SERVER_MODE
    }).catch(err => {
      console.warn('[server-config-save] Sports prewarm failed:', err.message)
    })
    res.json({
      ok: true,
      configAlias: 'selfhost',
      ...buildConfigReadback(persisted)
    })
  } catch (err) {
    res.status(500).json({ error: 'Failed to save server config' })
  }
})

app.post('/auto-provision', requireLocalNetworkRoute, async (req, res) => {
  try {
    const options = req.body || {}
    const localHostname = normalizeLocalHostname(options.localHostname || DEFAULT_LOCAL_HOSTNAME)
    const localHostnameCustom = localHostname !== DEFAULT_LOCAL_HOSTNAME
    let accountUserId = String(options.accountUserId || '').trim()
    let accountProvider = String(options.accountProvider || '').trim()
    let accountLinkedAt = Number(options.accountLinkedAt || 0)
    let stremioUserId = normalizeStremioUserId(options.stremioUserId || '')
    let hintedPairId = sanitizePairId(options.lanPairId || '')
    let autoLinkedSourceLabel = ''

    if (!stremioUserId && authSecretAvailable()) {
      const authSecret = getAuthTokenSecret()
      const candidates = discoverLocalStremioAuthKeyCandidates()
      for (const candidate of candidates) {
        try {
          const linked = await createLinkedStremioAuthSession(candidate.authKey, authSecret)
          stremioUserId = normalizeStremioUserId(linked?.stremio?.userId || '')
          if (!hintedPairId) {
            hintedPairId = sanitizePairId(linked?.stremio?.recommendedPairId || '')
          }
          if (stremioUserId) {
            if (!accountProvider) accountProvider = 'stremio-authkey'
            if (!accountLinkedAt) accountLinkedAt = Date.now()
            autoLinkedSourceLabel = String(candidate.sourceLabel || '').trim()
          }
          break
        } catch (err) {
          if (Number(err?.statusCode || 0) === 401) continue
          throw err
        }
      }
    }

    const result = await autoProvisionWindows({
      installIfMissing: options.installIfMissing,
      startIfStopped: options.startIfStopped,
      configureQbitLocalNoAuth: options.configureQbitLocalNoAuth,
      openFirewall: options.openFirewall,
      localHostname
    })
    const existingConfig = result.config
      ? resolveExistingConfigForBody(result.config, { preferLocal: true })
      : null
    const provisionedSource = result.config
      ? mergeRetainedSecrets({
        ...result.config,
        ...(accountUserId ? { accountUserId } : {}),
        ...(accountProvider ? { accountProvider } : {}),
        ...(accountLinkedAt > 0 ? { accountLinkedAt } : {}),
        ...(stremioUserId ? { stremioUserId } : {}),
        ...(hintedPairId ? { lanPairId: hintedPairId } : {}),
        localHostname,
        localHostnameCustom
      }, existingConfig)
      : null
    const provisionedConfig = provisionedSource
      ? normalizeAddonConfig(provisionedSource, {
        defaultEnabled: true,
        defaultRequired: true,
        includeLocalSecrets: true
      })
      : null
    const hydratedProvisionedConfig = provisionedConfig
      ? await hydrateAccountLinkForConfig(provisionedConfig)
      : null

    if (result.config && result.config.qbitUrl) {
      const persistedProvisionedConfig = saveLocalConfigFile(hydratedProvisionedConfig)
      scheduleLocalProviderWarmup(persistedProvisionedConfig, console, 'auto-provision').catch(err => {
        console.warn('[auto-provision] Provider warmup failed:', err.message)
      })
      result.config = persistedProvisionedConfig
    }
    const responseNotes = Array.isArray(result.notes) ? [...result.notes] : []
    if (autoLinkedSourceLabel) {
      responseNotes.push(`Signed-in Stremio session detected on this PC (${autoLinkedSourceLabel}) and linked automatically`)
    }
    res.json({
      ...result,
      notes: responseNotes,
      config: result.config ? buildConfigReadback(result.config) : null,
      lanPair: result.config
        ? {
            lanPairId: result.config.lanPairId,
            lanPairEnabled: result.config.lanPairEnabled,
            lanPairRequired: result.config.lanPairRequired,
            lanPairRelayUrl: result.config.lanPairRelayUrl
          }
        : null,
      localHostname
    })
  } catch (err) {
    res.status(500).json({ ok: false, error: 'Auto provision failed', detail: err.message })
  }
})

app.get('/health', (req, res) => {
  res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive')
  const accept = String(req.headers.accept || '')
  const wantsHtml = req.query?.format !== 'json' && accept.includes('text/html')
  if (wantsHtml) {
    setPublicCacheHeaders(res, 10, { sMaxAge: 60, staleWhileRevalidate: 60 })
    return res.sendFile(healthPage)
  }
  res.setHeader('Cache-Control', 'no-store')
  res.json({
    ok: true,
    time: new Date().toISOString()
  })
})

app.get('/auth/stremio/local-status', (req, res) => {
  if (!isSameHostRequest(req)) {
    return res.status(403).json({ error: 'Open configure on the Windows host PC to check local Stremio status.' })
  }

  try {
    res.setHeader('Cache-Control', 'no-store')
    res.json({
      ok: true,
      ...getLocalStremioDesktopStatus()
    })
  } catch (err) {
    res.status(500).json({
      error: 'Failed to inspect local Stremio status',
      detail: err.message
    })
  }
})

// Browser-triggered local account-link helpers read local session material from this machine,
// so keep both the same-host socket/IP gate and the configure page's double-submit CSRF flow.
app.post('/auth/stremio/auto-link-local', requireCsrfToken, async (req, res) => {
  if (!authSecretAvailable()) {
    return res.status(500).json({ error: 'AUTH_TOKEN_SECRET not configured' })
  }
  if (!isSameHostRequest(req)) {
    return res.status(403).json({ error: 'Auto detect only works from this PC. Open configure on the Windows host and try again.' })
  }

  const authSecret = getAuthTokenSecret()

  try {
    const clientIp = getClientIp(req)
    const limit = rateLimiters.auth.consume(clientIp || 'unknown')
    if (!limit.allowed) {
      res.setHeader('Retry-After', String(limit.retryAfterSeconds))
      return res.status(429).json({ error: 'too many requests' })
    }

    const candidates = discoverLocalStremioAuthKeyCandidates()
    if (!candidates.length) {
      return res.status(404).json({
        error: 'No signed-in Stremio session found on this PC',
        detail: 'Open Stremio Desktop or sign in at web.stremio.com in Brave, Chrome, or Edge, then try again.'
      })
    }

    let lastVerificationError = null
    for (const candidate of candidates) {
      try {
        const payload = await createLinkedStremioAuthSession(candidate.authKey, authSecret)
        return res.json({
          ...payload,
          detected: {
            method: 'local-storage',
            sourceLabel: candidate.sourceLabel
          }
        })
      } catch (err) {
        if (Number(err?.statusCode || 0) === 401) {
          lastVerificationError = err
          continue
        }
        throw err
      }
    }

    if (lastVerificationError) {
      return res.status(401).json({
        error: 'Signed-in Stremio session was found, but the stored AuthKey is no longer valid',
        detail: 'Open Stremio Desktop or web.stremio.com, refresh the login, then try Auto Find again.'
      })
    }

    return res.status(404).json({
      error: 'No valid Stremio AuthKey found on this PC',
      detail: 'Open Stremio Desktop or sign in at web.stremio.com, then try again.'
    })
  } catch (err) {
    const statusCode = Number(err?.statusCode || 0) || 500
    const payload = { error: statusCode === 500 ? 'Local Stremio auto-link failed' : err.message }
    if (err?.detail) payload.detail = err.detail
    res.status(statusCode).json(payload)
  }
})

// Manual AuthKey link is intentionally not same-host-only: the caller supplies the AuthKey
// directly, and sensitive-origin allowlisting plus double-submit CSRF is enough to protect it
// without breaking supported hosted configure flows.
app.post('/auth/stremio/link-authkey', requireCsrfToken, async (req, res) => {
  if (!authSecretAvailable()) {
    return res.status(500).json({ error: 'AUTH_TOKEN_SECRET not configured' })
  }
  const authSecret = getAuthTokenSecret()

  try {
    const clientIp = getClientIp(req)
    const limit = rateLimiters.auth.consume(clientIp || 'unknown')
    if (!limit.allowed) {
      res.setHeader('Retry-After', String(limit.retryAfterSeconds))
      return res.status(429).json({ error: 'too many requests' })
    }

    const payload = await createLinkedStremioAuthSession(req.body?.authKey, authSecret)
    const linkSessionToken = sanitizeStremioLinkSessionToken(req.body?.linkSessionToken)
    if (linkSessionToken) {
      const session = await stremioLinkStore.get(linkSessionToken)
      if (!session) {
        return res.status(404).json({ error: 'Link session not found or expired' })
      }

      const persisted = await persistStremioLinkSessionConfig(session, payload)
      const linkedSession = {
        ...session,
        status: 'linked',
        linkedAt: Date.now(),
        stremioUserId: String(payload?.stremio?.userId || '').trim(),
        recommendedPairId: String(payload?.stremio?.recommendedPairId || '').trim(),
        linkedConfigToken: String(persisted?.linkedConfigToken || '').trim(),
        persistedConfigSaved: persisted?.persistedConfigSaved === true
      }
      await saveStremioLinkSession(linkedSession)
      payload.linkSession = buildStremioLinkSessionResponse(req, linkedSession)
    }
    queueAnalyticsEvent(req, 'stremio_account_linked', {
      link_source: linkSessionToken ? 'session' : 'manual',
      persisted_config: Boolean(payload?.linkSession?.persistedConfigSaved === true)
    }, {
      url: '/auth/stremio/link-authkey'
    })
    res.json(payload)
  } catch (err) {
    const statusCode = Number(err?.statusCode || 0) || 500
    const payload = { error: statusCode === 500 ? 'Stremio link failed' : err.message }
    if (err?.detail) payload.detail = err.detail
    res.status(statusCode).json(payload)
  }
})

app.get('/auth/me', requireAuthUser, (req, res) => {
  res.setHeader('Cache-Control', 'no-store')
  res.json({
    ok: true,
    user: publicUserModel(req.authUser)
  })
})

// Returns local/lan install URLs for one-click setup across PC + TV/phone on same LAN.
app.get('/network-info', requireLocalNetworkRoute, (req, res) => {
  const port = parseInt(process.env.PORT || '7000', 10)
  const httpsPort = parseInt(process.env.HTTPS_PORT || '7001', 10)
  const lanIps = detectLanAddresses()
  const primaryLanIp = lanIps[0] || ''
  const mdnsHost = getMdnsHost()
  const loopback = buildLocalModeUrls('127.0.0.1', port, httpsPort)
  const mdns = buildLocalModeUrls(mdnsHost, port, httpsPort)
  const lan = primaryLanIp ? buildLocalModeUrls(primaryLanIp, port, httpsPort) : null

  res.json({
    port,
    httpsPort,
    localHostname: mdnsHost,
    loopback,
    mdns: { hostname: mdnsHost, ...mdns },
    lan,
    lanCandidates: lanIps.map(ip => ({ ip, ...buildLocalModeUrls(ip, port, httpsPort) })),
    preferredOrder: [
      { id: 'localhost', url: loopback.httpManifest },
      { id: 'mdns', url: mdns.httpManifest },
      { id: 'lan-ip', url: lan ? lan.httpManifest : '' }
    ],
    pairEndpoints: buildLanPairEndpoints(port, httpsPort)
  })
})


// Hybrid Home is a hosted route, so the same-host helper must ask the relay to mint
// the token with the relay's secret instead of encrypting it with the local runtime secret.
app.post('/local/lan-token', requireLocalNetworkRoute, requireCsrfToken, async (req, res) => {
  const localConfig = loadLocalConfigFile()
  if (!localConfig) return res.status(404).json({ error: 'Local config not saved yet' })

  try {
    const requestedRouteProfile = String(req.body?.routeProfile || '').trim().toLowerCase()
    const mergedLocalConfig = {
      ...localConfig,
      lanPairEnabled: true,
      ...(requestedRouteProfile ? { routeProfile: requestedRouteProfile } : {}),
      ...(typeof req.body?.lanPairRequired === 'boolean'
        ? { lanPairRequired: req.body.lanPairRequired }
        : {})
    }
    const normalized = await hydrateAccountLinkForConfig(normalizeAddonConfig(mergedLocalConfig, {
      defaultEnabled: true,
      defaultRequired: requestedRouteProfile === 'hybrid' ? false : true,
      includeLocalSecrets: true
    }))
    const pairId = sanitizePairId(normalized.lanPairId)
    const pairKey = sanitizePairKey(normalized.lanPairKey)
    if (!pairId || !pairKey || normalized.lanPairEnabled === false) {
      return res.status(400).json({ error: 'Hybrid Home is not configured yet' })
    }

    const hosted = await mintHostedConfigToken(normalized.lanPairRelayUrl || '', normalized)
    res.setHeader('Cache-Control', 'no-store')
    res.json({
      ok: true,
      token: hosted.token,
      lanPairId: pairId,
      lanPairRelayUrl: hosted.relayBase
    })
  } catch (err) {
    res.status(Number(err?.statusCode || 500)).json({ error: 'Failed to build LAN token', detail: err.message })
  }
})

app.get('/local/pair-status', requireLocalNetworkRoute, async (req, res) => {
  const localConfig = loadLocalConfigFile()
  if (!localConfig) {
    return res.status(404).json({ ok: false, error: 'Local config not saved yet' })
  }

  const pairId = sanitizePairId(localConfig.lanPairId)
  const pairKey = sanitizePairKey(localConfig.lanPairKey)
  const relayUrl = normalizeRelayUrl(localConfig.lanPairRelayUrl || '')
  if (!pairId || !pairKey || !relayUrl || localConfig.lanPairEnabled === false) {
    return res.json({ ok: true, online: false })
  }

  try {
    const relayRes = await fetch(`${relayUrl}/pair/status`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pairId, pairKey }),
      signal: AbortSignal.timeout(4000)
    })
    const relayData = await relayRes.json().catch(() => ({}))
    if (!relayRes.ok) {
      if (relayRes.status === 429) {
        res.setHeader('Retry-After', String(relayRes.headers.get('retry-after') || '60'))
        return res.status(429).json({ ok: false, error: 'relay rate-limited' })
      }
      return res.status(502).json({
        ok: false,
        error: 'relay status failed',
        detail: String(relayData?.error || `HTTP ${relayRes.status}`).trim()
      })
    }
    res.setHeader('Cache-Control', 'no-store')
    res.json({
      ok: true,
      online: relayData?.online === true,
      updatedAt: Number(relayData?.updatedAt || 0),
      expiresAt: Number(relayData?.expiresAt || 0)
    })
  } catch (err) {
    res.status(502).json({ ok: false, error: 'relay status failed', detail: err.message })
  }
})

app.post('/pair/heartbeat', async (req, res) => {
  try {
    const pairId = sanitizePairId(req.body?.pairId)
    const pairKey = sanitizePairKey(req.body?.pairKey)
    const ownerId = sanitizePairOwnerId(req.body?.ownerId)
    const localHostname = normalizeLocalHostname(req.body?.localHostname || DEFAULT_LOCAL_HOSTNAME)
    const relayUrl = normalizeRelayUrl(req.body?.relayUrl || '')
    const endpoints = normalizePairEndpoints(req.body?.endpoints || [])
    const pairLabel = summarizePairId(pairId || req.body?.pairId)
    const clientLabel = requestClientLabel(req)
    const endpointSources = summarizeEndpointSources(endpoints)

    if (!pairId || !pairKey || !ownerId) {
      console.warn(`[pair] heartbeat rejected id=${pairLabel} from=${clientLabel} reason=missing-fields`)
      return res.status(400).json({ ok: false, error: 'pairId, pairKey, and ownerId are required' })
    }
    if (!endpoints.length) {
      console.warn(`[pair] heartbeat rejected id=${pairLabel} from=${clientLabel} reason=no-endpoints`)
      return res.status(400).json({ ok: false, error: 'At least one valid LAN endpoint is required' })
    }
    const clientIp = getClientIp(req)
    const limit = rateLimiters.heartbeat.consume(`${clientIp || 'unknown'}:${pairId}`)
    if (!limit.allowed) {
      console.warn(`[pair] heartbeat rate-limited id=${pairLabel} from=${clientLabel}`)
      res.setHeader('Retry-After', String(limit.retryAfterSeconds))
      return res.status(429).json({ ok: false, error: 'too many requests' })
    }

    const incomingKeyHash = hashPairKey(pairKey)
    const incomingOwnerHash = hashPairKey(ownerId)
    const incomingIpHash = hashClientIp(req)
    const existingState = await lanPairStore.get(pairId)
    if (existingState) {
      const existingKeyHash = String(existingState.keyHash || '')
      const existingOwnerHash = String(existingState.ownerHash || '')
      const ownerMatches = Boolean(existingOwnerHash) && existingOwnerHash === incomingOwnerHash
      if (existingKeyHash && incomingKeyHash !== existingKeyHash && !ownerMatches) {
        console.warn(`[pair] heartbeat rejected id=${pairLabel} from=${clientLabel} reason=invalid-key`)
        return res.status(403).json({ ok: false, error: 'invalid pair key' })
      }
      if (LAN_PAIR_LOCK_HOST) {
        if (existingOwnerHash && existingOwnerHash !== incomingOwnerHash) {
          console.warn(`[pair] heartbeat rejected id=${pairLabel} from=${clientLabel} reason=owner-mismatch`)
          return res.status(409).json({ ok: false, error: 'pair owner mismatch' })
        }
      }
      if (LAN_PAIR_BIND_PUBLIC_IP && LAN_PAIR_LOCK_HOST) {
        const existingIpHash = String(existingState.clientIpHash || '')
        if (existingIpHash && incomingIpHash && existingIpHash !== incomingIpHash) {
          console.warn(`[pair] heartbeat rejected id=${pairLabel} from=${clientLabel} reason=host-mismatch`)
          return res.status(409).json({ ok: false, error: 'pair host mismatch' })
        }
      }
    }

    const now = Date.now()
    const state = {
      pairId,
      keyHash: incomingKeyHash,
      ownerHash: incomingOwnerHash,
      clientIpHash: incomingIpHash,
      endpoints,
      localHostname,
      relayUrl,
      appVersion: String(req.body?.appVersion || '').trim(),
      updatedAt: now,
      expiresAt: now + LAN_PAIR_TTL_SECONDS * 1000
    }
    await lanPairStore.set(pairId, state, LAN_PAIR_TTL_SECONDS)
    res.json({
      ok: true,
      online: true,
      ttlSeconds: LAN_PAIR_TTL_SECONDS,
      updatedAt: state.updatedAt
    })
    queueAnalyticsEvent(req, 'lan_host_active', {
      endpoint_count: endpoints.length,
      endpoint_sources: endpointSources,
      host_app_version: state.appVersion || ''
    }, {
      url: '/pair/heartbeat',
      dedupeKey: `pair:${pairId}:${new Date(now).toISOString().slice(0, 10)}`,
      dedupeWindowMs: 24 * 60 * 60 * 1000
    })
    console.log(
      `[pair] heartbeat ok id=${pairLabel} from=${clientLabel} endpoints=${endpoints.length} sources=${endpointSources} ttl=${LAN_PAIR_TTL_SECONDS}s`
    )
  } catch (err) {
    console.error('[pair] heartbeat error:', err.message)
    res.status(500).json({ ok: false, error: 'heartbeat failed', detail: err.message })
  }
})

app.post('/pair/status', async (req, res) => {
  try {
    const pairId = sanitizePairId(req.body?.pairId)
    const pairKey = sanitizePairKey(req.body?.pairKey)
    if (!pairId || !pairKey) return res.status(400).json({ ok: false, error: 'pairId and pairKey are required' })
    const clientIp = getClientIp(req)
    const limit = rateLimiters.status.consume(`${clientIp || 'unknown'}:${pairId}`)
    if (!limit.allowed) {
      res.setHeader('Retry-After', String(limit.retryAfterSeconds))
      return res.status(429).json({ ok: false, error: 'too many requests' })
    }

    const state = await lanPairStore.get(pairId)
    if (!state) {
      return res.json({ ok: true, online: false })
    }

    if (hashPairKey(pairKey) !== String(state.keyHash || '')) {
      return res.json({ ok: true, online: false })
    }

    if (LAN_PAIR_BIND_PUBLIC_IP) {
      const stateIpHash = String(state.clientIpHash || '')
      const requestIpHash = hashClientIp(req)
      if (stateIpHash && requestIpHash && stateIpHash !== requestIpHash) {
        return res.json({
          ok: true,
          online: false,
          reason: 'network-mismatch',
          updatedAt: Number(state.updatedAt || 0),
          expiresAt: Number(state.expiresAt || 0)
        })
      }
    }

    if (!isLanPairStateFresh(state)) {
      return res.json({
        ok: true,
        online: false,
        reason: 'stale-heartbeat',
        updatedAt: Number(state.updatedAt || 0),
        expiresAt: Number(state.expiresAt || 0)
      })
    }

    const preferred = chooseLanPairEndpoint(state)
    res.json({
      ok: true,
      online: Boolean(preferred),
      reason: preferred ? 'online' : 'no-endpoint',
      updatedAt: Number(state.updatedAt || 0),
      expiresAt: Number(state.expiresAt || 0)
    })
  } catch (err) {
    res.status(500).json({ ok: false, error: 'status failed', detail: err.message })
  }
})

// Local install helper page (localhost copy workflow).
// Open on the same PC that runs PVTKRRX:
// http://127.0.0.1:7000/local/install
app.get('/local/install', requireLocalNetworkRoute, (req, res) => {
  const port = parseInt(process.env.PORT || '7000', 10)
  const httpsPort = parseInt(process.env.HTTPS_PORT || '7001', 10)
  const desktopLocalOnly = parseBooleanLoose(process.env.PVTKRRX_DESKTOP_LOCAL_ONLY)
  const loopbackUrls = buildLocalModeUrls('127.0.0.1', port, httpsPort)
  const requestedHost = sanitizeHostForUrl(req.query.host)
  const headerHost = sanitizeHostForUrl(String(req.get('host') || '').split(':')[0])
  const fallbackHost = sanitizeHostForUrl(getMdnsHost())
  const host = requestedHost || headerHost || fallbackHost || '127.0.0.1'
  const lanDebugManifest = `http://${host}:${port}/local/manifest.json?mode=local`
  const showLanDebugManifest = host !== '127.0.0.1' && host !== 'localhost'
  const pcConfigureUrl = `http://127.0.0.1:${port}/configure?target=pc`
  const lanConfigureUrl = `http://127.0.0.1:${port}/configure?target=lan`
  const seedboxConfigureUrl = `http://127.0.0.1:${port}/configure?target=seedbox`
  const routeLead = desktopLocalOnly
    ? 'The Windows EXE now exposes the two local routes only. Use PC Local on this machine, and Hybrid Home for your other synced devices while this PC stays online.'
    : 'PVTKRRX now centers on three main Stremio routes: PC Local on this Windows machine, Hybrid Home for your synced devices, and Remote Seedbox for public ready-file playback.'
  const desktopLocalNote = desktopLocalOnly
    ? '<p class="route-note">Remote Seedbox has moved out of the Windows EXE. Use the separate server/cloud runtime for away-from-home playback.</p>'
    : ''
  const remoteSeedboxCard = desktopLocalOnly
    ? ''
    : `
        <section class="route-card">
          <div class="route-kicker">Public HTTPS endpoints</div>
          <h3>Remote Seedbox</h3>
          <p class="route-copy">Use this when Prowlarr, qBittorrent, and file serving are reachable over public authenticated URLs. On the hosted site this is not a generic tracker-buffering route: it is ready-file / public-playback only unless you self-host playback support.</p>
          <ul class="route-list">
            <li>Not a generic tracker-buffering route</li>
            <li>Works away from home LAN</li>
            <li>Requires public HTTPS playback path</li>
          </ul>
          <div class="actions">
            <a class="btn" href="${seedboxConfigureUrl}">Open Remote Seedbox Setup</a>
          </div>
          <p class="route-note">This is the right route for seedbox-first playback, not Hybrid Home. On the hosted relay it is intentionally ready-file / public-playback only and fails closed when the path cannot actually be served.</p>
        </section>`

  res.setHeader('Cache-Control', 'no-store')
  res.setHeader('Content-Type', 'text/html; charset=utf-8')
  res.send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>PVTKRRX Install Routes</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; background: #101018; color: #e8e8ff; }
    .shell { max-width: 1040px; margin: 0 auto; }
    .card { padding: 18px; border: 1px solid #2a2a3a; border-radius: 12px; background: #151526; box-shadow: 0 18px 40px rgba(0, 0, 0, 0.18); }
    .lead { max-width: 760px; line-height: 1.55; color: #c9d4f8; }
    .route-grid { display: grid; grid-template-columns: repeat(${desktopLocalOnly ? 2 : 3}, minmax(0, 1fr)); gap: 14px; margin-top: 18px; }
    .route-card { padding: 16px; border: 1px solid #2d3958; border-radius: 10px; background: linear-gradient(180deg, #131c2b, #101725); }
    .route-card h3 { margin: 0 0 6px; font-size: 18px; }
    .route-kicker { font-size: 11px; text-transform: uppercase; letter-spacing: 1.3px; color: #7dd3fc; margin-bottom: 10px; }
    .route-copy { min-height: 64px; line-height: 1.5; color: #d9e2ff; }
    .route-list { margin: 12px 0; padding-left: 18px; color: #b9c5e8; line-height: 1.45; }
    .route-list li + li { margin-top: 5px; }
    .actions { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 12px; }
    button.btn, a.btn { display: inline-block; padding: 10px 14px; background: #3b82f6; color: white; border: none; border-radius: 8px; cursor: pointer; font-size: 14px; text-decoration: none; }
    a.btn.secondary, button.btn.secondary { background: #1d2738; color: #d4def7; border: 1px solid #32415f; }
    code { display: block; margin-top: 10px; padding: 10px; background: #0c0c15; border-radius: 6px; word-break: break-all; }
    p { line-height: 1.45; }
    .route-note { margin-top: 10px; color: #99acd9; font-size: 13px; }
    @media (max-width: 900px) { .route-grid { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <div class="shell">
    <div class="card">
      <h2>PVTKRRX Install Routes</h2>
      <p class="lead">${routeLead}</p>
      ${desktopLocalNote}
      <div class="route-grid">
        <section class="route-card">
          <div class="route-kicker">Same Windows machine</div>
          <h3>PC Local</h3>
          <p class="route-copy">Use this on the same Windows machine that runs the local PVTKRRX server. It now exposes the real movies, TV, sports, and library catalogs on this PC.</p>
          <ul class="route-list">
            <li>Uses loopback only</li>
            <li>No heartbeat or account sync</li>
            <li>Direct same-PC browsing and playback</li>
          </ul>
          <div class="actions">
            <button class="btn" id="copyHttpBtn" type="button">Copy PC Local URL</button>
            <a class="btn secondary" href="${pcConfigureUrl}">Open PC Local Setup</a>
          </div>
          <code id="manifestCode">${loopbackUrls.httpManifest}</code>
          <p class="route-note">Install this in Stremio Desktop on this same Windows PC when you want PVTKRRX to appear as a real local addon source.</p>
          ${showLanDebugManifest
            ? `<p class="route-note">Debug-only raw LAN URL. This is not the supported same-PC install path.</p><code>${lanDebugManifest}</code>`
            : ''}
        </section>

        <section class="route-card">
          <div class="route-kicker">Home + away sync</div>
          <h3>Hybrid Home</h3>
          <p class="route-copy">Use one hosted addon on the same Stremio account. At home it follows the LAN host; away from home it falls back to your hosted/public playback path.</p>
          <ul class="route-list">
            <li>Hosted install URL with LAN redirect at home</li>
            <li>Cloud fallback away from home</li>
            <li>Host PC must stay online</li>
          </ul>
          <div class="actions">
            <a class="btn" href="${lanConfigureUrl}">Open Hybrid Home Setup</a>
          </div>
          <p class="route-note">This is the main synced route for your phone, TV, web, and Apple TV while the host PC stays online and the hosted path stays available away from home.</p>
        </section>
        ${remoteSeedboxCard}
      </div>
    </div>
  </div>
  <script>
    async function copyCode(codeId, btnId) {
      const btn = document.getElementById(btnId)
      const text = document.getElementById(codeId).textContent.trim()
      try {
        await navigator.clipboard.writeText(text)
        const prev = btn.textContent
        btn.textContent = 'Copied!'
        setTimeout(() => { btn.textContent = prev }, 1400)
      } catch (_) {
        const range = document.createRange()
        const code = document.getElementById(codeId)
        range.selectNodeContents(code)
        const sel = window.getSelection()
        sel.removeAllRanges()
        sel.addRange(range)
        try { document.execCommand('copy') } catch (_) {}
        sel.removeAllRanges()
      }
    }
    document.getElementById('copyHttpBtn').addEventListener('click', () => copyCode('manifestCode', 'copyHttpBtn'))
  </script>
</body>
</html>`)
})

// ─── POST /test-connection — validate credentials ──────────
app.post('/test-connection', requireCsrfToken, async (req, res) => {
  const clientIp = getClientIp(req)
  const limit = rateLimiters.testConnection.consume(clientIp || 'unknown')
  if (!limit.allowed) {
    res.setHeader('Retry-After', String(limit.retryAfterSeconds))
    return res.status(429).json({ error: 'too many requests' })
  }

  const payload = req.body && typeof req.body === 'object' && !Array.isArray(req.body)
    ? req.body
    : {}
  const existingConfig = resolveExistingConfigForBody(payload, { preferLocal: isSameHostRequest(req) })
  const mergedPayload = mergeRetainedSecrets(payload, existingConfig)
  const { jackettUrl, jackettApiKey, qbitUrl, qbitUsername, qbitPassword } = mergedPayload
  const parsedJackettUrl = parseHttpUrlCandidate(jackettUrl)
  const parsedQbitUrl = parseHttpUrlCandidate(qbitUrl)
  const trustedLocalCaller = isSameHostRequest(req)
  const trustedServerAdminCaller = trustedLocalCaller || hasServerAdminToken(req)

  try {
    if (!trustedServerAdminCaller) {
      for (const target of [parsedJackettUrl, parsedQbitUrl]) {
        await validateHostedConnectionTarget(target)
      }
    }
  } catch (err) {
    const statusCode = Number(err?.statusCode || 0) || 403
    return res.status(statusCode).json({ error: err.message })
  }

  const results = { jackett: false, qbit: false }

  if (!parsedJackettUrl || !String(jackettApiKey || '').trim()) {
    results.jackettError = 'Prowlarr URL and API key are required'
  } else {
    try {
      const prowlarr = new ProwlarrClient(parsedJackettUrl.toString(), jackettApiKey)
      await prowlarr.caps()
      results.jackett = true
    } catch (err) {
      results.jackettError = err.message
    }
  }

  if (!parsedQbitUrl) {
    results.qbitError = 'qBittorrent URL is required'
  } else {
    try {
      const qbit = new QBitClient(parsedQbitUrl.toString(), qbitUsername, qbitPassword)
      await qbit.preferences()
      results.qbit = true
    } catch (err) {
      results.qbitError = err.message
    }
  }

  res.json(results)
})

// ─── withConfig middleware ──────────────────────────────────


// ─── Stremio addon routes (config-authenticated) ────────────
app.get('/:config/manifest.json', withConfig, async (req, res) => {
  console.log(`[stremio] ← manifest  config=${req.params.config === 'local' ? 'local' : 'token'} from=${req.ip || req.socket?.remoteAddress || '?'}`)
  await observeStremioLinkManifestHit(req).catch(() => {})
  const m = getManifest(req)
  // Configured URL — user is already set up, show Install not Configure.
  // For /local without saved credentials, keep configurationRequired=true
  // so Stremio can install and then guide user to Configure instead of failing fetch.
  if (m.behaviorHints) m.behaviorHints.configurationRequired = Boolean(req.localConfigMissing)
  if (shouldRejectPcLocalManifestRequest(req)) {
    if (m.behaviorHints) m.behaviorHints.configurationRequired = true
    m.description = 'PC Local only works from http://127.0.0.1 on the same Windows PC. For phones, TVs, or other synced devices, install Hybrid Home instead.'
    console.warn(
      `[stremio] local manifest rejected for non-local host=${requestHostname(req) || '?'} from=${requestClientLabel(req)}`
    )
  }
  if (req.configIssues.length > 0) {
    if (m.behaviorHints) m.behaviorHints.configurationRequired = true
    m.description = req.configIssues[0].message
  }
  if (String(req.params?.config || '').trim().toLowerCase() !== 'local') {
    const route = analyticsRouteLabelFromProfile(req.config?.routeProfile)
    queueAnalyticsEvent(req, 'manifest_install_seen', {
      route,
      route_profile: req.config?.routeProfile || '',
      linked: Boolean(String(req.config?.stremioUserId || '').trim())
    }, {
      url: '/addon/manifest',
      dedupeKey: `manifest:${req.params.config}`,
      dedupeWindowMs: 365 * 24 * 60 * 60 * 1000
    })
    queueAnalyticsEvent(req, 'manifest_active_day', {
      route,
      route_profile: req.config?.routeProfile || '',
      linked: Boolean(String(req.config?.stremioUserId || '').trim())
    }, {
      url: '/addon/manifest',
      dedupeKey: `manifest-day:${req.params.config}:${new Date().toISOString().slice(0, 10)}`,
      dedupeWindowMs: 24 * 60 * 60 * 1000
    })
  }
  console.log(`[stremio] → manifest  id=${m.id} catalogs=${m.catalogs?.length || 0} configRequired=${m.behaviorHints?.configurationRequired} issues=${req.configIssues.length}`)
  applyHostedRouteCacheHeaders(req, res, 60, {
    sMaxAge: 300,
    staleWhileRevalidate: 900,
    staleIfError: 86400
  })
  res.json(m)
})

app.get('/:config/config.json', withConfig, requireLocalConfigReadback, (req, res) => {
  res.setHeader('Cache-Control', 'no-store')
  res.json(buildConfigReadback(req.config))
})

app.get('/manifest.json', (req, res) => {
  console.log(`[stremio] ← manifest  config=root from=${req.ip || req.socket?.remoteAddress || '?'}`)
  setPublicCacheHeaders(res, 60, {
    sMaxAge: 300,
    staleWhileRevalidate: 900,
    staleIfError: 86400
  })
  const m = manifest.createBootstrapManifest(getPublicBaseUrl(req), {
    selfHostServerMode: SELF_HOST_SERVER_MODE,
    desktopLocalOnly: parseBooleanLoose(process.env.PVTKRRX_DESKTOP_LOCAL_ONLY),
    guideOnlyBootstrap: !SELF_HOST_SERVER_MODE &&
      !parseBooleanLoose(process.env.PVTKRRX_DESKTOP_LOCAL_ONLY) &&
      !isSameHostRequest(req)
  })
  m.stremioAddonsConfig = {
    issuer: 'https://stremio-addons.net',
    signature: 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..AzQ40k5XkfKIpO43fWtS7A.rgrQ0RnN4MtCS-7tL73auLA3tO91P37eTo2JLWUZhd5DMLOI7psmn4CzRH7d31lu5JjNtf65Gj4NMonMW5kZn-rg93ZPkg3dYZpDk0d8EGajQMAYG8YCMdBMBuQYXY1s.wKjJvVG3pmEk-BmwU9L5AA'
  }
  console.log(`[stremio] → manifest  id=${m.id} catalogs=${m.catalogs?.length || 0} configRequired=${m.behaviorHints?.configurationRequired}`)
  res.json(m)
})

app.get('/catalog/:type/:id.json', withLegacyRootLocalConfig, requireConfigSubscription, async (req, res) => {
  console.warn(`[stremio] compat root catalog type=${req.params.type} id=${req.params.id} from=${requestClientLabel(req)} -> /local`)
  const result = await handleCatalog(req.config, req.params.type, req.params.id, null, {
    baseUrl: getSportsArtworkBaseUrl(req)
  })
  console.log(`[stremio] compat root catalog result type=${req.params.type} id=${req.params.id} metas=${result?.metas?.length || 0}`)
  const ttl = parseCacheSeconds(result?.cacheMaxAge, 120, 15, 900)
  applyHostedRouteCacheHeaders(req, res, 0, {
    sMaxAge: ttl,
    staleWhileRevalidate: Math.min(ttl * 4, 3600),
    staleIfError: Math.min(Math.max(ttl * 24, 3600), 86400)
  })
  res.json(result)
})

app.get('/catalog/:type/:id/:extra.json', withLegacyRootLocalConfig, requireConfigSubscription, async (req, res) => {
  console.warn(`[stremio] compat root catalog type=${req.params.type} id=${req.params.id} extra=${req.params.extra} from=${requestClientLabel(req)} -> /local`)
  const result = await handleCatalog(req.config, req.params.type, req.params.id, req.params.extra, {
    baseUrl: getSportsArtworkBaseUrl(req)
  })
  console.log(`[stremio] compat root catalog result type=${req.params.type} id=${req.params.id} metas=${result?.metas?.length || 0}`)
  const ttl = parseCacheSeconds(result?.cacheMaxAge, 120, 15, 900)
  applyHostedRouteCacheHeaders(req, res, 0, {
    sMaxAge: ttl,
    staleWhileRevalidate: Math.min(ttl * 4, 3600),
    staleIfError: Math.min(Math.max(ttl * 24, 3600), 86400)
  })
  res.json(result)
})

app.get('/stream/:type/:id.json', withLegacyRootLocalConfig, requireConfigSubscription, async (req, res) => {
  const addonUrl = getPublicBaseUrl(req)
  const playbackBaseUrl = getPlaybackBaseUrl(req)
  console.warn(`[stremio] compat root stream type=${req.params.type} id=${req.params.id} from=${requestClientLabel(req)} -> /local`)
  const result = await handleStream(req.config, req.params.type, req.params.id, addonUrl, 'local', playbackBaseUrl)
  console.log(`[stremio] compat root stream result type=${req.params.type} id=${req.params.id} streams=${Array.isArray(result?.streams) ? result.streams.length : 0}`)
  const ttl = parseCacheSeconds(result?.cacheMaxAge, 20, 5, 120)
  applyHostedRouteCacheHeaders(req, res, 0, { sMaxAge: ttl, staleWhileRevalidate: Math.min(ttl * 3, 300) })
  res.json(result)
})

app.get('/meta/:type/:id.json', withLegacyRootLocalConfig, requireConfigSubscription, async (req, res) => {
  console.warn(`[stremio] compat root meta type=${req.params.type} id=${req.params.id} from=${requestClientLabel(req)} -> /local`)
  const result = await handleMeta(req.config, req.params.type, req.params.id, {
    baseUrl: getSportsArtworkBaseUrl(req)
  })
  applyHostedRouteCacheHeaders(req, res, 0, {
    sMaxAge: 300,
    staleWhileRevalidate: 1800,
    staleIfError: 86400
  })
  res.json(result)
})

app.get('/:config/catalog/:type/:id.json', withConfig, requireConfigSubscription, maybeLanPairRedirect('catalog'), async (req, res) => {
  console.log(`[stremio] ← catalog   type=${req.params.type} id=${req.params.id} from=${req.ip || req.socket?.remoteAddress || '?'}`)
  const result = await handleCatalog(req.config, req.params.type, req.params.id, null, {
    baseUrl: getSportsArtworkBaseUrl(req)
  })
  console.log(`[stremio] → catalog   type=${req.params.type} id=${req.params.id} metas=${result?.metas?.length || 0}`)
  const ttl = parseCacheSeconds(result?.cacheMaxAge, 120, 15, 900)
  applyHostedRouteCacheHeaders(req, res, 0, {
    sMaxAge: ttl,
    staleWhileRevalidate: Math.min(ttl * 4, 3600),
    staleIfError: Math.min(Math.max(ttl * 24, 3600), 86400)
  })
  res.json(result)
})

app.get('/:config/catalog/:type/:id/:extra.json', withConfig, requireConfigSubscription, maybeLanPairRedirect('catalog'), async (req, res) => {
  console.log(`[stremio] ← catalog   type=${req.params.type} id=${req.params.id} extra=${req.params.extra} from=${req.ip || req.socket?.remoteAddress || '?'}`)
  const result = await handleCatalog(req.config, req.params.type, req.params.id, req.params.extra, {
    baseUrl: getSportsArtworkBaseUrl(req)
  })
  console.log(`[stremio] → catalog   type=${req.params.type} id=${req.params.id} metas=${result?.metas?.length || 0}`)
  const ttl = parseCacheSeconds(result?.cacheMaxAge, 120, 15, 900)
  applyHostedRouteCacheHeaders(req, res, 0, {
    sMaxAge: ttl,
    staleWhileRevalidate: Math.min(ttl * 4, 3600),
    staleIfError: Math.min(Math.max(ttl * 24, 3600), 86400)
  })
  res.json(result)
})

app.get('/:config/stream/:type/:id.json', withConfig, requireConfigSubscription, maybeLanPairRedirect('stream'), async (req, res) => {
  const addonUrl = getPublicBaseUrl(req)
  const playbackBaseUrl = getPlaybackBaseUrl(req)
  console.log(`[stremio] <- stream   type=${req.params.type} id=${req.params.id} from=${requestClientLabel(req)}`)
  const result = await handleStream(req.config, req.params.type, req.params.id, addonUrl, req.params.config, playbackBaseUrl)
  console.log(`[stremio] -> stream   type=${req.params.type} id=${req.params.id} streams=${Array.isArray(result?.streams) ? result.streams.length : 0}`)
  const ttl = parseCacheSeconds(result?.cacheMaxAge, 20, 5, 120)
  applyHostedRouteCacheHeaders(req, res, 0, { sMaxAge: ttl, staleWhileRevalidate: Math.min(ttl * 3, 300) })
  res.json(result)
})

app.get('/:config/meta/:type/:id.json', withConfig, requireConfigSubscription, maybeLanPairRedirect('meta'), async (req, res) => {
  console.log(`[stremio] ← meta     type=${req.params.type} id=${req.params.id} from=${req.ip || req.socket?.remoteAddress || '?'}`)
  const result = await handleMeta(req.config, req.params.type, req.params.id, {
    baseUrl: getSportsArtworkBaseUrl(req)
  })
  applyHostedRouteCacheHeaders(req, res, 0, {
    sMaxAge: 300,
    staleWhileRevalidate: 1800,
    staleIfError: 86400
  })
  res.json(result)
})

// Experimental internal SportsMeta routes removed 2026-04-22. SportsMeta is
// now a standalone service at https://sportsmeta.pvtkrrx.cc and owns its own
// /resolve, /event, catalog, and asset routes.

app.get('/:config/qbit/preferences', withConfig, requireLocalQbitControl, async (req, res) => {
  try {
    const qbit = new QBitClient(req.config.qbitUrl, req.config.qbitUsername, req.config.qbitPassword)
    const prefs = await qbit.preferences()
    const autorun = describeQbitAutorunMode(prefs)
    res.json({
      savePath: String(prefs?.save_path || ''),
      tempPath: String(prefs?.temp_path || ''),
      incompletePathEnabled: Boolean(prefs?.temp_path_enabled),
      additionalStorageRoots: normalizeLocalStorageRoots(req.config.additionalStorageRoots),
      autoExtractEnabled: autorun.autorunEnabled,
      autoExtractManagedByPvtkrrx: autorun.managedByPvtkrrx,
      autoExtractMode: autorun.mode,
      autoExtractLabel: autorun.label,
      autoExtractProgram: autorun.autorunProgram,
      autoExtractScriptPath: getQbitPostProcessScriptPath()
    })
  } catch (err) {
    res.status(500).json({ error: 'Failed to read qBit preferences', detail: err.message })
  }
})

app.post('/:config/qbit/download-path', withConfig, requireLocalQbitControl, async (req, res) => {
  try {
    const savePath = String(req.body?.savePath || '').trim()
    if (!savePath) return res.status(400).json({ error: 'savePath is required' })

    const qbit = new QBitClient(req.config.qbitUrl, req.config.qbitUsername, req.config.qbitPassword)
    await qbit.setPreferences({ save_path: savePath })
    const prefs = await qbit.preferences()
    const autorun = describeQbitAutorunMode(prefs)
    res.json({
      ok: true,
      savePath: String(prefs?.save_path || ''),
      tempPath: String(prefs?.temp_path || ''),
      incompletePathEnabled: Boolean(prefs?.temp_path_enabled),
      autoExtractEnabled: autorun.autorunEnabled,
      autoExtractManagedByPvtkrrx: autorun.managedByPvtkrrx,
      autoExtractMode: autorun.mode,
      autoExtractLabel: autorun.label
    })
  } catch (err) {
    res.status(500).json({ error: 'Failed to update qBit download path', detail: err.message })
  }
})

function getLocalQbitAutomationBaseUrl(req) {
  try {
    const current = new URL(getPublicBaseUrl(req))
    const port = String(current.port || process.env.PORT || '7000').trim() || '7000'
    return `http://127.0.0.1:${port}`
  } catch (_) {
    return `http://127.0.0.1:${String(process.env.PORT || '7000').trim() || '7000'}`
  }
}

app.post('/:config/qbit/auto-extract', withConfig, requireLocalQbitControl, async (req, res) => {
  try {
    const rawEnabled = req.body?.enabled
    const enableAutoExtract = rawEnabled === true || rawEnabled === 1 || String(rawEnabled).trim().toLowerCase() === 'true'
    const disableAutoExtract = rawEnabled === false || rawEnabled === 0 || String(rawEnabled).trim().toLowerCase() === 'false'
    if (!enableAutoExtract && !disableAutoExtract) {
      return res.status(400).json({ error: 'enabled must be true or false' })
    }

    const qbit = new QBitClient(req.config.qbitUrl, req.config.qbitUsername, req.config.qbitPassword)
    const currentPrefs = await qbit.preferences()
    const currentAutorun = describeQbitAutorunMode(currentPrefs)

    if (!currentAutorun.managedByPvtkrrx && String(currentAutorun.autorunProgram || '').trim()) {
      return res.status(409).json({
        error: 'qBittorrent already has a different completion program configured. Clear that external completion program in qBittorrent before letting PVTKRRX manage packed-release extraction.'
      })
    }

    if (enableAutoExtract) {
      const baseUrl = getLocalQbitAutomationBaseUrl(req)
      const scriptPath = ensureQbitPostProcessScript(baseUrl)
      await qbit.setPreferences({
        autorun_enabled: true,
        autorun_program: buildQbitAutorunProgram(scriptPath, baseUrl)
      })
    } else {
      await qbit.setPreferences({
        autorun_enabled: false,
        autorun_program: ''
      })
    }

    const updatedPrefs = await qbit.preferences()
    const autorun = describeQbitAutorunMode(updatedPrefs)
    res.json({
      ok: true,
      autoExtractEnabled: autorun.autorunEnabled,
      autoExtractManagedByPvtkrrx: autorun.managedByPvtkrrx,
      autoExtractMode: autorun.mode,
      autoExtractLabel: autorun.label,
      autoExtractProgram: autorun.autorunProgram,
      autoExtractScriptPath: getQbitPostProcessScriptPath()
    })
  } catch (err) {
    res.status(500).json({ error: 'Failed to update qBit packed-release extraction hook', detail: err.message })
  }
})

app.post('/:config/qbit/postprocess', withConfig, requireLocalQbitControl, async (req, res) => {
  try {
    const completedPath = String(req.body?.completedPath || '').trim()
    const torrentName = String(req.body?.torrentName || '').trim()
    if (!completedPath && !torrentName) {
      return res.status(400).json({ error: 'completedPath or torrentName is required' })
    }

    const qbit = new QBitClient(req.config.qbitUrl, req.config.qbitUsername, req.config.qbitPassword)
    const torrents = await qbit.torrents('completed')
    const torrent = findTorrentForPostProcess(torrents, completedPath, torrentName)
    if (!torrent?.hash) {
      return res.json({
        ok: true,
        status: 'ignored',
        reason: 'torrent-not-found'
      })
    }

    const files = await qbit.files(torrent.hash)
    if (!hasPackedArchiveFiles(files)) {
      return res.json({
        ok: true,
        status: 'ignored',
        reason: 'not-packed-archive',
        hash: String(torrent.hash || '').slice(0, 8)
      })
    }

    const extraction = await ensurePackedArchiveExtracted(torrent, files, req.config.additionalStorageRoots)
    res.json({
      ok: true,
      status: String(extraction?.status || 'unknown'),
      hash: String(torrent.hash || '').slice(0, 8),
      extractedPath: String(extraction?.path || '')
    })
  } catch (err) {
    res.status(500).json({ error: 'Failed to post-process completed qBit torrent', detail: err.message })
  }
})

// ─── Built-in file server — serves local files with Range support ───
// Used when no external fileServerUrl is configured (e.g. local qBit setup).
app.get('/:config/file/:info', withConfig, requireConfigSubscription, maybeLanPairRedirect('file'), async (req, res) => {
  try {
    if (IS_HOSTED_RELAY_RUNTIME && req.params.config !== 'local') {
      return res.status(403).json({
        error: 'Built-in file serving is disabled on hosted runtime',
        detail: 'Use File Server URL or LAN Pair local relay for playback'
      })
    }

    let state = null
    try {
      state = decodeFileStateToken(req.params.info)
    } catch (_) {
      return res.status(400).json({ error: 'Invalid file token' })
    }
    const h = String(state?.h || '').toLowerCase()
    const p = String(state?.p || '')
    console.log(`[file-route] hash=${String(h || '').slice(0, 8)} hasPath=${Boolean(p)}`)
    const qbit = new QBitClient(req.config.qbitUrl, req.config.qbitUsername, req.config.qbitPassword)
    const playback = await loadTorrentPlaybackState(qbit, String(h || '').toLowerCase(), p, req.config.additionalStorageRoots)
    let isOrphanFile = false
    let orphanFileStat = null

    if (!playback?.torrent) {
      const absoluteTokenPath = path.isAbsolute(p) ? path.normalize(p) : ''
      if (!absoluteTokenPath) {
        console.warn(`[file-route] torrent not found hash=${String(h || '').slice(0, 8)}`)
        return res.status(404).json({ error: 'Torrent not found' })
      }
      try {
        orphanFileStat = await fs.promises.stat(absoluteTokenPath)
      } catch (_) {
        console.warn(`[file-route] torrent not found hash=${String(h || '').slice(0, 8)}`)
        return res.status(404).json({ error: 'Torrent not found' })
      }
      if (!orphanFileStat?.isFile()) {
        console.warn(`[file-route] orphan path is not a file hash=${String(h || '').slice(0, 8)}`)
        return res.status(404).json({ error: 'File not found' })
      }
      isOrphanFile = true
    }

    let torrent = playback?.torrent || { hash: h, progress: 1 }
    let files = playback?.files || []
    let file = playback?.file || null
    let resolvedFilePath = playback?.resolvedFilePath || (isOrphanFile ? path.normalize(p) : '')
    const torrentHash = String(torrent?.hash || h || '').toLowerCase()
    if (!file && isOrphanFile) {
      file = {
        name: path.basename(path.normalize(p)),
        size: Number(orphanFileStat?.size || 0),
        progress: 1
      }
    }
    if (!file) {
      const errMsg = playback.packedArchive
        ? 'Packed archive release detected (RAR) with no direct video file. Choose a WEB-DL/REMUX source.'
        : 'No playable video file found in torrent.'
      return res.status(422).json({ error: errMsg })
    }
    if (!isOrphanFile) {
      await primeTorrentForStreaming(qbit, torrent, file, files)
    }
    let fileExists = Boolean(isOrphanFile || playback?.fileExists)
    let fileSize = Math.max(0, Number(file?.size || playback?.diskSize || orphanFileStat?.size || 0))
    let readableBytes = isOrphanFile ? fileSize : Number(playback.readableBytes || 0)
    let isComplete = isOrphanFile || Number(file?.progress || torrent.progress || 0) >= 0.999
    let maxReadable = isComplete ? fileSize : Math.max(0, Math.min(fileSize, readableBytes))
    let pieceRangeContext = null

    const applyRefreshedPlayback = (refreshed) => {
      if (!refreshed?.torrent || !refreshed?.file) return false
      torrent = refreshed.torrent
      files = Array.isArray(refreshed.files) ? refreshed.files : files
      file = refreshed.file
      resolvedFilePath = refreshed.resolvedFilePath || ''
      fileExists = Boolean(refreshed.fileExists && resolvedFilePath)
      fileSize = Math.max(0, Number(refreshed.file?.size || refreshed.diskSize || fileSize))
      readableBytes = Number(refreshed.readableBytes || 0)
      isComplete = Number(refreshed.file?.progress || refreshed.torrent.progress || 0) >= 0.999
      maxReadable = isComplete ? fileSize : Math.max(0, Math.min(fileSize, readableBytes))
      pieceRangeContext = null
      return true
    }

    const waitForFileState = async (predicate) => {
      if (isOrphanFile) return false
      const waitUntil = Date.now() + STREAM_RANGE_WAIT_TIMEOUT_MS
      while (Date.now() < waitUntil) {
        await sleep(STREAM_RANGE_WAIT_INTERVAL_MS)
        const refreshed = await loadTorrentPlaybackState(qbit, torrentHash, file?.name || p, req.config.additionalStorageRoots)
        if (!applyRefreshedPlayback(refreshed)) {
          if (!refreshed?.torrent) break
          continue
        }
        if (predicate()) return true
      }
      return false
    }

    const getRequestedPieceWindowEnd = async (startByte) => {
      if (isOrphanFile || isComplete) return fileSize - 1
      if (!Number.isFinite(startByte) || startByte < 0 || startByte >= fileSize) return -1
      if (startByte < maxReadable) return maxReadable - 1

      const filePieceRange = Array.isArray(file?.piece_range) ? file.piece_range : null
      if (!filePieceRange || filePieceRange.length < 2) return -1

      const filePieceStart = Number(filePieceRange[0])
      const filePieceEnd = Number(filePieceRange[1])
      if (!Number.isFinite(filePieceStart) || !Number.isFinite(filePieceEnd)) return -1

      let pieceSize = Number(pieceRangeContext?.pieceSize || 0)
      let pieceStates = Array.isArray(pieceRangeContext?.pieceStates) ? pieceRangeContext.pieceStates : null
      if (!pieceSize || !pieceStates) {
        try {
          const [properties, states] = await Promise.all([
            qbit.properties(torrentHash),
            qbit.pieceStates(torrentHash)
          ])
          pieceSize = Math.max(0, Number(properties?.piece_size || 0))
          pieceStates = Array.isArray(states) ? states.map(value => Number(value)) : null
          pieceRangeContext = { pieceSize, pieceStates }
        } catch (_) {
          pieceRangeContext = { pieceSize: 0, pieceStates: null }
          return -1
        }
      }
      if (!pieceSize || !Array.isArray(pieceStates) || pieceStates.length === 0) return -1

      let fileOffset = 0
      const activeFileIndex = Number.isInteger(file?.index) ? file.index : null
      const targetPathKey = normalizeTorrentPath(file?.name || p)
      for (const entry of Array.isArray(files) ? files : []) {
        const entryIndex = Number.isInteger(entry?.index) ? entry.index : null
        const entryPathKey = normalizeTorrentPath(entry?.name || '')
        if ((activeFileIndex !== null && entryIndex === activeFileIndex) || (activeFileIndex === null && entryPathKey === targetPathKey)) {
          break
        }
        fileOffset += Math.max(0, Number(entry?.size || 0))
      }

      const requestedStartInTorrent = fileOffset + startByte
      const requestedStartPiece = Math.floor(requestedStartInTorrent / pieceSize)
      if (requestedStartPiece < filePieceStart || requestedStartPiece > filePieceEnd) return -1
      if (Number(pieceStates[requestedStartPiece]) !== 2) return -1

      let lastDownloadedPiece = requestedStartPiece
      while (lastDownloadedPiece + 1 <= filePieceEnd && Number(pieceStates[lastDownloadedPiece + 1]) === 2) {
        lastDownloadedPiece += 1
      }

      const fileEndInTorrent = fileOffset + Math.max(0, fileSize - 1)
      const lastDownloadedByteInTorrent = Math.min(fileEndInTorrent, ((lastDownloadedPiece + 1) * pieceSize) - 1)
      return Math.max(startByte, lastDownloadedByteInTorrent - fileOffset)
    }

    let seekPriorityRequested = false
    const waitForRequestedRange = async (startByte) => {
      let availableRangeEnd = await getRequestedPieceWindowEnd(startByte)
      if (availableRangeEnd >= startByte) return availableRangeEnd
      if (isOrphanFile) return -1

      // When seeking to an unavailable range, ensure qBit stays in sequential
      // mode so pieces near the seek point are prioritized.
      if (!seekPriorityRequested && torrentHash) {
        seekPriorityRequested = true
        if (torrent?.seq_dl !== true) {
          try {
            await qbit.toggleSequentialDownload(torrentHash)
            torrent = { ...torrent, seq_dl: true }
            console.log(`[file-route] enabled sequential download for seek at byte ${startByte}`)
          } catch (_) {}
        }
      }

      const waitUntil = Date.now() + STREAM_RANGE_WAIT_TIMEOUT_MS
      while (Date.now() < waitUntil) {
        await sleep(STREAM_RANGE_WAIT_INTERVAL_MS)
        const refreshed = await loadTorrentPlaybackState(qbit, torrentHash, file?.name || p, req.config.additionalStorageRoots)
        if (!applyRefreshedPlayback(refreshed)) {
          if (!refreshed?.torrent) break
          continue
        }
        availableRangeEnd = await getRequestedPieceWindowEnd(startByte)
        if (availableRangeEnd >= startByte) return availableRangeEnd
      }

      return -1
    }

    if ((!isOrphanFile && !fileExists) || !resolvedFilePath) {
      const becameAvailable = await waitForFileState(() => Boolean(fileExists && resolvedFilePath))
      if (!becameAvailable) {
        console.warn('[file-route] file not found on disk')
        return res.status(425).json({
          error: 'Buffering torrent metadata',
          progress: Number(file?.progress || torrent.progress || 0)
        })
      }
    }

    const ext = path.extname(resolvedFilePath).toLowerCase()
    const mime = { '.mp4': 'video/mp4', '.mkv': 'video/x-matroska', '.avi': 'video/x-msvideo', '.wmv': 'video/x-ms-wmv', '.ts': 'video/mp2t', '.m4v': 'video/x-m4v' }
    const contentType = mime[ext] || 'application/octet-stream'

    if (!isComplete && readableBytes <= 0) {
      const hasReadableBytes = await waitForFileState(() => Boolean(fileExists && resolvedFilePath && (isComplete || readableBytes > 0)))
      if (!hasReadableBytes) {
        return res.status(425).json({
          error: 'Download started — waiting for initial buffer',
          progress: Number(file?.progress || torrent.progress || 0)
        })
      }
    }

    const range = req.headers.range
    res.setHeader('Accept-Ranges', 'bytes')
    res.setHeader('Content-Type', contentType)
    res.setHeader('Cache-Control', 'no-store')
    res.setHeader('Connection', 'keep-alive')
    res.setHeader('X-PVTKRRX-Progress', String(Math.round(Number(file?.progress || torrent.progress || 0) * 100)))

    if (range) {
      const [startStr, endStr] = range.replace(/bytes=/, '').split('-')
      let start = parseInt(startStr, 10)
      let requestedEnd = endStr ? parseInt(endStr, 10) : fileSize - 1

      // Support suffix-byte ranges: "bytes=-500000"
      if (!Number.isFinite(start) && Number.isFinite(requestedEnd) && requestedEnd > 0) {
        const suffixLen = requestedEnd
        start = Math.max(0, fileSize - suffixLen)
        requestedEnd = fileSize - 1
      }

      if (!Number.isFinite(start) || start < 0 || start >= fileSize) {
        res.setHeader('Content-Range', `bytes */${fileSize}`)
        res.setHeader('Retry-After', '2')
        return res.sendStatus(416)
      }

      let availableRangeEnd = isComplete ? (fileSize - 1) : await waitForRequestedRange(start)
      if (availableRangeEnd < start) {
        // Return a retryable status for progressive playback instead of a hard 416.
        res.setHeader('Content-Range', `bytes */${fileSize}`)
        res.setHeader('Retry-After', '2')
        return res.status(503).json({
          error: 'Requested byte range not available yet',
          progress: Number(file?.progress || torrent.progress || 0),
          retryAfterSeconds: 2
        })
      }

      const end = Math.min(requestedEnd, availableRangeEnd)
      if (end < start) {
        res.setHeader('Content-Range', `bytes */${fileSize}`)
        res.setHeader('Retry-After', '2')
        return res.sendStatus(416)
      }

      if (isComplete && fileSize > 0 && !isOrphanFile) {
        const watchedRatio = (end + 1) / fileSize
        if (watchedRatio >= WATCHED_DELETE_THRESHOLD) {
          scheduleWatchedCleanup(req.config, torrentHash, `range-${Math.round(watchedRatio * 100)}pct`)
        }
      }

      res.status(206)
      res.setHeader('Content-Range', `bytes ${start}-${end}/${fileSize}`)
      res.setHeader('Content-Length', String(end - start + 1))
      fs.createReadStream(resolvedFilePath, { start, end }).pipe(res)
    } else {
      if (isComplete) {
        res.status(200)
        res.setHeader('Content-Length', String(fileSize))
        fs.createReadStream(resolvedFilePath).pipe(res)
      } else {
        if (maxReadable <= 0) {
          const hasReadableBytes = await waitForFileState(() => Boolean(fileExists && resolvedFilePath && (isComplete || readableBytes > 0)))
          if (!hasReadableBytes) {
            return res.status(425).json({
              error: 'Download started — waiting for initial buffer',
              progress: Number(file?.progress || torrent.progress || 0)
            })
          }
        }
        const end = maxReadable - 1
        res.status(206)
        res.setHeader('Content-Range', `bytes 0-${end}/${fileSize}`)
        res.setHeader('Content-Length', String(maxReadable))
        fs.createReadStream(resolvedFilePath, { start: 0, end }).pipe(res)
      }
    }
  } catch (err) {
    console.error('[file] Error:', redactSensitiveText(err.message))
    if (!res.headersSent) res.status(500).json({ error: 'File serve failed' })
  }
})

// ─── Playback endpoint — Comet pattern ──────────────────────
app.get('/:config/playback/:info', withConfig, requireConfigSubscription, maybeLanPairRedirect('playback'), async (req, res) => {
  try {
    if (IS_HOSTED_RELAY_RUNTIME && req.params.config !== 'local') {
      return res.status(403).json({
        error: 'Built-in playback buffering is disabled on hosted runtime',
        detail: 'Use File Server URL or LAN Pair local relay for playback'
      })
    }

    let info = null
    try {
      info = decodePlaybackStateToken(req.params.info)
    } catch (_) {
      return res.status(400).json({ error: 'Invalid playback token' })
    }
    const targetPathHint = String(info.p || '')
    const trackerHost = extractTrackerHost(info.l)
    let trackedHash = String(info.h || extractInfoHashFromLink(info.l) || '').toLowerCase()
    console.log(`[playback-route] hash=${trackedHash.slice(0, 8)} hasLink=${Boolean(info.l)}`)
    const qbit = new QBitClient(req.config.qbitUrl, req.config.qbitUsername, req.config.qbitPassword)
    const waitDeadline = Date.now() + STREAM_WAIT_TIMEOUT_MS
    let primedTorrent = false
    let primedFile = false
    let lastProgress = 0
    let hasTorrent = false
    let knownHashesBeforeAdd = null
    let maxAvailability = 0
    let maxSeedersSeen = 0
    let maxPeersSeen = 0
    let trackerPayload = null
    let trackerInspection = null
    const baseUrl = getPlaybackBaseUrl(req)
    const builtinFileUrlPrefix = `${baseUrl}/${req.params.config}/file/`

    const tryRedirectToFileRoute = (state, reason) => {
      if (!state?.torrent || !state?.file?.name) return false

      const videoProgress = Number(state.file?.progress || 0)
      const complete = isCompletedTorrent(state.torrent, videoProgress)
      const fileUrl = buildPlaybackFileUrl(
        req.config,
        req.params.config,
        baseUrl,
        state.torrent.hash,
        state.torrent,
        state.file.name,
        {
          multipleFiles: Array.isArray(state.files) && state.files.length > 1,
          currentFilePath: state.fileExists ? state.resolvedFilePath : '',
          requireCurrentPathProof: !complete
        }
      )
      if (!fileUrl) return false

      const canBufferViaBuiltinFileRoute = fileUrl.startsWith(builtinFileUrlPrefix)
      if (!complete && !canBufferViaBuiltinFileRoute) return false

      console.log(
        `[playback-route] ${reason} -> redirect file${complete ? '' : ' (buffering via /file)'}`
      )
      res.redirect(302, fileUrl)
      return true
    }

    if (!trackedHash && info.l && !isMagnetLink(info.l)) {
      try {
        trackerPayload = await fetchTorrentPayload(info.l)
        trackerInspection = inspectTorrentPayload(trackerPayload.bytes)
        if (trackerInspection.legacyAviOnly) {
          return res.status(422).json({
            error: 'Legacy AVI/XviD source detected. Pick an MKV or MP4 source instead.'
          })
        }
        if (trackerInspection.infoHash) {
          trackedHash = String(trackerInspection.infoHash || '').toLowerCase()
        }
      } catch (err) {
        console.warn(`[playback-route] tracker payload inspect failed: ${redactSensitiveText(err.message)}`)
      }
    }

    // If we can identify the torrent hash, check whether it's already playable.
    if (trackedHash) {
      const existing = await loadTorrentPlaybackState(qbit, trackedHash, targetPathHint, req.config.additionalStorageRoots)
      if (existing?.torrent) {
        if (!primedTorrent || (!primedFile && existing.file)) {
          await primeTorrentForStreaming(qbit, existing.torrent, existing.file, existing.files)
          primedTorrent = true
          if (existing.file) primedFile = true
        }
        if (!existing.file && existing.packedArchive && existing.archiveReady) {
          return res.status(422).json({
            error: 'Packed archive release detected (RAR). Reopen the stream list and use the ready RAR stream.'
          })
        }
        if (!existing.file && existing.packedArchive) {
          return res.status(422).json({
            error: 'Packed archive release detected (RAR). This Stremio path cannot start a partial multi-volume archive while it is still downloading. Wait until every RAR volume is complete, then reopen the stream list and use the ready RAR stream.'
          })
        }
        if (!existing.file && !existing.packedArchive && Number(existing.torrent.progress || 0) >= 0.999) {
          return res.status(422).json({
            error: 'Torrent completed but no playable video file was detected.'
          })
        }
        hasTorrent = true
        const existingComplete = Number(existing.torrent.progress || 0) >= 0.999 || Number(existing.file?.progress || 0) >= 0.999
        if (tryRedirectToFileRoute(existing, existing.ready || existingComplete
          ? 'existing torrent ready'
          : 'existing torrent buffering')) {
          return
        }
        if (existingComplete && existing.file?.name) {
          return res.status(412).json({
            error: 'Hosted playback requires File Server URL or LAN Pair relay'
          })
        }
        lastProgress = Number(existing.file?.progress || existing.torrent.progress || 0)
        maxAvailability = Math.max(maxAvailability, Number(existing.torrent?.availability || 0))
        maxSeedersSeen = Math.max(maxSeedersSeen, Number(existing.torrent?.num_seeds || 0))
        maxPeersSeen = Math.max(maxPeersSeen, Number(existing.torrent?.num_leechs || 0))
      }
    }

    // If hash is missing, snapshot current torrent hashes so we can detect which torrent was just added.
    if (!trackedHash && info.l) {
      try {
        const current = await qbit.torrents('all')
        knownHashesBeforeAdd = new Set((current || []).map(t => String(t.hash || '').toLowerCase()))
      } catch (err) {
        console.warn('[playback-route] Hash snapshot failed — torrent detection may be unreliable:', redactSensitiveText(err.message))
      }
    }

    if (!hasTorrent && !info.l) {
      return res.status(404).json({ error: 'Torrent not found and no tracker link provided' })
    }

    // Not ready yet — add to qBit queue if we have a tracker/magnet link.
    if (info.l && !hasTorrent) {
      try {
        if (isMagnetLink(info.l)) {
          await qbit.add(info.l, {
            sequentialDownload: true,
            firstLastPiecePrio: STREAM_PRIORITIZE_LAST_PIECES
          })
        } else {
          if (!trackerPayload) {
            trackerPayload = await fetchTorrentPayload(info.l)
          }
          if (!trackerInspection) {
            trackerInspection = inspectTorrentPayload(trackerPayload.bytes)
            if (trackerInspection.legacyAviOnly) {
              return res.status(422).json({
                error: 'Legacy AVI/XviD source detected. Pick an MKV or MP4 source instead.'
              })
            }
            if (!trackedHash && trackerInspection.infoHash) {
              trackedHash = String(trackerInspection.infoHash || '').toLowerCase()
            }
          }
          await qbit.addTorrentFile(trackerPayload.bytes, trackerPayload.fileName, {
            sequentialDownload: true,
            firstLastPiecePrio: STREAM_PRIORITIZE_LAST_PIECES
          })
          if (trackerInspection.packedOnly) {
            return res.status(422).json({
              error: 'Packed archive release detected (RAR). Download queued, but this Stremio path cannot start a partial multi-volume archive while it is still downloading. Wait until every RAR volume is complete, then reopen the stream list and use the ready RAR stream.'
            })
          }
        }
      } catch (addErr) {
        // qBit may reject duplicate/stale URLs; continue probing torrent list.
        console.warn(`[playback-route] add rejected: ${redactSensitiveText(addErr.message)}`)
      }
    }

    // Keep the request open only until we can identify the target file or confirm true readiness.
    // For local/self-hosted built-in playback, redirect into /file as soon as the file path is known
    // so the shared file route can hold the HTTP connection open while bytes continue arriving.
    while (Date.now() < waitDeadline) {
      await sleep(STREAM_WAIT_INTERVAL_MS)

      if (!trackedHash) {
        const allTorrents = await qbit.torrents('all')
        const candidate = pickLikelyNewTorrent(allTorrents, knownHashesBeforeAdd, trackerHost)
        if (candidate?.hash) {
          trackedHash = String(candidate.hash).toLowerCase()
          lastProgress = Number(candidate.progress || 0)
        } else {
          continue
        }
      }

      const state = await loadTorrentPlaybackState(qbit, trackedHash, targetPathHint, req.config.additionalStorageRoots)
      if (!state?.torrent) {
        trackedHash = ''
        continue
      }
      if (!primedTorrent || (!primedFile && state.file)) {
        await primeTorrentForStreaming(qbit, state.torrent, state.file, state.files)
        primedTorrent = true
        if (state.file) primedFile = true
      }
      if (!state.file) {
        if (state.packedArchive && state.archiveReady) {
          return res.status(422).json({
            error: 'Packed archive release detected (RAR). Reopen the stream list and use the ready RAR stream.'
          })
        }
        if (state.packedArchive) {
          return res.status(422).json({
            error: 'Packed archive release detected (RAR). This Stremio path cannot start a partial multi-volume archive while it is still downloading. Wait until every RAR volume is complete, then reopen the stream list and use the ready RAR stream.'
          })
        }
        if (!state.packedArchive && Number(state.torrent.progress || 0) >= 0.999) {
          return res.status(422).json({
            error: 'Torrent completed but no playable video file was detected.'
          })
        }
        lastProgress = Number(state.torrent.progress || 0)
        maxAvailability = Math.max(maxAvailability, Number(state.torrent?.availability || 0))
        maxSeedersSeen = Math.max(maxSeedersSeen, Number(state.torrent?.num_seeds || 0))
        maxPeersSeen = Math.max(maxPeersSeen, Number(state.torrent?.num_leechs || 0))
        continue
      }
      hasTorrent = true

      lastProgress = Number(state.file?.progress || state.torrent.progress || 0)
      maxAvailability = Math.max(maxAvailability, Number(state.torrent?.availability || 0))
      maxSeedersSeen = Math.max(maxSeedersSeen, Number(state.torrent?.num_seeds || 0))
      maxPeersSeen = Math.max(maxPeersSeen, Number(state.torrent?.num_leechs || 0))
      const stateComplete = Number(state.torrent.progress || 0) >= 0.999 || Number(state.file?.progress || 0) >= 0.999
      if (tryRedirectToFileRoute(state, state.ready || stateComplete
        ? 'progressive-ready'
        : 'progressive-buffering')) {
        return
      }
      if (stateComplete && state.file?.name) {
        return res.status(412).json({
          error: 'Hosted playback requires File Server URL or LAN Pair relay'
        })
      }
    }

    // Playback loop timed out — try one final redirect to the /file route
    // instead of hard 503. The /file route's range-wait mechanism will hold
    // the HTTP connection while bytes arrive, keeping Stremio on the player
    // page instead of crashing back to source selection.
    if (trackedHash) {
      const finalState = await loadTorrentPlaybackState(qbit, trackedHash, targetPathHint, req.config.additionalStorageRoots)
      if (tryRedirectToFileRoute(finalState, 'timeout-fallback')) {
        return
      }
    }

    // Truly no file available — hard 503.
    const stalledNoPieces = lastProgress <= 0.001 && maxAvailability < 0.01
    console.warn(
      `[playback-route] timeout waiting for buffer hash=${trackedHash.slice(0, 8)} ` +
      `progress=${Math.round(lastProgress * 100)}% availability=${maxAvailability.toFixed(3)} ` +
      `seeders=${maxSeedersSeen} peers=${maxPeersSeen}`
    )
    res.status(503).json({
      error: stalledNoPieces
        ? 'Source stalled - no available pieces from peers. Pick another source.'
        : 'Download queued - still buffering start of file',
      progress: lastProgress,
      availability: Number(maxAvailability.toFixed(3)),
      seedersSeen: maxSeedersSeen,
      peersSeen: maxPeersSeen,
      retryAfterSeconds: 4
    })
  } catch (err) {
    console.error('[playback-route] Error:', redactSensitiveText(err.message))
    res.status(500).json({ error: 'Playback failed' })
  }
})

// ─── Local dev server ───────────────────────────────────────
function startLocalServers(options = {}) {
  const exitOnHttpError = options.exitOnHttpError !== false
  const enableLanAlias = options.enableLanAlias !== false
  const ensureLanAccessOnBoot = options.ensureLanAccessOnBoot !== false
  const logger = createRedactingLogger(options.logger || console)
  const port = Number.isFinite(options.port) ? options.port : parseInt(process.env.PORT || '7000', 10)
  const httpsPort = Number.isFinite(options.httpsPort) ? options.httpsPort : parseInt(process.env.HTTPS_PORT || '7001', 10)
  const mdnsHost = getMdnsHost()
  let lanAlias = null
  const state = {
    httpServer: null,
    httpsServer: null,
    httpsReady: Promise.resolve(null),
    port,
    httpsPort,
    lanAlias: null
  }

  logger.log(`[boot] starting local runtime port=${port} httpsPort=${httpsPort}`)

  if (ensureLanAccessOnBoot) {
    ensureBootLanAccess(logger).catch(err => {
      logger.warn('[boot] LAN access setup failed:', err.message)
    })
  }

  const bootConfig = loadLocalConfigFile()
  if (bootConfig) {
    const warmTimer = setTimeout(() => {
      repairLocalProwlarrConfig(bootConfig, logger, 'server-boot')
        .then((repairedConfig) => {
          scheduleSportsCatalogPrewarm(repairedConfig, logger, 'server-boot', {
            defaultEnabled: SELF_HOST_SERVER_MODE
          }).catch(err => {
            logger.warn('[boot] Sports prewarm failed:', err.message)
          })
          return scheduleLocalProviderWarmup(repairedConfig, logger, 'server-boot')
        })
        .catch(err => {
          logger.warn('[boot] Provider warmup failed:', err.message)
        })
    }, 900)
    if (typeof warmTimer.unref === 'function') warmTimer.unref()
  }

  // Legacy sportsCacheAutofill (15-min TheSportsDB scheduled job) was removed
  // on 2026-04-22. SportsMeta owns artwork now, so no recurring PVTKRRX job
  // hits TheSportsDB from this runtime anymore.

  // HTTP
  const httpServer = http.createServer(app)
  state.httpServer = httpServer
  httpServer.listen(port, () => {
    logger.log(`PVTKRRX HTTP  → http://localhost:${port}`)
    logger.log(`Configure:      http://localhost:${port}/configure`)
    if (SELF_HOST_SERVER_MODE) {
      const publicBase = String(process.env.PVTKRRX_PUBLIC_BASE_URL || '').replace(/\/+$/, '')
      const base = publicBase || `http://localhost:${port}`
      const adminToken = serverAdminState.token
      // Write directly to stdout — bypasses the redacting logger so the token
      // and URL are never masked in the startup banner.
      process.stdout.write(`\n─────────────────────────────────────────────────────────\n`)
      process.stdout.write(`STREMIO INSTALL URL\n`)
      process.stdout.write(`  ${base}/selfhost/manifest.json?mode=hosted\n`)
      if (adminToken) {
        process.stdout.write(`CONFIGURE URL (pre-authenticated)\n`)
        process.stdout.write(`  ${base}/configure#serverAdminToken=${encodeURIComponent(adminToken)}\n`)
      }
      process.stdout.write(`─────────────────────────────────────────────────────────\n\n`)
    }
    if (enableLanAlias && !lanAlias) {
      lanAlias = startLanAlias({ hostname: mdnsHost, port, logger })
      state.lanAlias = lanAlias
      if (lanAlias?.enabled) {
        logger.log(`PVTKRRX mDNS  → http://${lanAlias.hostname}:${port}/local/manifest.json?mode=local`)
      } else {
        logger.warn(`PVTKRRX mDNS disabled (${lanAlias?.reason || 'unknown'})`)
      }
    }
  })
  httpServer.on('error', (err) => {
    logger.error('HTTP server failed to start:', err.message)
    if (exitOnHttpError) process.exit(1)
  })
  httpServer.on('close', () => {
    try {
      if (lanAlias && typeof lanAlias.stop === 'function') lanAlias.stop()
    } catch (err) {
      logger.warn('[server] mDNS alias cleanup failed:', err.message)
    }
  })

  // HTTPS (self-signed — must be trusted in OS/browser first)
  state.httpsReady = (async () => {
    try {
      const attrs = [{ name: 'commonName', value: 'localhost' }]
      const pems = await selfsigned.generate(attrs, {
        days: 365,
        algorithm: 'sha256',
        keySize: 2048,
        extensions: [
          { name: 'basicConstraints', cA: false, critical: true },
          { name: 'keyUsage', digitalSignature: true, keyEncipherment: true, critical: true },
          { name: 'extKeyUsage', serverAuth: true, clientAuth: true },
          {
            name: 'subjectAltName',
            altNames: [
              { type: 2, value: 'localhost' },
              { type: 7, ip: '127.0.0.1' },
              { type: 7, ip: '::1' }
            ]
          }
        ]
      })
      const httpsServer = https.createServer({ key: pems.private, cert: pems.cert }, app)
      state.httpsServer = httpsServer
      await new Promise((resolve, reject) => {
        const onListening = () => {
          httpsServer.off('error', onError)
          resolve()
        }
        const onError = (err) => {
          httpsServer.off('listening', onListening)
          reject(err)
        }
        httpsServer.once('listening', onListening)
        httpsServer.once('error', onError)
        httpsServer.listen(httpsPort)
      })
      logger.log(`PVTKRRX HTTPS → https://localhost:${httpsPort} (self-signed — trust cert in browser first)`)
      httpsServer.on('error', (err) => {
        logger.warn(`HTTPS server error on port ${httpsPort}:`, err.message)
      })
      return httpsServer
    } catch (err) {
      logger.warn('HTTPS server skipped:', err.message)
      return null
    }
  })()

  return state
}

if (require.main === module) {
  startLocalServers({ exitOnHttpError: true, logger: console })
}

module.exports = app
module.exports.startLocalServers = startLocalServers
