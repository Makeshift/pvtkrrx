const fs = require('fs')
const os = require('os')
const path = require('path')
const crypto = require('crypto')
const net = require('node:net')
const { execFileSync, spawnSync } = require('child_process')
const readline = require('node:readline/promises')
const { stdin: input, stdout: output } = require('node:process')

const { loadSecureJsonFile, saveSecureJsonFile } = require('../src/utils/secureJsonFile')
const { ensureServerAdminToken } = require('../src/utils/serverAdminToken')
const { discoverProwlarrConfig, discoverQbitConfig, ensureProwlarrQbitDownloadClient } = require('../src/utils/provision')
const { installSystemdService } = require('./install-systemd-service')

const SELFHOST_BOOTSTRAP_ACTIVE_ENV = 'PVTKRRX_SELFHOST_BOOTSTRAP_ACTIVE'

function parseDotEnvFile(filePath) {
  if (!fs.existsSync(filePath)) return {}
  const out = {}
  const lines = fs.readFileSync(filePath, 'utf8').split(/\r?\n/)
  for (const rawLine of lines) {
    const line = rawLine.trim()
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
    out[key] = value
  }
  return out
}

function formatEnvValue(value) {
  const text = String(value ?? '')
  if (/[\s#"'`]/.test(text)) {
    return JSON.stringify(text)
  }
  return text
}

function updateDotEnvFile(filePath, updates) {
  const existingLines = fs.existsSync(filePath)
    ? fs.readFileSync(filePath, 'utf8').split(/\r?\n/)
    : []
  const pending = new Map(
    Object.entries(updates).map(([key, value]) => [String(key), String(value ?? '')])
  )

  const nextLines = existingLines.map((line) => {
    const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=/)
    if (!match) return line
    const key = match[1]
    if (!pending.has(key)) return line
    const value = pending.get(key)
    pending.delete(key)
    return `${key}=${formatEnvValue(value)}`
  })

  for (const [key, value] of pending.entries()) {
    nextLines.push(`${key}=${formatEnvValue(value)}`)
  }

  const body = `${nextLines.filter((line, index, arr) => index < arr.length - 1 || line !== '').join('\n')}\n`
  fs.writeFileSync(filePath, body, 'utf8')
}

function randomSecret(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url')
}

function normalizeBaseUrl(input) {
  return String(input || '').trim().replace(/\/+$/, '')
}

function isTryCloudflareUrl(input) {
  return /^https:\/\/[a-z0-9-]+\.trycloudflare\.com(?:\/|$)/i.test(normalizeBaseUrl(input))
}

function resolveSelfHostHttpsMode(existingHttpsMode, existingPublicBaseUrl) {
  const mode = normalizeSelfHostHttpsMode(existingHttpsMode || '')
  const publicBaseUrl = normalizeBaseUrl(existingPublicBaseUrl || '')
  const canReusePublicBaseUrl = Boolean(publicBaseUrl) && !isTryCloudflareUrl(publicBaseUrl)

  if (mode === 'skip') return 'skip'
  if (mode === 'freedns') return 'freedns'
  if (mode === 'domain') return canReusePublicBaseUrl ? 'domain' : 'freedns'
  if (isTryCloudflareUrl(publicBaseUrl)) return 'freedns'
  return canReusePublicBaseUrl ? 'domain' : 'freedns'
}

function normalizePortNumber(input, fallback = 0) {
  const parsed = Number.parseInt(String(input || '').trim(), 10)
  if (Number.isFinite(parsed) && parsed >= 1 && parsed <= 65535) return parsed
  return Number.isFinite(fallback) && fallback >= 1 && fallback <= 65535 ? fallback : 0
}

function normalizeSelfHostHttpsMode(input) {
  const text = String(input || '').trim().toLowerCase()
  if (!text) return ''
  if (['freedns', 'free-dns', 'afraid', 'afraid.org'].includes(text)) return 'freedns'
  if (['cloudflare', 'cloudflare-tunnel', 'tunnel', 'cf'].includes(text)) return 'freedns'
  if (['domain', 'custom-domain', 'own-domain', 'custom', 'https-domain'].includes(text)) return 'domain'
  if (['skip', 'later', 'manual', 'none', 'off'].includes(text)) return 'skip'
  return ''
}

function describeSelfHostHttpsMode(mode) {
  switch (normalizeSelfHostHttpsMode(mode)) {
    case 'freedns':
      return 'FreeDNS + local Caddy'
    case 'domain':
      return 'custom domain + local Caddy'
    case 'skip':
      return 'skip for now'
    default:
      return 'unknown'
  }
}

function parseHttpUrl(input, options = {}) {
  const {
    allowEmpty = false,
    requireHttps = false,
    allowLoopbackHttp = false
  } = options
  const text = normalizeBaseUrl(input)
  if (!text) {
    if (allowEmpty) return null
    throw new Error('Value is required')
  }

  let parsed
  try {
    parsed = new URL(text)
  } catch (_) {
    throw new Error('Enter a valid URL')
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('URL must start with http:// or https://')
  }

  const hostname = String(parsed.hostname || '').trim().toLowerCase()
  if (
    requireHttps &&
    parsed.protocol !== 'https:' &&
    !(allowLoopbackHttp && hostname === '127.0.0.1')
  ) {
    throw new Error('This value must use https://')
  }

  return parsed
}

function normalizeOrigin(input) {
  try {
    const parsed = parseHttpUrl(input, { allowEmpty: true, allowLoopbackHttp: true })
    return parsed ? normalizeBaseUrl(parsed.origin) : ''
  } catch (_) {
    return ''
  }
}

function normalizeOriginList(input, fallback = '') {
  const collect = (value) => String(value || '')
    .split(',')
    .map((part) => {
      try {
        return normalizeOrigin(part)
      } catch (_) {
        return ''
      }
    })
    .filter(Boolean)

  const items = collect(input)
  if (items.length > 0) return [...new Set(items)].join(', ')

  const fallbackItems = collect(fallback)
  return [...new Set(fallbackItems)].join(', ')
}

function buildDefaultAllowedOrigins(publicBaseUrl, httpPort, httpsPort, existingValue = '') {
  const preferred = normalizeOriginList(existingValue)
  if (preferred) return preferred

  const next = []
  const publicOrigin = normalizeOrigin(publicBaseUrl)
  if (publicOrigin) next.push(publicOrigin)
  next.push(`http://localhost:${httpPort}`)
  next.push(`http://127.0.0.1:${httpPort}`)
  next.push(`https://localhost:${httpsPort}`)
  next.push(`https://127.0.0.1:${httpsPort}`)
  return [...new Set(next)].join(', ')
}

function buildLoopbackHttpUrl(port, fallback = 'http://127.0.0.1:8080') {
  const normalizedPort = normalizePortNumber(port, 0)
  if (normalizedPort > 0) {
    return `http://127.0.0.1:${normalizedPort}`
  }
  return String(fallback || '').trim() || 'http://127.0.0.1:8080'
}

async function promptValue(rl, label, defaultValue = '', options = {}) {
  const suffix = defaultValue ? ` [${defaultValue}]` : ''
  const raw = await rl.question(`${label}${suffix}: `)
  const text = String(raw || '').trim()
  if (!text) return String(defaultValue || '').trim()
  if (options.allowEmpty === true && text === '-') return ''
  return text
}

async function promptBoolean(rl, label, defaultValue = true) {
  const suffix = defaultValue ? ' [Y/n]' : ' [y/N]'
  const raw = await rl.question(`${label}${suffix}: `)
  const text = String(raw || '').trim().toLowerCase()
  if (!text) return defaultValue
  if (['y', 'yes', 'true', '1'].includes(text)) return true
  if (['n', 'no', 'false', '0'].includes(text)) return false
  return defaultValue
}

async function promptHttpUrl(rl, label, defaultValue = '', options = {}) {
  while (true) {
    const value = await promptValue(rl, label, defaultValue, {
      allowEmpty: options.allowEmpty === true
    })
    try {
      const parsed = parseHttpUrl(value, options)
      return parsed ? normalizeBaseUrl(parsed.toString()) : ''
    } catch (error) {
      console.log(error.message)
    }
  }
}

function sanitizeHttpUrlDefault(value, fallback = '', options = {}) {
  try {
    const parsed = parseHttpUrl(value, {
      ...options,
      allowEmpty: true
    })
    return parsed ? normalizeBaseUrl(parsed.toString()) : String(fallback || '').trim()
  } catch (_) {
    return String(fallback || '').trim()
  }
}

async function promptInteger(rl, label, defaultValue, options = {}) {
  const min = Number.isFinite(options.min) ? options.min : 1
  const max = Number.isFinite(options.max) ? options.max : Number.MAX_SAFE_INTEGER
  while (true) {
    const raw = await promptValue(rl, label, String(defaultValue || ''))
    const value = Number.parseInt(String(raw || '').trim(), 10)
    if (!Number.isFinite(value) || value < min || value > max) {
      console.log(`Enter a whole number between ${min} and ${max}.`)
      continue
    }
    return value
  }
}

function commandExists(command) {
  const probe = process.platform === 'win32'
    ? spawnSync('where', [command], { stdio: 'ignore' })
    : spawnSync('which', [command], { stdio: 'ignore' })
  return probe.status === 0
}

function resolveCommandPath(command) {
  const probe = process.platform === 'win32'
    ? spawnSync('where', [command], { encoding: 'utf8' })
    : spawnSync('which', [command], { encoding: 'utf8' })
  if (probe.status !== 0) return ''
  return String(probe.stdout || '')
    .split(/\r?\n/)
    .map(line => line.trim())
    .find(Boolean) || ''
}

function runAsRoot(command, args, options = {}) {
  const execOptions = {
    stdio: options.stdio || 'inherit',
    cwd: options.cwd || process.cwd()
  }

  if (typeof process.getuid === 'function' && process.getuid() === 0) {
    execFileSync(command, args, execOptions)
    return
  }

  if (!commandExists('sudo')) {
    throw new Error(`Root access is required to run ${command}. Re-run this command with sudo.`)
  }

  execFileSync('sudo', [command, ...args], execOptions)
}

function normalizeArchForCaddy() {
  switch (process.arch) {
    case 'x64':
      return 'amd64'
    case 'arm64':
      return 'arm64'
    default:
      throw new Error(`Unsupported architecture for Caddy: ${process.arch}`)
  }
}

/*
function _legacyInstallCloudflaredBinary(repoRoot) {
  const existingBinary = resolveCommandPath('cloudflared')
  if (existingBinary) {
    return existingBinary
  }

  if (!commandExists('curl')) {
    throw new Error('curl is required to install cloudflared')
  }

  const arch = normalizeArchForCloudflared()
  const downloadUrl = `https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${arch}`
  const targetPath = '/usr/local/bin/cloudflared'

  console.log('Downloading cloudflared...')
  runAsRoot('mkdir', ['-p', '/usr/local/bin'], { cwd: repoRoot })
  runAsRoot('curl', ['-fsSL', downloadUrl, '-o', targetPath], { cwd: repoRoot })
  runAsRoot('chmod', ['0755', targetPath], { cwd: repoRoot })
  console.log('✓ cloudflared installed')

  return targetPath
}

async function _legacyEnsureCloudflaredTunnel(repoRoot, httpPort, existingPublicBaseUrl) {
  const configuredBase = normalizeBaseUrl(existingPublicBaseUrl || '')
  if (process.platform !== 'linux') {
    return {
      installed: false,
      publicBaseUrl: configuredBase,
      serviceName: '',
      unitPath: '',
      binaryPath: resolveCommandPath('cloudflared') || ''
    }
  }

  const binaryPath = _legacyInstallCloudflaredBinary(repoRoot)
  if (configuredBase && !isTryCloudflareUrl(configuredBase)) {
    return {
      installed: true,
      publicBaseUrl: configuredBase,
      serviceName: '',
      unitPath: '',
      binaryPath
    }
  }

  const serviceName = 'pvtkrrx-tunnel'
  const unitPath = `/etc/systemd/system/${serviceName}.service`
  const unitBody = `[Unit]
Description=PVTKRRX Cloudflare Tunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${binaryPath} tunnel --url http://localhost:${httpPort} --no-autoupdate
Restart=always
RestartSec=10
KillSignal=SIGINT
TimeoutStopSec=20

[Install]
WantedBy=multi-user.target
`

  const tempPath = path.join(os.tmpdir(), `${serviceName}.service`)
  fs.writeFileSync(tempPath, unitBody, 'utf8')
  const restartStartedAt = new Date().toISOString()
  try {
    runAsRoot('install', ['-m', '0644', tempPath, unitPath], { cwd: repoRoot })
    runAsRoot('systemctl', ['daemon-reload'], { cwd: repoRoot })
    runAsRoot('systemctl', ['enable', `${serviceName}.service`], { cwd: repoRoot })
    runAsRoot('systemctl', ['restart', `${serviceName}.service`], { cwd: repoRoot })
  } finally {
    try {
      fs.unlinkSync(tempPath)
    } catch (_) {}
  }

  console.log('Waiting for Cloudflare Tunnel URL...')
  let publicBaseUrl = ''
  for (let attempts = 0; attempts < 45; attempts += 1) {
    publicBaseUrl = readCloudflaredTunnelUrl(serviceName, restartStartedAt)
    if (publicBaseUrl) break
    await sleep(1000)
  }

  if (!publicBaseUrl) {
    throw new Error('Cloudflare Tunnel started, but the public URL was not found in the service logs')
  }

  console.log(`✓ Tunnel URL: ${publicBaseUrl}`)
  return {
    installed: true,
    publicBaseUrl,
    serviceName,
    unitPath,
    binaryPath
  }
}

*/

function isSystemdUnitActive(unitName) {
  if (process.platform !== 'linux' || !commandExists('systemctl')) return false
  const result = spawnSync('systemctl', ['is-active', '--quiet', unitName], { stdio: 'ignore' })
  return result.status === 0
}

function systemdUnitExists(unitName) {
  if (process.platform !== 'linux' || !commandExists('systemctl')) return false
  const result = spawnSync('systemctl', ['cat', unitName], { stdio: 'ignore' })
  return result.status === 0
}

function disableLegacyCloudflareTunnel(repoRoot) {
  const serviceName = 'pvtkrrx-tunnel.service'
  if (!systemdUnitExists(serviceName)) {
    return {
      disabled: false,
      message: ''
    }
  }

  try {
    runAsRoot('systemctl', ['disable', '--now', serviceName], { cwd: repoRoot })
    return {
      disabled: true,
      message: `Disabled legacy Cloudflare tunnel service: ${serviceName}`
    }
  } catch (error) {
    return {
      disabled: false,
      message: `Could not disable legacy Cloudflare tunnel service ${serviceName}: ${error.message}`
    }
  }
}

async function isLocalPortActive(port) {
  const candidate = normalizePortNumber(port, 0)
  if (!candidate) return false

  return new Promise((resolve) => {
    const socket = net.createConnection({ host: '127.0.0.1', port: candidate })
    let settled = false

    const finish = (value) => {
      if (settled) return
      settled = true
      socket.destroy()
      resolve(value)
    }

    socket.setTimeout(500)
    socket.once('connect', () => finish(true))
    socket.once('timeout', () => finish(false))
    socket.once('error', () => finish(false))
  })
}

async function resolveLatestCaddyTarballUrl() {
  const arch = normalizeArchForCaddy()
  const response = await fetch('https://api.github.com/repos/caddyserver/caddy/releases/latest', {
    headers: {
      'Accept': 'application/vnd.github+json',
      'User-Agent': 'pvtkrrx-selfhost-installer'
    }
  })

  if (!response.ok) {
    throw new Error(`Could not query the latest Caddy release (${response.status})`)
  }

  const payload = await response.json()
  const asset = Array.isArray(payload?.assets)
    ? payload.assets.find((entry) => typeof entry?.name === 'string' && entry.name.endsWith(`linux_${arch}.tar.gz`))
    : null

  if (!asset?.browser_download_url) {
    throw new Error(`Could not find a Linux ${arch} Caddy tarball in the latest release`)
  }

  return asset.browser_download_url
}

async function installCaddyBinary(repoRoot) {
  const existingBinary = resolveCommandPath('caddy')
  if (existingBinary) {
    return existingBinary
  }

  if (!commandExists('tar')) {
    throw new Error('tar is required to install Caddy')
  }

  const downloadUrl = await resolveLatestCaddyTarballUrl()
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pvtkrrx-caddy-'))
  const tarballPath = path.join(tempDir, 'caddy.tar.gz')
  const extractedPath = path.join(tempDir, 'caddy')
  const targetPath = '/usr/local/bin/caddy'

  try {
    console.log('Downloading Caddy...')
    const response = await fetch(downloadUrl, {
      headers: {
        'User-Agent': 'pvtkrrx-selfhost-installer'
      }
    })
    if (!response.ok) {
      throw new Error(`Could not download Caddy (${response.status})`)
    }

    const buffer = Buffer.from(await response.arrayBuffer())
    fs.writeFileSync(tarballPath, buffer)
    execFileSync('tar', ['-xzf', tarballPath, '-C', tempDir], { stdio: 'ignore' })
    runAsRoot('mkdir', ['-p', '/usr/local/bin'], { cwd: repoRoot })
    runAsRoot('install', ['-m', '0755', extractedPath, targetPath], { cwd: repoRoot })
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true })
  }

  console.log('✓ Caddy installed')
  return targetPath
}

function buildSelfHostCaddyConfig(hostname, upstreamPort) {
  return `${hostname} {
    encode zstd gzip
    reverse_proxy 127.0.0.1:${upstreamPort}
}
`
}

function buildSelfHostCaddyService(binaryPath, configPath) {
  return `[Unit]
Description=PVTKRRX self-host Caddy reverse proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=${binaryPath} run --environ --config ${configPath}
ExecReload=${binaryPath} reload --config ${configPath} --force
Restart=always
RestartSec=5
TimeoutStopSec=20
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`
}

async function ensureSelfHostCaddy(repoRoot, publicBaseUrl, httpPort) {
  const origin = normalizeOrigin(publicBaseUrl)
  if (process.platform !== 'linux' || !origin) {
    return {
      configured: false,
      skipped: true,
      message: ''
    }
  }

  const hostname = new URL(origin).hostname
  const serviceName = 'pvtkrrx-caddy.service'
  const serviceIsActive = isSystemdUnitActive(serviceName)
  const portsBusy = await isLocalPortActive(80) || await isLocalPortActive(443)
  if (portsBusy && !serviceIsActive) {
    return {
      configured: false,
      skipped: true,
      message: 'Ports 80/443 are already in use. Add this hostname to your existing reverse proxy instead of starting a dedicated local Caddy service.'
    }
  }

  const binaryPath = await installCaddyBinary(repoRoot)
  const configDir = '/etc/pvtkrrx/caddy'
  const configPath = path.join(configDir, 'Caddyfile')
  const unitPath = '/etc/systemd/system/pvtkrrx-caddy.service'
  const tempConfigPath = path.join(os.tmpdir(), 'pvtkrrx-selfhost.Caddyfile')
  const tempUnitPath = path.join(os.tmpdir(), 'pvtkrrx-caddy.service')
  fs.writeFileSync(tempConfigPath, buildSelfHostCaddyConfig(hostname, httpPort), 'utf8')
  fs.writeFileSync(tempUnitPath, buildSelfHostCaddyService(binaryPath, configPath), 'utf8')

  try {
    runAsRoot('mkdir', ['-p', configDir], { cwd: repoRoot })
    runAsRoot(binaryPath, ['validate', '--config', tempConfigPath], { cwd: repoRoot })
    runAsRoot('install', ['-m', '0644', tempConfigPath, configPath], { cwd: repoRoot })
    runAsRoot('install', ['-m', '0644', tempUnitPath, unitPath], { cwd: repoRoot })
    runAsRoot('systemctl', ['daemon-reload'], { cwd: repoRoot })
    runAsRoot('systemctl', ['enable', 'pvtkrrx-caddy.service'], { cwd: repoRoot })
    runAsRoot('systemctl', ['restart', 'pvtkrrx-caddy.service'], { cwd: repoRoot })
  } finally {
    try {
      fs.unlinkSync(tempConfigPath)
    } catch (_) {}
    try {
      fs.unlinkSync(tempUnitPath)
    } catch (_) {}
  }

  return {
    configured: true,
    skipped: false,
    serviceName: 'pvtkrrx-caddy.service',
    configPath,
    hostname
  }
}

async function updateFreeDnsRecord(updateUrl) {
  const normalized = sanitizeHttpUrlDefault(updateUrl, '', {
    allowEmpty: true
  })
  if (!normalized) {
    return {
      updated: false,
      message: ''
    }
  }

  console.log('Updating FreeDNS record...')
  const response = await fetch(normalized, {
    headers: {
      'User-Agent': 'pvtkrrx-selfhost-installer'
    }
  })
  const body = String(await response.text()).trim()
  if (!response.ok) {
    throw new Error(`FreeDNS update failed (${response.status})`)
  }

  if (body) {
    console.log(`✓ FreeDNS response: ${body.split(/\r?\n/, 1)[0]}`)
  } else {
    console.log('✓ FreeDNS update accepted')
  }

  return {
    updated: true,
    message: body
  }
}

function lookupUserGroup(user) {
  const username = String(user || '').trim()
  if (!username) throw new Error('Service user is required')
  const uid = execFileSync('id', ['-u', username], { encoding: 'utf8' }).trim()
  const gid = execFileSync('id', ['-gn', username], { encoding: 'utf8' }).trim()
  return {
    user: username,
    uid: Number.parseInt(uid, 10),
    group: gid
  }
}

function ensureOwnership(targetPath, user, repoRoot) {
  if (process.platform !== 'linux' || !targetPath || !user) return
  if (!fs.existsSync(targetPath)) fs.mkdirSync(targetPath, { recursive: true })
  const owner = lookupUserGroup(user)
  runAsRoot('chown', ['-R', `${owner.user}:${owner.group}`, targetPath], { cwd: repoRoot })
}

function loadExistingServerConfig(runtimeDir, secret) {
  const configPath = path.join(runtimeDir, 'local-config.json')
  try {
    return loadSecureJsonFile(configPath, {
      defaultValue: null,
      secret
    })
  } catch (_) {
    return null
  }
}

function runFullBootstrap(repoRoot) {
  if (String(process.env[SELFHOST_BOOTSTRAP_ACTIVE_ENV] || '').trim() === '1') {
    throw new Error('Self-host bootstrap is already running; refusing to re-enter install-selfhost.sh from inside the active bootstrap chain.')
  }
  const scriptPath = path.join(repoRoot, 'scripts', 'install-selfhost.sh')
  const result = spawnSync('bash', [scriptPath], {
    cwd: repoRoot,
    env: {
      ...process.env,
      [SELFHOST_BOOTSTRAP_ACTIVE_ENV]: '1'
    },
    stdio: 'inherit'
  })
  if (result.error) throw result.error
  if (Number(result.status || 0) !== 0) {
    throw new Error(`Self-host bootstrap exited with code ${Number(result.status || 1)}`)
  }
}

function defaultServiceUser() {
  return String(
    process.env.PVTKRRX_SERVICE_USER ||
    process.env.SUDO_USER ||
    process.env.USER ||
    os.userInfo().username
  ).trim()
}

function defaultServiceName() {
  return String(
    process.env.PVTKRRX_SYSTEMD_SERVICE_NAME ||
    'pvtkrrx'
  ).trim() || 'pvtkrrx'
}

function resolveExistingSelfHostPassword(runtimeDir, env = process.env) {
  const state = ensureServerAdminToken(runtimeDir, {
    env,
    createIfMissing: false
  })
  return String(state?.token || '').trim()
}

function deriveDisplayOrigin(publicBaseUrl, port) {
  const publicOrigin = normalizeOrigin(publicBaseUrl)
  if (publicOrigin) return publicOrigin
  return `http://localhost:${port}`
}

function buildServerAdminBootstrapUrl(displayOrigin, token) {
  const origin = normalizeOrigin(displayOrigin)
  const adminToken = String(token || '').trim()
  if (!origin || !adminToken) return ''
  return `${origin}/configure#serverPassword=${encodeURIComponent(adminToken)}&serverAdminToken=${encodeURIComponent(adminToken)}`
}

function writeInstallerSummaryLine(line) {
  fs.writeSync(1, `${String(line || '')}\n`)
}

function printWorkingUrlSummary(displayOrigin, bootstrapUrl, publicBaseUrl) {
  const hasPublicOrigin = Boolean(normalizeOrigin(publicBaseUrl))
  writeInstallerSummaryLine(hasPublicOrigin ? 'Working public URLs:' : 'Working local URLs:')
  writeInstallerSummaryLine(`PVTKRRX URL: ${displayOrigin}`)
  writeInstallerSummaryLine(`Configure URL: ${displayOrigin}/configure`)
  if (bootstrapUrl) {
    writeInstallerSummaryLine(`Bootstrap URL: ${bootstrapUrl}`)
  }
  writeInstallerSummaryLine(`Self-host manifest URL: ${displayOrigin}/selfhost/manifest.json?mode=hosted`)
}

function describePlaybackOrigin(displayOrigin, publicBaseUrl, playbackBaseUrl) {
  const publicOrigin = normalizeOrigin(publicBaseUrl)
  const playbackOrigin = normalizeOrigin(playbackBaseUrl)
  if (!playbackOrigin) {
    return publicOrigin ? `Playback origin: ${publicOrigin}` : ''
  }
  if (playbackOrigin === publicOrigin || playbackOrigin === normalizeOrigin(displayOrigin)) {
    return `Playback origin: ${playbackOrigin}`
  }
  return `Playback origin: ${playbackOrigin} (control/install origin stays ${publicOrigin || displayOrigin})`
}

function resolveInstallPlaybackBaseUrl(existingPlaybackBaseUrl, publicBaseUrl, selfHostHttpsMode) {
  const playbackOrigin = normalizeOrigin(existingPlaybackBaseUrl)
  if (playbackOrigin) return playbackOrigin

  const publicOrigin = normalizeOrigin(publicBaseUrl)
  if ((selfHostHttpsMode === 'domain' || selfHostHttpsMode === 'freedns') && publicOrigin) {
    return publicOrigin
  }

  return ''
}

async function run() {
  const repoRoot = path.resolve(__dirname, '..')
  const envPath = path.join(repoRoot, '.env')
  const envFromFile = parseDotEnvFile(envPath)
  const defaultRuntimeDir = String(
    envFromFile.PVTKRRX_RUNTIME_DIR ||
    process.env.PVTKRRX_RUNTIME_DIR ||
    path.join(repoRoot, 'data', 'pvtkrrx')
  ).trim()
  const mergedEnv = {
    ...envFromFile,
    ...process.env,
    PVTKRRX_RUNTIME_DIR: defaultRuntimeDir
  }
  const existingSecret = String(mergedEnv.ENCRYPTION_SECRET || '').trim()
  const existingAuthSecret = String(mergedEnv.AUTH_TOKEN_SECRET || '').trim()
  const existingSelfHostPassword = resolveExistingSelfHostPassword(defaultRuntimeDir, mergedEnv)
  const existingPort = Number.parseInt(String(mergedEnv.PORT || '7000').trim(), 10) || 7000
  const existingHttpsPort = Number.parseInt(String(mergedEnv.HTTPS_PORT || '7001').trim(), 10) || 7001
  const existingPublicBaseUrl = normalizeBaseUrl(mergedEnv.PVTKRRX_PUBLIC_BASE_URL || '')
  const existingPlaybackBaseUrl = normalizeBaseUrl(mergedEnv.PVTKRRX_PLAYBACK_BASE_URL || '')
  const existingFreeDnsUpdateUrl = sanitizeHttpUrlDefault(mergedEnv.PVTKRRX_FREEDNS_UPDATE_URL || '', '', {
    allowEmpty: true
  })
  const existingHttpsMode = normalizeSelfHostHttpsMode(mergedEnv.PVTKRRX_SELF_HOST_HTTPS_MODE || '')
  const existingConfig = loadExistingServerConfig(defaultRuntimeDir, existingSecret)
  const bundledNodePath = String(process.env.PVTKRRX_NODE_PATH || process.execPath).trim() || process.execPath

  const rl = readline.createInterface({ input, output })
  try {
    console.log('PVTKRRX server installer')
    console.log('This installer writes a stable self-host config, a self-host password, and optional systemd service.')
    console.log('Press Enter to keep an existing/default value. Use "-" to clear an optional field.')
    console.log('')

    const prowlarr = await discoverProwlarrConfig({ useHints: false })
    const qbit = await discoverQbitConfig({ useHints: false })
    const envQbitPort = normalizePortNumber(mergedEnv.PVTKRRX_QBIT_WEBUI_PORT || '', 0)
    const preferredQbitUrl = buildLoopbackHttpUrl(
      envQbitPort || normalizePortNumber(qbit.port || '', 0) || 8080
    )
    const missingProviders = !prowlarr.installed || !prowlarr.apiKey || !qbit.installed
    if (process.platform === 'linux' && missingProviders) {
      console.log('Prowlarr and/or qBittorrent are missing. Running the full bootstrap now so they are installed automatically.')
      console.log('')
      rl.close()
      runFullBootstrap(repoRoot)
      return
    }

    const encryptionSecret = await promptValue(
      rl,
      'ENCRYPTION_SECRET',
      existingSecret || randomSecret()
    )
    const authTokenSecret = await promptValue(
      rl,
      'AUTH_TOKEN_SECRET',
      existingAuthSecret || randomSecret()
    )
    const selfHostPassword = await promptValue(
      rl,
      'Self-host config password',
      existingSelfHostPassword || randomSecret()
    )
    const httpPort = await promptInteger(rl, 'HTTP port', existingPort, { min: 1, max: 65535 })
    const httpsPort = await promptInteger(rl, 'HTTPS port', existingHttpsPort, { min: 1, max: 65535 })
    const runtimeDir = await promptValue(rl, 'Runtime directory', defaultRuntimeDir)
    const safeExistingPublicBaseUrl = sanitizeHttpUrlDefault(existingPublicBaseUrl, '', {
      requireHttps: true
    })
    const defaultHttpsMode = resolveSelfHostHttpsMode(existingHttpsMode, safeExistingPublicBaseUrl)
    let selfHostHttpsMode = normalizeSelfHostHttpsMode(
      await promptValue(
        rl,
        'HTTPS front door mode (freedns/domain/skip)',
        defaultHttpsMode
      )
    )
    if (!selfHostHttpsMode) selfHostHttpsMode = defaultHttpsMode

    let publicBaseUrl = (selfHostHttpsMode === 'domain' || selfHostHttpsMode === 'freedns') && !isTryCloudflareUrl(safeExistingPublicBaseUrl)
      ? safeExistingPublicBaseUrl
      : ''
    let freeDnsUpdateUrl = existingFreeDnsUpdateUrl
    if (selfHostHttpsMode === 'freedns' || selfHostHttpsMode === 'domain') {
      publicBaseUrl = await promptHttpUrl(
        rl,
        'Public HTTPS URL for Stremio install links',
        safeExistingPublicBaseUrl,
        {
          allowEmpty: false,
          requireHttps: true
        }
      )
      if (selfHostHttpsMode === 'freedns') {
        freeDnsUpdateUrl = await promptHttpUrl(
          rl,
          'FreeDNS update URL (optional)',
          existingFreeDnsUpdateUrl,
          {
            allowEmpty: true
          }
        )
      } else {
        freeDnsUpdateUrl = ''
      }
    } else {
      publicBaseUrl = ''
      freeDnsUpdateUrl = ''
    }
    const defaultPlaybackBaseUrl = resolveInstallPlaybackBaseUrl(
      existingPlaybackBaseUrl,
      publicBaseUrl,
      selfHostHttpsMode
    )
    let playbackBaseUrl = defaultPlaybackBaseUrl
    if (selfHostHttpsMode === 'domain' || selfHostHttpsMode === 'freedns') {
      playbackBaseUrl = await promptHttpUrl(
        rl,
        'Playback HTTPS URL for built-in /file and /playback (optional; leave blank to use the main host)',
        defaultPlaybackBaseUrl || publicBaseUrl,
        {
          allowEmpty: true,
          requireHttps: true
        }
      )
      if (!playbackBaseUrl) playbackBaseUrl = publicBaseUrl
    }

    const defaultAllowedWebOrigins = buildDefaultAllowedOrigins(
      publicBaseUrl,
      httpPort,
      httpsPort,
      String(mergedEnv.PVTKRRX_ALLOWED_WEB_ORIGINS || '').trim()
    )
    const allowedWebOrigins = normalizeOriginList(
      await promptValue(
        rl,
        'Allowed browser origins (comma separated, optional)',
        defaultAllowedWebOrigins,
        { allowEmpty: true }
      ),
      defaultAllowedWebOrigins
    )

    const prowlarrDetectedHere = Boolean(prowlarr.installed)
    const qbitDetectedHere = Boolean(qbit.installed)
    if (prowlarrDetectedHere) {
      console.log('Prowlarr detected on this host. The suggested URL points to this server (loopback).')
    } else {
      console.log('Prowlarr was NOT detected on this host.')
      console.log('  Enter the URL PVTKRRX can reach (e.g. http://seedbox.example.com:9696)')
      console.log('  Only enter http://127.0.0.1:9696 if Prowlarr really runs on this same server.')
    }
    const jackettUrlDefault = prowlarrDetectedHere
      ? sanitizeHttpUrlDefault(prowlarr.url || existingConfig?.jackettUrl || '', 'http://localhost:9696')
      : sanitizeHttpUrlDefault(existingConfig?.jackettUrl || '', '', { allowEmpty: true })
    const jackettUrl = await promptHttpUrl(
      rl,
      'Prowlarr URL',
      jackettUrlDefault,
      { allowEmpty: !prowlarrDetectedHere && !jackettUrlDefault }
    )
    const jackettApiKey = await promptValue(
      rl,
      'Prowlarr API key',
      String(existingConfig?.jackettApiKey || '').trim(),
      { allowEmpty: true }
    )
    if (qbitDetectedHere) {
      console.log('qBittorrent detected on this host. The suggested URL points to this server (loopback).')
    } else {
      console.log('qBittorrent was NOT detected on this host.')
      console.log('  Enter the URL PVTKRRX can reach (e.g. http://seedbox.example.com:8080)')
      console.log('  Only enter http://127.0.0.1:<port> if qBittorrent really runs on this same server.')
    }
    const qbitUrlDefault = qbitDetectedHere
      ? sanitizeHttpUrlDefault(preferredQbitUrl || existingConfig?.qbitUrl || '', preferredQbitUrl)
      : sanitizeHttpUrlDefault(existingConfig?.qbitUrl || '', '', { allowEmpty: true })
    const qbitUrl = await promptHttpUrl(
      rl,
      'qBittorrent URL',
      qbitUrlDefault,
      { allowEmpty: !qbitDetectedHere && !qbitUrlDefault }
    )
    const qbitUsername = await promptValue(
      rl,
      'qBittorrent username',
      String(qbit.username || existingConfig?.qbitUsername || '').trim(),
      { allowEmpty: true }
    )
    const qbitPassword = await promptValue(
      rl,
      'qBittorrent password',
      String(existingConfig?.qbitPassword || '').trim(),
      { allowEmpty: true }
    )
    const fileServerUrl = await promptHttpUrl(
      rl,
      'File Server URL (optional)',
      sanitizeHttpUrlDefault(existingConfig?.fileServerUrl, '', { allowEmpty: true }),
      { allowEmpty: true }
    )
    const fileServerAuth = await promptValue(
      rl,
      'File Server Authorization header (optional)',
      String(existingConfig?.fileServerAuth || '').trim(),
      { allowEmpty: true }
    )
    const maxResults = await promptInteger(
      rl,
      'Max results per search',
      String(existingConfig?.maxResults || 50).trim(),
      { min: 10, max: 200 }
    )
    const autoDeleteWatched = await promptBoolean(
      rl,
      'Auto-delete watched torrents/files',
      existingConfig?.autoDeleteWatched !== false
    )
    const watchedDeleteGraceSeconds = await promptInteger(
      rl,
      'Delete grace period seconds',
      String(existingConfig?.watchedDeleteGraceSeconds ?? 300).trim(),
      { min: 0, max: 86400 * 30 }
    )

    let installService = false
    let serviceName = defaultServiceName()
    let serviceUser = defaultServiceUser()
    if (process.platform === 'linux') {
      installService = await promptBoolean(rl, 'Install/start systemd service for auto-boot', true)
      if (installService) {
        serviceName = await promptValue(rl, 'systemd service name', serviceName)
        serviceUser = await promptValue(rl, 'systemd service user', serviceUser)
      }
    }

    updateDotEnvFile(envPath, {
      ENCRYPTION_SECRET: encryptionSecret,
      AUTH_TOKEN_SECRET: authTokenSecret,
      PVTKRRX_SELF_HOST_PASSWORD: selfHostPassword,
      PVTKRRX_SERVER_ADMIN_TOKEN: selfHostPassword,
      PVTKRRX_SELF_HOST_MODE: 'true',
      PVTKRRX_SELF_HOST_HTTPS_MODE: selfHostHttpsMode,
      PVTKRRX_RUNTIME_DIR: runtimeDir,
      PVTKRRX_PUBLIC_BASE_URL: publicBaseUrl,
      PVTKRRX_FREEDNS_UPDATE_URL: freeDnsUpdateUrl,
      PVTKRRX_PLAYBACK_BASE_URL: playbackBaseUrl,
      PVTKRRX_ALLOWED_WEB_ORIGINS: allowedWebOrigins,
      PORT: String(httpPort),
      HTTPS_PORT: String(httpsPort)
    })

    process.env.ENCRYPTION_SECRET = encryptionSecret
    process.env.AUTH_TOKEN_SECRET = authTokenSecret
    process.env.PVTKRRX_SELF_HOST_PASSWORD = selfHostPassword
    process.env.PVTKRRX_SERVER_ADMIN_TOKEN = selfHostPassword
    process.env.PVTKRRX_SELF_HOST_MODE = 'true'
    process.env.PVTKRRX_SELF_HOST_HTTPS_MODE = selfHostHttpsMode
    process.env.PVTKRRX_RUNTIME_DIR = runtimeDir
    process.env.PVTKRRX_PUBLIC_BASE_URL = publicBaseUrl
    process.env.PVTKRRX_FREEDNS_UPDATE_URL = freeDnsUpdateUrl
    process.env.PVTKRRX_PLAYBACK_BASE_URL = playbackBaseUrl
    process.env.PVTKRRX_ALLOWED_WEB_ORIGINS = allowedWebOrigins
    process.env.PORT = String(httpPort)
    process.env.HTTPS_PORT = String(httpsPort)

    if (selfHostHttpsMode === 'freedns') {
      await updateFreeDnsRecord(freeDnsUpdateUrl)
    }
    if (selfHostHttpsMode === 'domain' || selfHostHttpsMode === 'freedns') {
      const legacyTunnelResult = disableLegacyCloudflareTunnel(repoRoot)
      if (legacyTunnelResult?.message) {
        console.log(legacyTunnelResult.message)
      }
      const caddyResult = await ensureSelfHostCaddy(repoRoot, publicBaseUrl, httpPort)
      if (caddyResult?.message) {
        console.log(caddyResult.message)
      } else if (caddyResult?.configured) {
        console.log(`✓ Local Caddy route ready for ${caddyResult.hostname}`)
      }
    }

    const { normalizeAddonConfig } = require('../src/lib/shared')

    const nextConfig = normalizeAddonConfig({
      ...(existingConfig && typeof existingConfig === 'object' ? existingConfig : {}),
      jackettUrl,
      jackettApiKey,
      qbitUrl,
      qbitUsername,
      qbitPassword,
      provider: String(existingConfig?.provider || 'custom').trim() || 'custom',
      fileServerUrl,
      fileServerAuth,
      maxResults,
      autoDeleteWatched,
      watchedDeleteGraceSeconds,
      lanPairEnabled: false,
      lanPairRequired: false
    }, {
      includeLocalSecrets: true
    })

    const localConfigPath = path.join(runtimeDir, 'local-config.json')
    saveSecureJsonFile(localConfigPath, nextConfig, { secret: encryptionSecret })
    const adminState = ensureServerAdminToken(runtimeDir, {
      env: process.env,
      createIfMissing: true
    })

    const prowlarrSync = await ensureProwlarrQbitDownloadClient({
      prowlarrUrl: jackettUrl,
      prowlarrApiKey: jackettApiKey,
      qbitUrl,
      qbitUsername,
      qbitPassword,
      queueingEnabled: Boolean(qbit.queueingEnabled)
    })
    if (prowlarrSync.ok) {
      console.log(`✓ Prowlarr qBittorrent download client ${prowlarrSync.action}`)
    } else if (prowlarrSync.message) {
      console.warn(`⚠ Prowlarr qBittorrent download client: ${prowlarrSync.message}`)
    }

    // Sports artwork is served by the SportsMeta service
    // (https://sportsmeta.pvtkrrx.cc). PVTKRRX no longer pre-seeds or refreshes
    // a local TheSportsDB image cache during install.

    let serviceResult = null
    if (installService) {
      ensureOwnership(runtimeDir, serviceUser, repoRoot)
      try {
        serviceResult = installSystemdService({
          repoRoot,
          nodePath: bundledNodePath,
          serviceName,
          user: serviceUser
        })
      } catch (error) {
        console.warn(`systemd install skipped: ${error.message}`)
      }
    }

    const displayOrigin = deriveDisplayOrigin(publicBaseUrl, httpPort)
    const configureBootstrapUrl = buildServerAdminBootstrapUrl(displayOrigin, adminState.token)
    console.log('')
    console.log('PVTKRRX server install complete')
    console.log(`App directory: ${repoRoot}`)
    console.log(`Runtime directory: ${runtimeDir}`)
    console.log(`HTTPS mode: ${describeSelfHostHttpsMode(selfHostHttpsMode)}`)
    console.log(`Saved config: ${localConfigPath}`)
    console.log(`Self-host password file: ${adminState.path || path.join(runtimeDir, 'server-admin-token')}`)
    printWorkingUrlSummary(displayOrigin, configureBootstrapUrl, publicBaseUrl)
    const playbackOriginLine = describePlaybackOrigin(displayOrigin, publicBaseUrl, playbackBaseUrl)
    if (playbackOriginLine) console.log(playbackOriginLine)
    if (publicBaseUrl) {
      console.log(`Allowed web origins: ${allowedWebOrigins || '(none)'}`)
    } else {
      console.log('Remote Stremio installs need a real HTTPS origin. Add one later by setting PVTKRRX_PUBLIC_BASE_URL in .env and restarting the service.')
    }
    console.log(`HTTP port: ${httpPort}`)
    console.log(`HTTPS port: ${httpsPort}`)
    console.log(`Node binary: ${bundledNodePath}`)
    if (serviceResult) {
      console.log(`systemd service: ${serviceResult.serviceName}.service`)
      console.log(`Service unit: ${serviceResult.unitPath}`)
      console.log(`Service user: ${serviceResult.user}`)
    } else if (process.platform === 'linux') {
      console.log('Auto-boot: run `npm run server:install-service` later if you want systemd startup.')
    }
  } finally {
    rl.close()
  }
}

// ─── Auto-detection ────────────────────────────────────────────────

function findProwlarrConfig() {
  const prowlarrDataDir = String(process.env.PVTKRRX_PROWLARR_DATA || '').trim()
  const candidates = [
    prowlarrDataDir ? path.join(prowlarrDataDir, 'config.xml') : null,
    '/var/lib/prowlarr/config.xml',
    path.join(os.homedir(), '.config', 'Prowlarr', 'config.xml'),
    '/opt/Prowlarr/config.xml'
  ].filter(Boolean)

  for (const p of candidates) {
    if (fs.existsSync(p)) return p
  }
  return null
}

function parseProwlarrConfigXml(configPath) {
  const xml = fs.readFileSync(configPath, 'utf8')
  const apiKey = (xml.match(/<ApiKey>([^<]+)<\/ApiKey>/) || [])[1] || ''
  const port = (xml.match(/<Port>([^<]+)<\/Port>/) || [])[1] || '9696'
  return { apiKey: apiKey.trim(), port: Number.parseInt(port.trim(), 10) || 9696 }
}

function findQbitConfig() {
  const qbitUser = String(process.env.PVTKRRX_QBIT_USER || 'qbittorrent').trim()
  const candidates = [
    `/var/lib/${qbitUser}/.config/qBittorrent/qBittorrent.conf`,
    path.join(os.homedir(), '.config', 'qBittorrent', 'qBittorrent.conf'),
    `/home/${qbitUser}/.config/qBittorrent/qBittorrent.conf`
  ]

  for (const p of candidates) {
    if (fs.existsSync(p)) return p
  }
  return null
}

function parseQbitConfig(configPath) {
  const ini = fs.readFileSync(configPath, 'utf8')
  const portMatch = ini.match(/WebUI\\Port=(\d+)/) || ini.match(/web_ui_port=(\d+)/i)
  const usernameMatch = ini.match(/WebUI\\Username=(.+)/)
  const savePathMatch = ini.match(/Session\\DefaultSavePath=(.+)/)
  const queueingEnabledMatch = ini.match(/(?:Session\\)?QueueingSystemEnabled=(true|false)/i)

  return {
    port: portMatch ? Number.parseInt(portMatch[1], 10) : null,
    username: usernameMatch ? usernameMatch[1].trim() : '',
    savePath: savePathMatch ? savePathMatch[1].trim() : '',
    queueingEnabled: queueingEnabledMatch ? queueingEnabledMatch[1].toLowerCase() === 'true' : false
  }
}

async function runAuto() {
  const repoRoot = path.resolve(__dirname, '..')
  const envPath = path.join(repoRoot, '.env')
  const envFromFile = parseDotEnvFile(envPath)
  const defaultRuntimeDir = String(
    envFromFile.PVTKRRX_RUNTIME_DIR ||
    process.env.PVTKRRX_RUNTIME_DIR ||
    path.join(repoRoot, 'data', 'pvtkrrx')
  ).trim()
  const mergedEnv = { ...envFromFile, ...process.env, PVTKRRX_RUNTIME_DIR: defaultRuntimeDir }
  const existingSecret = String(mergedEnv.ENCRYPTION_SECRET || '').trim()
  const existingAuthSecret = String(mergedEnv.AUTH_TOKEN_SECRET || '').trim()
  const existingSelfHostPassword = resolveExistingSelfHostPassword(defaultRuntimeDir, mergedEnv)
  const existingConfig = loadExistingServerConfig(defaultRuntimeDir, existingSecret)
  const bundledNodePath = String(process.env.PVTKRRX_NODE_PATH || process.execPath).trim() || process.execPath
  const httpPort = Number.parseInt(String(mergedEnv.PORT || '7000').trim(), 10) || 7000
  const httpsPort = Number.parseInt(String(mergedEnv.HTTPS_PORT || '7001').trim(), 10) || 7001
  const existingPublicBaseUrl = sanitizeHttpUrlDefault(mergedEnv.PVTKRRX_PUBLIC_BASE_URL || '', '', {
    requireHttps: true
  })
  const existingPlaybackBaseUrl = sanitizeHttpUrlDefault(mergedEnv.PVTKRRX_PLAYBACK_BASE_URL || '', '', {
    requireHttps: true,
    allowEmpty: true
  })
  const existingFreeDnsUpdateUrl = sanitizeHttpUrlDefault(mergedEnv.PVTKRRX_FREEDNS_UPDATE_URL || '', '', {
    allowEmpty: true
  })
  const existingHttpsMode = normalizeSelfHostHttpsMode(mergedEnv.PVTKRRX_SELF_HOST_HTTPS_MODE || '')
  const selfHostHttpsMode = resolveSelfHostHttpsMode(existingHttpsMode, existingPublicBaseUrl)
  let publicBaseUrl = (selfHostHttpsMode === 'domain' || selfHostHttpsMode === 'freedns') && !isTryCloudflareUrl(existingPublicBaseUrl)
    ? existingPublicBaseUrl
    : ''

  if ((selfHostHttpsMode === 'domain' || selfHostHttpsMode === 'freedns') && !publicBaseUrl) {
    throw new Error(`PVTKRRX_SELF_HOST_HTTPS_MODE=${selfHostHttpsMode} requires PVTKRRX_PUBLIC_BASE_URL to be set`)
  }

  if (selfHostHttpsMode === 'skip') {
    publicBaseUrl = ''
  }
  const playbackBaseUrl = resolveInstallPlaybackBaseUrl(
    existingPlaybackBaseUrl,
    publicBaseUrl,
    selfHostHttpsMode
  )

  console.log('PVTKRRX auto-configuration')
  console.log(`HTTPS mode: ${describeSelfHostHttpsMode(selfHostHttpsMode)}`)
  console.log('')

  const prowlarr = await discoverProwlarrConfig({ useHints: false })
  const qbit = await discoverQbitConfig({ useHints: false })
  const envQbitPort = normalizePortNumber(mergedEnv.PVTKRRX_QBIT_WEBUI_PORT || '', 0)
  const preferredQbitUrl = buildLoopbackHttpUrl(
    envQbitPort || normalizePortNumber(qbit.port || '', 0) || 8080
  )

  const prowlarrDetectedHere = Boolean(prowlarr.installed)
  const qbitDetectedHere = Boolean(qbit.installed)
  const existingJackettUrl = String(existingConfig?.jackettUrl || '').trim()
  const existingQbitUrl = String(existingConfig?.qbitUrl || '').trim()

  // Env var fallbacks — used when no locally-installed service is detected and no
  // saved config URL is present.  Intended for Docker Compose deployments where
  // Prowlarr and qBittorrent run in separate containers reachable via Docker service
  // DNS names (e.g. PVTKRRX_PROWLARR_URL=http://prowlarr:9696).
  const envProwlarrUrl = sanitizeHttpUrlDefault(String(mergedEnv.PVTKRRX_PROWLARR_URL || '').trim(), '', { allowEmpty: true })
  const envQbitUrl = sanitizeHttpUrlDefault(String(mergedEnv.PVTKRRX_QBIT_URL || '').trim(), '', { allowEmpty: true })
  // Credential env-var fallbacks — used when no locally-detected or saved credential exists.
  // Intended for Docker Compose deployments where services exchange credentials via env vars.
  const envProwlarrApiKey = String(mergedEnv.PVTKRRX_PROWLARR_API_KEY || '').trim()
  const envQbitUsername = String(mergedEnv.PVTKRRX_QBIT_USERNAME || '').trim()
  const envQbitPassword = String(mergedEnv.PVTKRRX_QBIT_PASSWORD || '').trim()

  let jackettUrl = ''
  if (prowlarr.url) {
    jackettUrl = sanitizeHttpUrlDefault(prowlarr.url, '', { allowEmpty: true })
  } else if (existingJackettUrl) {
    jackettUrl = sanitizeHttpUrlDefault(existingJackettUrl, '', { allowEmpty: true })
  } else if (envProwlarrUrl) {
    jackettUrl = envProwlarrUrl
  }
  let jackettApiKey = String(prowlarr.apiKey || existingConfig?.jackettApiKey || envProwlarrApiKey || '').trim()
  let qbitUrl = ''
  if (qbitDetectedHere) {
    qbitUrl = sanitizeHttpUrlDefault(preferredQbitUrl || qbit.url || '', '', { allowEmpty: true })
  } else if (existingQbitUrl) {
    qbitUrl = sanitizeHttpUrlDefault(existingQbitUrl, '', { allowEmpty: true })
  } else if (envQbitUrl) {
    qbitUrl = envQbitUrl
  }
  let qbitUsername = String(qbit.username || existingConfig?.qbitUsername || envQbitUsername || '').trim()
  let qbitPassword = String(existingConfig?.qbitPassword || envQbitPassword || '').trim()

  if (prowlarrDetectedHere) {
    console.log(`✓ Prowlarr detected on this host${prowlarr.configPath ? ` at ${prowlarr.configPath}` : ''}`)
    console.log(`  URL: ${jackettUrl || '(none)'}`)
    if (jackettApiKey) console.log(`  API key: ${jackettApiKey.slice(0, 8)}...`)
  } else if (existingJackettUrl) {
    console.log(`• Prowlarr not detected on this host. Keeping saved URL: ${existingJackettUrl}`)
    console.log('  If Prowlarr runs on a different seedbox or VPS, leave this saved URL in place.')
    console.log('  If you intended Prowlarr to be on this server, install it locally and re-run the installer.')
  } else if (jackettUrl) {
    console.log(`• Prowlarr: using PVTKRRX_PROWLARR_URL from environment: ${jackettUrl}`)
    if (jackettApiKey) {
      console.log(`  API key: ${jackettApiKey.slice(0, 8)}... (from PVTKRRX_PROWLARR_API_KEY)`)
    } else {
      console.log('  API key not set — add it in /configure once Prowlarr is running.')
    }
  } else {
    console.log('⚠ Prowlarr not detected on this host and no saved URL present.')
    console.log('  Leaving Prowlarr URL empty. Set it later in /configure:')
    console.log('    • http://127.0.0.1:9696 only if Prowlarr is on this same server')
    console.log('    • http://<seedbox-hostname>:<port> if Prowlarr runs elsewhere')
  }

  if (qbitDetectedHere) {
    console.log(`✓ qBittorrent detected on this host${qbit.configPath ? ` at ${qbit.configPath}` : ''}`)
    console.log(`  URL: ${qbitUrl || '(none)'}`)
    if (qbitUsername) console.log(`  Username: ${qbitUsername}`)
    if (qbit.savePath) console.log(`  Save path: ${qbit.savePath}`)
    if (qbit.localHostAuthDisabled) console.log('  Localhost auth: disabled')
  } else if (existingQbitUrl) {
    console.log(`• qBittorrent not detected on this host. Keeping saved URL: ${existingQbitUrl}`)
    console.log('  If qBittorrent runs on a different seedbox or VPS, leave this saved URL in place.')
  } else if (qbitUrl) {
    console.log(`• qBittorrent: using PVTKRRX_QBIT_URL from environment: ${qbitUrl}`)
    if (qbitUsername) console.log(`  Username: ${qbitUsername}`)
    if (qbitPassword) console.log('  Password: set from environment.')
    else console.log('  Password not set — add it in /configure once qBittorrent is running.')
  } else {
    console.log('⚠ qBittorrent not detected on this host and no saved URL present.')
    console.log('  Leaving qBittorrent URL empty. Set it later in /configure:')
    console.log('    • http://127.0.0.1:8080 only if qBittorrent is on this same server')
    console.log('    • http://<seedbox-hostname>:<port> if qBittorrent runs elsewhere')
  }

  // ── Secrets ──
  const encryptionSecret = existingSecret || randomSecret()
  const authTokenSecret = existingAuthSecret || randomSecret()
  const selfHostPassword = existingSelfHostPassword || randomSecret()

  // ── Write .env ──
  const allowedWebOrigins = buildDefaultAllowedOrigins(
    publicBaseUrl,
    httpPort,
    httpsPort,
    String(mergedEnv.PVTKRRX_ALLOWED_WEB_ORIGINS || '').trim()
  )

  updateDotEnvFile(envPath, {
    ENCRYPTION_SECRET: encryptionSecret,
    AUTH_TOKEN_SECRET: authTokenSecret,
    PVTKRRX_SELF_HOST_PASSWORD: selfHostPassword,
    PVTKRRX_SERVER_ADMIN_TOKEN: selfHostPassword,
    PVTKRRX_SELF_HOST_MODE: 'true',
    PVTKRRX_SELF_HOST_HTTPS_MODE: selfHostHttpsMode,
    PVTKRRX_RUNTIME_DIR: defaultRuntimeDir,
    PVTKRRX_PUBLIC_BASE_URL: publicBaseUrl,
    PVTKRRX_FREEDNS_UPDATE_URL: existingFreeDnsUpdateUrl,
    PVTKRRX_PLAYBACK_BASE_URL: playbackBaseUrl,
    PVTKRRX_ALLOWED_WEB_ORIGINS: allowedWebOrigins,
    PORT: String(httpPort),
    HTTPS_PORT: String(httpsPort)
  })

  // ── Set process env for normalizeAddonConfig ──
  process.env.ENCRYPTION_SECRET = encryptionSecret
  process.env.AUTH_TOKEN_SECRET = authTokenSecret
  process.env.PVTKRRX_SELF_HOST_PASSWORD = selfHostPassword
  process.env.PVTKRRX_SERVER_ADMIN_TOKEN = selfHostPassword
  process.env.PVTKRRX_SELF_HOST_MODE = 'true'
  process.env.PVTKRRX_SELF_HOST_HTTPS_MODE = selfHostHttpsMode
  process.env.PVTKRRX_RUNTIME_DIR = defaultRuntimeDir
  process.env.PVTKRRX_PUBLIC_BASE_URL = publicBaseUrl
  process.env.PVTKRRX_FREEDNS_UPDATE_URL = existingFreeDnsUpdateUrl
  process.env.PVTKRRX_PLAYBACK_BASE_URL = playbackBaseUrl
  process.env.PVTKRRX_ALLOWED_WEB_ORIGINS = allowedWebOrigins
  process.env.PORT = String(httpPort)
  process.env.HTTPS_PORT = String(httpsPort)

  if (selfHostHttpsMode === 'freedns') {
    await updateFreeDnsRecord(existingFreeDnsUpdateUrl)
  }
  if (selfHostHttpsMode === 'domain' || selfHostHttpsMode === 'freedns') {
    const legacyTunnelResult = disableLegacyCloudflareTunnel(repoRoot)
    if (legacyTunnelResult?.message) {
      console.log(legacyTunnelResult.message)
    }
    const caddyResult = await ensureSelfHostCaddy(repoRoot, publicBaseUrl, httpPort)
    if (caddyResult?.message) {
      console.log(caddyResult.message)
    } else if (caddyResult?.configured) {
      console.log(`✓ Local Caddy route ready for ${caddyResult.hostname}`)
    }
  }

  // ── Write local config ──
  const { normalizeAddonConfig } = require('../src/lib/shared')

  const nextConfig = normalizeAddonConfig({
    ...(existingConfig && typeof existingConfig === 'object' ? existingConfig : {}),
    jackettUrl,
    jackettApiKey,
    qbitUrl,
    qbitUsername,
    qbitPassword,
    provider: String(existingConfig?.provider || 'custom').trim() || 'custom',
    fileServerUrl: sanitizeHttpUrlDefault(existingConfig?.fileServerUrl || '', '', { allowEmpty: true }),
    fileServerAuth: String(existingConfig?.fileServerAuth || '').trim(),
    maxResults: existingConfig?.maxResults || 50,
    autoDeleteWatched: existingConfig?.autoDeleteWatched !== false,
    watchedDeleteGraceSeconds: existingConfig?.watchedDeleteGraceSeconds ?? 300,
    lanPairEnabled: false,
    lanPairRequired: false
  }, { includeLocalSecrets: true })

  fs.mkdirSync(defaultRuntimeDir, { recursive: true })
  const localConfigPath = path.join(defaultRuntimeDir, 'local-config.json')
  saveSecureJsonFile(localConfigPath, nextConfig, { secret: encryptionSecret })
  const adminState = ensureServerAdminToken(defaultRuntimeDir, {
    env: process.env,
    createIfMissing: true
  })

  const prowlarrSync = await ensureProwlarrQbitDownloadClient({
    prowlarrUrl: jackettUrl,
    prowlarrApiKey: jackettApiKey,
    qbitUrl,
    qbitUsername,
    qbitPassword,
    queueingEnabled: Boolean(qbit.queueingEnabled)
  })
  if (!prowlarrSync.ok) {
    console.warn(`Prowlarr qBittorrent download client: ${prowlarrSync.message}`)
  } else {
    console.log(`✓ Prowlarr qBittorrent download client ${prowlarrSync.action}`)
  }

  console.log('')
  console.log(`✓ Config saved to ${localConfigPath}`)
  console.log(`✓ Self-host password: ${adminState.path ? fs.readFileSync(adminState.path, 'utf8').trim() : adminState.token}`)

  // Sports artwork is served by SportsMeta (https://sportsmeta.pvtkrrx.cc);
  // no local TheSportsDB cache is populated from this installer anymore.

  // ── systemd service ──
  let serviceResult = null
  if (process.platform === 'linux') {
    const serviceName = defaultServiceName()
    const serviceUser = defaultServiceUser()
    ensureOwnership(defaultRuntimeDir, serviceUser, repoRoot)
    try {
      serviceResult = installSystemdService({
        repoRoot,
        nodePath: bundledNodePath,
        serviceName,
        user: serviceUser
      })
      console.log(`✓ systemd service: ${serviceResult.serviceName}.service (${serviceResult.unitPath})`)
    } catch (error) {
      console.warn(`⚠ systemd install skipped: ${error.message}`)
    }
  }

  const displayOrigin = deriveDisplayOrigin(publicBaseUrl, httpPort)
  const configureBootstrapUrl = buildServerAdminBootstrapUrl(displayOrigin, adminState.token)
  console.log('')
  console.log('─── Summary ───')
  console.log(`HTTPS mode: ${describeSelfHostHttpsMode(selfHostHttpsMode)}`)
  console.log(`Prowlarr:    ${jackettUrl}`)
  console.log(`qBittorrent: ${qbitUrl}`)
  printWorkingUrlSummary(displayOrigin, configureBootstrapUrl, publicBaseUrl)
  const playbackOriginLine = describePlaybackOrigin(displayOrigin, publicBaseUrl, playbackBaseUrl)
  if (playbackOriginLine) console.log(playbackOriginLine)
  console.log(`HTTP port:   ${httpPort}`)
  console.log(`Node binary: ${bundledNodePath}`)
}

if (require.main === module) {
  const isAuto = process.argv.includes('--auto') || !process.stdin.isTTY || !process.stdout.isTTY
  const entry = isAuto ? runAuto : run
  entry().catch((error) => {
    console.error(error.message)
    process.exit(1)
  })
}

module.exports = {
  buildServerAdminBootstrapUrl,
  buildDefaultAllowedOrigins,
  defaultServiceName,
  defaultServiceUser,
  deriveDisplayOrigin,
  isTryCloudflareUrl,
  printWorkingUrlSummary,
  runFullBootstrap,
  run,
  runAuto,
  normalizeOrigin,
  normalizeOriginList,
  resolveSelfHostHttpsMode,
  resolveInstallPlaybackBaseUrl,
  resolveExistingSelfHostPassword,
  parseDotEnvFile,
  parseHttpUrl,
  updateDotEnvFile,
  writeInstallerSummaryLine
}
