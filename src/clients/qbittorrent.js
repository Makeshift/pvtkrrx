const crypto = require('crypto')

const TIMEOUT_MS = Math.max(5000, parseInt(process.env.PVTKRRX_QBIT_TIMEOUT_MS || '12000', 10))
const SESSION_CACHE_TTL_MS = Math.max(
  60000,
  parseInt(process.env.PVTKRRX_QBIT_SESSION_CACHE_TTL_MS || '1800000', 10)
)
const sessionCache = new Map()
const loginInFlight = new Map()

function buildSessionCacheKey(url, username, password) {
  const secretHash = crypto
    .createHash('sha256')
    .update(String(password || ''))
    .digest('base64url')
  return [
    String(url || '').trim().replace(/\/$/, ''),
    String(username || '').trim(),
    secretHash
  ].join('\n')
}

function readCachedSession(cacheKey) {
  const cached = sessionCache.get(cacheKey)
  if (!cached || Number(cached.expiresAt || 0) <= Date.now()) {
    sessionCache.delete(cacheKey)
    return null
  }
  return cached
}

class QBitClient {
  constructor(url, username, password) {
    this.url = url.replace(/\/$/, '')
    this.username = username
    this.password = password
    this.sid = null
    this.cookieName = 'SID' // qBit 4.x default; overwritten on login for 5.x
    // Try localhost/no-auth first, then fall back to cookie auth when needed.
    this.noAuth = true
    this.cacheKey = buildSessionCacheKey(this.url, this.username, this.password)
    this.applyCachedSession()
  }

  applyCachedSession() {
    const cached = readCachedSession(this.cacheKey)
    if (!cached) return
    this.sid = cached.sid || null
    if (cached.cookieName) this.cookieName = cached.cookieName
    if (typeof cached.noAuth === 'boolean' && (cached.noAuth || this.username)) {
      this.noAuth = cached.noAuth
    }
  }

  rememberSession() {
    sessionCache.set(this.cacheKey, {
      sid: this.sid || '',
      cookieName: this.cookieName || 'SID',
      noAuth: this.noAuth === true,
      expiresAt: Date.now() + SESSION_CACHE_TTL_MS
    })
  }

  clearSession() {
    this.sid = null
    sessionCache.delete(this.cacheKey)
  }

  async login(force = false) {
    if (this.sid && !force) return this.sid
    if (force) this.sid = null

    if (!force) {
      this.applyCachedSession()
      if (this.sid) return this.sid

      const pendingLogin = loginInFlight.get(this.cacheKey)
      if (pendingLogin) {
        const sid = await pendingLogin
        this.applyCachedSession()
        return this.sid || sid
      }
    }

    const loginPromise = this.performLogin()
    loginInFlight.set(this.cacheKey, loginPromise)
    try {
      return await loginPromise
    } finally {
      if (loginInFlight.get(this.cacheKey) === loginPromise) {
        loginInFlight.delete(this.cacheKey)
      }
    }
  }

  async performLogin() {
    if (!this.username) {
      throw new Error('qBit requires WebUI credentials or localhost auth disabled')
    }

    if (!this.password) {
      throw new Error('qBit password is required when localhost auth is enabled')
    }

    const res = await fetch(`${this.url}/api/v2/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `username=${encodeURIComponent(this.username)}&password=${encodeURIComponent(this.password)}`,
      signal: AbortSignal.timeout(TIMEOUT_MS)
    })

    if (!res.ok) {
      if (res.status === 403) throw new Error('qBit login rejected (403). Check username/password.')
      throw new Error(`qBit login HTTP ${res.status}`)
    }

    const body = await res.text()
    // qBittorrent 4.x responds with 200 + body 'Ok.' on success.
    // qBittorrent 5.x responds with 204 No Content (empty body) on success.
    // Anything else (200 + non-Ok body) means wrong credentials.
    if (res.status !== 204 && body.trim() !== 'Ok.') {
      throw new Error('qBit login: invalid credentials')
    }

    const setCookie = res.headers.get('set-cookie') || ''
    // qBit 4.x: SID=<value>
    // qBit 5.x: QBT_SID_<PORT>=<value>
    // Capture the full cookie name so we can send it back correctly.
    const match = setCookie.match(/\b([A-Za-z0-9_]*SID[A-Za-z0-9_]*)=([^;]+)/)
    if (!match) throw new Error('qBit login: no SID cookie')

    this.cookieName = match[1]
    this.sid = match[2]
    this.noAuth = false
    this.rememberSession()
    return this.sid
  }

  async request(path, options = {}) {
    const method = options.method || 'GET'
    const body = options.body
    const expect = options.expect || 'json'

    const doFetch = async (withCookie) => {
      const headers = { ...(options.headers || {}) }
      if (withCookie && this.sid) headers.Cookie = `${this.cookieName || 'SID'}=${this.sid}`
      const res = await fetch(`${this.url}${path}`, {
        method,
        headers,
        body,
        signal: AbortSignal.timeout(TIMEOUT_MS)
      })
      return res
    }

    // First attempt without auth when enabled
    if (this.noAuth) {
      const res = await doFetch(false)
      if (res.ok) {
        this.sid = null
        this.noAuth = true
        this.rememberSession()
        return expect === 'text' ? res.text() : res.json()
      }
      if (res.status !== 403) throw new Error(`qBit ${path} HTTP ${res.status}`)
      this.noAuth = false
      this.rememberSession()
    }

    await this.login()
    let res = await doFetch(true)
    if (res.status === 403) {
      this.clearSession()
      try {
        await this.login(true)
        res = await doFetch(true)
      } catch (_) {}
    }
    if (res.status === 403) {
      // Retry without auth in case localhost auth is disabled but cookie flow failed.
      res = await doFetch(false)
      if (res.ok) {
        this.noAuth = true
        this.sid = null
        this.rememberSession()
        return expect === 'text' ? res.text() : res.json()
      }
    }
    if (!res.ok) throw new Error(`qBit ${path} HTTP ${res.status}`)
    this.rememberSession()
    return expect === 'text' ? res.text() : res.json()
  }

  async torrents(filter = 'completed') {
    return this.request(`/api/v2/torrents/info?filter=${encodeURIComponent(filter)}`)
  }

  async torrentsByHashes(hashes, filter = 'all') {
    const value = Array.isArray(hashes) ? hashes.join('|') : String(hashes || '')
    return this.request(
      `/api/v2/torrents/info?filter=${encodeURIComponent(filter)}&hashes=${encodeURIComponent(value)}`
    )
  }

  async toggleSequentialDownload(hashes) {
    const value = Array.isArray(hashes) ? hashes.join('|') : String(hashes || '')
    return this.request('/api/v2/torrents/toggleSequentialDownload', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `hashes=${encodeURIComponent(value)}`,
      expect: 'text'
    })
  }

  async toggleFirstLastPiecePrio(hashes) {
    const value = Array.isArray(hashes) ? hashes.join('|') : String(hashes || '')
    return this.request('/api/v2/torrents/toggleFirstLastPiecePrio', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `hashes=${encodeURIComponent(value)}`,
      expect: 'text'
    })
  }

  async setFilePriority(hash, fileIds, priority = 7) {
    const ids = Array.isArray(fileIds) ? fileIds.join('|') : String(fileIds || '')
    return this.request('/api/v2/torrents/filePrio', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `hash=${encodeURIComponent(hash)}&id=${encodeURIComponent(ids)}&priority=${encodeURIComponent(String(priority))}`,
      expect: 'text'
    })
  }

  async files(hash) {
    return this.request(`/api/v2/torrents/files?hash=${encodeURIComponent(hash)}`)
  }

  async properties(hash) {
    return this.request(`/api/v2/torrents/properties?hash=${encodeURIComponent(hash)}`)
  }

  async pieceStates(hash) {
    return this.request(`/api/v2/torrents/pieceStates?hash=${encodeURIComponent(hash)}`)
  }

  async add(magnetOrUrl, options = {}) {
    const params = new URLSearchParams()
    params.set('urls', String(magnetOrUrl || ''))
    if (options.sequentialDownload === true) params.set('sequentialDownload', 'true')
    if (options.firstLastPiecePrio === true) params.set('firstLastPiecePrio', 'true')
    if (options.paused === true) params.set('paused', 'true')

    return this.request('/api/v2/torrents/add', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
      expect: 'text'
    })
  }

  async addTorrentFile(bytes, fileName = 'download.torrent', options = {}) {
    const payload = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes || [])
    if (!payload || payload.length === 0) {
      throw new Error('torrent payload is empty')
    }

    const form = new FormData()
    form.append(
      'torrents',
      new Blob([payload], { type: 'application/x-bittorrent' }),
      String(fileName || 'download.torrent')
    )
    if (options.sequentialDownload === true) form.append('sequentialDownload', 'true')
    if (options.firstLastPiecePrio === true) form.append('firstLastPiecePrio', 'true')
    if (options.paused === true) form.append('paused', 'true')

    return this.request('/api/v2/torrents/add', {
      method: 'POST',
      body: form,
      expect: 'text'
    })
  }

  async delete(hashes, deleteFiles = true) {
    const value = Array.isArray(hashes) ? hashes.join('|') : String(hashes || '')
    return this.request('/api/v2/torrents/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `hashes=${encodeURIComponent(value)}&deleteFiles=${deleteFiles ? 'true' : 'false'}`,
      expect: 'text'
    })
  }

  async preferences() {
    return this.request('/api/v2/app/preferences')
  }

  async setPreferences(prefs) {
    const json = JSON.stringify(prefs || {})
    return this.request('/api/v2/app/setPreferences', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `json=${encodeURIComponent(json)}`,
      expect: 'text'
    })
  }
}

module.exports = { QBitClient }
