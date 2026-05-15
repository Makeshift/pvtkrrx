// Build Stremio stream objects - two patterns: on-seedbox and on-tracker

const PVTKRRX_LOGO_URL = 'https://raw.githubusercontent.com/Kepners/pvtkrrx/main/public/logo.png'
const VIDEO_EXTENSIONS = ['.mkv', '.mp4', '.avi', '.wmv', '.ts', '.m4v']
const SAMPLE_HINT_RE = /(^|[\\/.\-_ ])[sS]ample([\\/.\-_ ]|$)|(^|[\\/.\-_ ])[tT]railer([\\/.\-_ ]|$)|(^|[\\/.\-_ ])[pP]review([\\/.\-_ ]|$)|(^|[\\/.\-_ ])[pP]roof([\\/.\-_ ]|$)/
const ARCHIVE_EXT_RE = /\.(?:rar|r\d{2,3}|zip|7z|001)$/i
const RAR_EXT_RE = /\.(?:rar|r\d{2,3}|part\d{1,3}\.rar)$/i
const ARCHIVE_VIDEO_INCLUDE_PATTERNS = ['/\\.(mkv|mp4|avi|wmv|ts|m4v)$/i']
const LEGACY_AVI_TITLE_RE = /(?:^|[ ._\-[\]()])(?:xvid|divx)(?:$|[ ._\-[\]()])|\.avi(?:$|[ ._\-[\]()])/i

function formatSize(bytes) {
  if (!bytes || bytes <= 0) return '0 B'
  if (bytes >= 1e12) return (bytes / 1e12).toFixed(1) + ' TB'
  if (bytes >= 1e9) return (bytes / 1e9).toFixed(1) + ' GB'
  if (bytes >= 1e6) return (bytes / 1e6).toFixed(1) + ' MB'
  return (bytes / 1e3).toFixed(0) + ' KB'
}

function truncateTitle(title, maxLen = 92) {
  const text = String(title || '').replace(/[^\w.\-()[\] ]/g, ' ').replace(/\s+/g, ' ').trim()
  if (!text) return ''
  if (text.length <= maxLen) return text
  return `${text.slice(0, maxLen - 1).trim()}…`
}

function uniqueNonEmpty(values) {
  return [...new Set((values || []).filter(Boolean))]
}

function withExtraDescription(baseText, extraLines = []) {
  const extras = uniqueNonEmpty(extraLines)
  if (!extras.length) return baseText
  return uniqueNonEmpty([baseText, ...extras]).join('\n')
}

function slugToken(value, maxLen = 48) {
  const text = String(value || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
  if (!text) return ''
  return text.slice(0, maxLen)
}

function buildBingeGroup(item, parsed, mode = 'seedbox') {
  const imdbId = String(item?.imdbId || item?.imdb || '').trim().toLowerCase()
  const cleanedTitle = String(item?.title || '')
    .replace(/\bS\d{1,2}E\d{1,3}\b/ig, ' ')
    .replace(/\b\d{1,2}x\d{1,3}\b/ig, ' ')
    .replace(/\bSeason[\s._-]*\d{1,2}\b/ig, ' ')
    .replace(/\bEpisode[\s._-]*\d{1,3}\b/ig, ' ')
  const titleKey = slugToken(cleanedTitle, 40)
  const fallback = slugToken(parsed?.quality || 'unknown', 16) || 'unknown'
  const groupKey = imdbId || titleKey || fallback
  const prefix = mode === 'buffering' ? 'pvtkrrx-buffering' : 'pvtkrrx'
  return `${prefix}-${groupKey}`
}

function formatPeerLabel(seeders, mode) {
  if (mode === 'seedbox') return ''
  const count = Math.max(0, Number(seeders || 0))
  return count > 0 ? `Peers: ${count}` : 'ZERO PEERS'
}

function detectContainerLabel(...values) {
  for (const value of values) {
    const match = String(value || '').toLowerCase().match(/\.(mkv|mp4|avi|wmv|ts|m4v|mov|rar|zip|7z|001|r\d{2,3})(?:$|[^\w])/i)
    if (!match) continue
    const normalized = String(match[1] || '').toLowerCase()
    if (normalized === '001') return 'ARCHIVE'
    return normalized.toUpperCase()
  }
  return 'VIDEO'
}

function buildStateBadge(mode, options = {}) {
  if (options.extracted === true) return '📦'
  if (mode === 'seedbox') return '✅'
  if (mode === 'buffering') return '⏳'
  return '⬇️'
}

function buildStateLabel(mode, options = {}, progressPercent = null) {
  if (options.extracted === true) return 'Downloaded and extracted'
  if (mode === 'seedbox') return 'Downloaded — ready to play'
  if (mode === 'buffering') return `Buffering ${Number.isFinite(progressPercent) ? progressPercent : 0}%`
  return 'Download and play'
}

function buildStreamName(parsed, mode, fileName = '', options = {}) {
  const badge = buildStateBadge(mode, options)
  const container = detectContainerLabel(fileName, parsed?.container, parsed?.titleHint, parsed?.title)
  const quality = parsed?.quality || 'AUTO'
  const shortSource = parsed?.source || ''
  const shortCodec = parsed?.codec || ''
  const tech = uniqueNonEmpty([shortSource, shortCodec]).join(' ')
  const tag = String(options.sourceTag || '').trim()
  const tagSegment = tag ? ` ${tag}` : ''
  return tech
    ? `PVTKRRX ${badge}${tagSegment} ${quality} ${tech} 🎬${container}`
    : `PVTKRRX ${badge}${tagSegment} ${quality} 🎬${container}`
}

function buildDescription(item, parsed, mode, progressPercent = null, fileName = '', options = {}) {
  const title = truncateTitle(item.title)
  const tech = uniqueNonEmpty([parsed.codec, parsed.hdr, parsed.bitDepth]).join(' • ')
  const source = uniqueNonEmpty([
    parsed.source,
    parsed.remux ? 'REMUX' : '',
    parsed.audio ? `🔊 ${parsed.audio}` : ''
  ]).join(' • ')

  const modeLabel = buildStateLabel(mode, options, progressPercent)

  const peerLabel = formatPeerLabel(item.seeders, mode)
  const stats = uniqueNonEmpty([
    modeLabel,
    peerLabel,
    `💾 ${formatSize(item.size)}`,
    item.indexer ? `🛰 ${item.indexer}` : '',
    parsed.languages ? `🌐 ${parsed.languages}` : ''
  ]).join(' | ')
  const enrichedStats = uniqueNonEmpty([
    modeLabel,
    options.sourceLabel ? `Source: ${options.sourceLabel}` : '',
    `Format: ${detectContainerLabel(fileName, parsed?.container, parsed?.titleHint, parsed?.title)}`,
    peerLabel,
    `Size: ${formatSize(item.size)}`,
    item.indexer ? `Indexer: ${item.indexer}` : '',
    parsed.languages ? `Lang: ${parsed.languages}` : ''
  ]).join(' | ')

  const detailLine = uniqueNonEmpty([tech, source]).join(' | ')
  if (!title) return detailLine ? `${detailLine}\n${enrichedStats}` : enrichedStats
  return detailLine ? `${title}\n${detailLine}\n${enrichedStats}` : `${title}\n${enrichedStats}`
}

function buildOnSeedboxStream(item, fileUrl, fileName, videoSize, config, parsed, options = {}) {
  const containerLabel = detectContainerLabel(fileName, parsed?.container, parsed?.titleHint, parsed?.title)
  const stream = {
    name: buildStreamName(parsed, 'seedbox', fileName, options),
    description: buildDescription(item, parsed, 'seedbox', null, fileName, options),
    url: fileUrl,
    thumbnail: PVTKRRX_LOGO_URL,
    behaviorHints: {
      notWebReady: false,
      bingeGroup: buildBingeGroup(item, parsed, 'seedbox'),
      filename: fileName,
      sourceSeeders: Math.max(0, Number(item.seeders || 0)),
      sourceCodec: String(parsed?.codec || ''),
      sourceHdr: String(parsed?.hdr || ''),
      sourceQuality: String(parsed?.quality || ''),
      sourceSize: Math.max(0, Number(videoSize || item?.size || 0)),
      sourceMode: 'seedbox',
      sourceContainer: containerLabel.toLowerCase(),
      sourceOrigin: String(options.sourceOrigin || ''),
      sourceOriginLabel: String(options.sourceLabel || '')
    }
  }

  if (videoSize) stream.behaviorHints.videoSize = videoSize

  if (config.fileServerAuth) {
    const encoded = Buffer.from(config.fileServerAuth).toString('base64')
    stream.behaviorHints.proxyHeaders = {
      request: { Authorization: `Basic ${encoded}` }
    }
  }

  return stream
}

function buildOnBufferingStream(item, fileUrl, fileName, videoSize, config, parsed, progressPercent, options = {}) {
  const containerLabel = detectContainerLabel(fileName, parsed?.container, parsed?.titleHint, parsed?.title)
  const stream = {
    name: buildStreamName(parsed, 'buffering', fileName, options),
    description: buildDescription(item, parsed, 'buffering', progressPercent, fileName, options),
    url: fileUrl,
    thumbnail: PVTKRRX_LOGO_URL,
    behaviorHints: {
      notWebReady: false,
      bingeGroup: buildBingeGroup(item, parsed, 'buffering'),
      filename: fileName,
      sourceSeeders: Math.max(0, Number(item.seeders || 0)),
      sourceCodec: String(parsed?.codec || ''),
      sourceHdr: String(parsed?.hdr || ''),
      sourceQuality: String(parsed?.quality || ''),
      sourceSize: Math.max(0, Number(videoSize || item?.size || 0)),
      sourceMode: 'buffering',
      sourceContainer: containerLabel.toLowerCase(),
      sourceOrigin: String(options.sourceOrigin || ''),
      sourceOriginLabel: String(options.sourceLabel || '')
    }
  }

  if (videoSize) stream.behaviorHints.videoSize = videoSize
  if (config.fileServerAuth) {
    const encoded = Buffer.from(config.fileServerAuth).toString('base64')
    stream.behaviorHints.proxyHeaders = {
      request: { Authorization: `Basic ${encoded}` }
    }
  }

  return stream
}

function buildOnTrackerStream(item, playbackUrl, parsed, options = {}) {
  const safeName = (item.title || 'download').replace(/[^\w.\-()[\] ]/g, '')
  const fileName = `${safeName}.torrent`
  return {
    name: buildStreamName(parsed, 'tracker', fileName, options),
    description: buildDescription(item, parsed, 'tracker', null, fileName, options),
    url: playbackUrl,
    thumbnail: PVTKRRX_LOGO_URL,
    behaviorHints: {
      notWebReady: true,
      filename: fileName,
      sourceSeeders: Math.max(0, Number(item.seeders || 0)),
      sourceCodec: String(parsed?.codec || ''),
      sourceHdr: String(parsed?.hdr || ''),
      sourceQuality: String(parsed?.quality || ''),
      sourceSize: Math.max(0, Number(item?.size || 0)),
      sourceMode: 'tracker',
      sourceContainer: detectContainerLabel(item?.title || safeName).toLowerCase(),
      sourceOrigin: String(options.sourceOrigin || ''),
      sourceOriginLabel: String(options.sourceLabel || '')
    }
  }
}

function buildOnArchiveStream(item, rarUrls, fileName, totalBytes, parsed, progressPercent = null, options = {}) {
  const buffering = Number.isFinite(progressPercent) && progressPercent < 100
  const mode = buffering ? 'buffering' : 'seedbox'
  return {
    name: buildStreamName(parsed, mode, fileName, options),
    description: withExtraDescription(
      buildDescription(item, parsed, mode, progressPercent, fileName, options),
      ['Multi-part RAR archive stream']
    ),
    rarUrls,
    thumbnail: PVTKRRX_LOGO_URL,
    fileMustInclude: [...ARCHIVE_VIDEO_INCLUDE_PATTERNS],
    behaviorHints: {
      notWebReady: true,
      bingeGroup: buildBingeGroup(item, parsed, mode),
      filename: fileName,
      sourceSeeders: Math.max(0, Number(item.seeders || 0)),
      sourceCodec: String(parsed?.codec || ''),
      sourceHdr: String(parsed?.hdr || ''),
      sourceQuality: String(parsed?.quality || ''),
      sourceSize: Math.max(0, Number(totalBytes || item?.size || 0)),
      sourceMode: mode,
      sourceContainer: 'rar',
      sourceOrigin: String(options.sourceOrigin || ''),
      sourceOriginLabel: String(options.sourceLabel || '')
    }
  }
}

function buildInfoStream(code, helpUrl, count = 1) {
  const total = Math.max(1, Number(count || 0))
  let name = '[INFO] PVTKRRX'
  let description = 'Playback note'
  const noun = total === 1 ? 'option' : 'options'
  const verb = total === 1 ? 'was' : 'were'

  if (code === 'hosted-ready-only') {
    name = '[INFO] Ready Files Only'
    description = withExtraDescription(
      'This hosted Remote Seedbox route only shows files that are already ready to play.',
      [
        `${total} download ${noun} ${verb} hidden because this hosted route cannot queue and buffer downloads.`,
        'Use PC Local, LAN Bridge, or self-hosted playback if you want queue-and-buffer streams.'
      ]
    )
  } else if (code === 'auth-suppressed') {
    name = '[INFO] Direct Buffer Hidden'
    description = withExtraDescription(
      'Direct queue-and-buffer is hidden here to protect your file-server login.',
      [
        `${total} download ${noun} ${verb} hidden because this hosted route cannot safely forward your file-server login during playback redirects.`,
        'Ready files can still play. Remove file-server auth or self-host playback if you want queue-and-buffer.'
      ]
    )
  } else if (code === 'buffering-path-unproven') {
    name = '[INFO] Buffer URL Not Ready'
    description = withExtraDescription(
      'Not enough live file info is available yet for a safe buffer URL.',
      [
        `${total} buffering ${noun} ${verb} hidden until qBittorrent exposes the current file path for the file being downloaded.`,
        'Wait for more progress, or use PC Local, LAN Bridge, or self-hosted playback for local queue-and-buffer.'
      ]
    )
  } else if (code === 'packed-archive-pending') {
    name = '[INFO] Packed Release Downloading'
    description = withExtraDescription(
      'This source is a multi-part RAR release and is still downloading.',
      [
        `${total} packed-release ${noun} ${verb} hidden until every archive volume is available for Stremio to open safely.`,
        'Choose a direct WEB-DL/REMUX source now, or wait until the packed release finishes downloading.'
      ]
    )
  } else if (code === 'packed-archive-live-unsupported') {
    name = '[INFO] Packed Release Needs Full Download'
    description = withExtraDescription(
      'This source is a multi-part RAR scene release, not a direct video file.',
      [
        `${total} packed-release ${noun} ${verb} not offered as live playback because this Stremio path cannot reliably start a partial multi-volume archive while it is still downloading.`,
        'Choose a direct WEB-DL/REMUX source for instant playback, or wait until the packed release fully downloads and PVTKRRX can surface a normal direct-play file.'
      ]
    )
  } else if (code === 'packed-archive-extracting') {
    name = '[INFO] Packed Release Extracting'
    description = withExtraDescription(
      'This completed packed release is being unpacked on the host for broader playback support.',
      [
        `${total} packed-release ${noun} ${verb} queued for background extraction so phones, tablets, and TVs can use a normal direct video file.`,
        'Refresh the stream list shortly for the extracted direct-play stream.'
      ]
    )
  } else if (code === 'packed-archive-extractor-unavailable') {
    name = '[INFO] Archive Extraction Unavailable'
    description = withExtraDescription(
      'This host could not prepare a normal direct-play file for this completed packed release.',
      [
        `${total} packed-release ${noun} ${verb} hidden because PVTKRRX only treats extracted direct video as supported playback by default.`,
        'Use another source now, or fix host-side archive extraction and refresh for the direct-play stream.'
      ]
    )
  } else if (code === 'tracker-link-unverified') {
    name = '[INFO] Source Verification Failed'
    description = withExtraDescription(
      'Some tracker download URLs could not be verified safely before playback.',
      [
        `${total} stream ${noun} ${verb} hidden because PVTKRRX could not fetch and inspect the tracker payload ahead of time.`,
        'Refresh later or choose another source that can be verified and queued safely.'
      ]
    )
  } else if (code === 'legacy-avi-suppressed') {
    name = '[INFO] AVI Source Hidden'
    description = withExtraDescription(
      'A legacy AVI/XviD/DivX source was hidden because Stremio failed to start that format reliably.',
      [
        `${total} legacy video ${noun} ${verb} skipped so playback selection favours MKV/MP4-style sources that can actually start.`,
        'Choose a WEB-DL, WEBRip, HDTV, MKV, or MP4 source instead.'
      ]
    )
  }

  return {
    name,
    description,
    externalUrl: helpUrl,
    behaviorHints: {
      sourceMode: 'notice',
      sourceNoticeCode: String(code || ''),
      sourceSeeders: 0,
      sourceSize: 0
    }
  }
}

// Find the main video file in a list of torrent files
function isVideoFileName(name) {
  const value = String(name || '').toLowerCase()
  return VIDEO_EXTENSIONS.some(ext => value.endsWith(ext))
}

function titleLooksLegacyAvi(title) {
  return LEGACY_AVI_TITLE_RE.test(String(title || ''))
}

function isLegacyAviVideoName(name) {
  const value = String(name || '').toLowerCase()
  return value.endsWith('.avi') || titleLooksLegacyAvi(value)
}

function hasLegacyAviVideoFiles(files) {
  return (Array.isArray(files) ? files : []).some(file => {
    const name = String(file?.name || '')
    return isVideoFileName(name) && isLegacyAviVideoName(name) && !isSampleVideoName(name)
  })
}

function isSampleVideoName(name) {
  return SAMPLE_HINT_RE.test(String(name || ''))
}

function isArchiveFileName(name) {
  return ARCHIVE_EXT_RE.test(String(name || '').toLowerCase())
}

function hasPackedArchiveFiles(files) {
  return (files || []).some(f => isArchiveFileName(f?.name))
}

function archiveVolumeSortKey(name) {
  const normalized = String(name || '').replace(/[\\/]+/g, '/').toLowerCase()
  const basename = normalized.split('/').pop() || normalized

  let match = basename.match(/^(.*)\.part(\d{1,4})\.rar$/i)
  if (match) {
    return {
      stem: match[1],
      volume: Math.max(0, Number.parseInt(match[2], 10) - 1),
      fallback: basename
    }
  }

  match = basename.match(/^(.*)\.rar$/i)
  if (match) {
    return {
      stem: match[1],
      volume: 0,
      fallback: basename
    }
  }

  match = basename.match(/^(.*)\.r(\d{2,3})$/i)
  if (match) {
    return {
      stem: match[1],
      volume: Number.parseInt(match[2], 10) + 1,
      fallback: basename
    }
  }

  return {
    stem: basename,
    volume: Number.MAX_SAFE_INTEGER,
    fallback: basename
  }
}

function findPackedArchiveFiles(files) {
  return (Array.isArray(files) ? files : [])
    .filter(f => RAR_EXT_RE.test(String(f?.name || '').toLowerCase()))
    .sort((a, b) => {
      const left = archiveVolumeSortKey(a?.name)
      const right = archiveVolumeSortKey(b?.name)
      const stemDiff = left.stem.localeCompare(right.stem, undefined, { numeric: true, sensitivity: 'base' })
      if (stemDiff !== 0) return stemDiff
      if (left.volume !== right.volume) return left.volume - right.volume
      return left.fallback.localeCompare(right.fallback, undefined, { numeric: true, sensitivity: 'base' })
    })
}

function arePackedArchiveFilesReady(files) {
  const archiveFiles = findPackedArchiveFiles(files)
  return archiveFiles.length > 0 && archiveFiles.every(file => Number(file?.progress || 0) >= 0.999)
}

function pickLargestFile(files) {
  if (!Array.isArray(files) || files.length === 0) return null
  return files.reduce((a, b) => Number(a?.size || 0) > Number(b?.size || 0) ? a : b)
}

function findVideoFile(files, options = {}) {
  const list = Array.isArray(files) ? files : []
  if (list.length === 0) return null

  const videoFiles = list.filter(f => isVideoFileName(f?.name) && !isLegacyAviVideoName(f?.name))
  if (videoFiles.length === 0) return null

  const nonSample = videoFiles.filter(f => !isSampleVideoName(f?.name))
  if (nonSample.length > 0) return pickLargestFile(nonSample)

  // Packed scene releases often contain only Sample/*.mkv plus .rar parts.
  // Avoid selecting sample files as the main playback target in that case.
  if (hasPackedArchiveFiles(list) && options.allowSampleFallback !== true) return null
  return pickLargestFile(videoFiles)
}

// Find a specific episode file in a season pack
function findEpisodeFile(files, season, episode) {
  const seasonNum = Number.parseInt(String(season || ''), 10)
  const episodeNum = Number.parseInt(String(episode || ''), 10)
  if (!Number.isFinite(seasonNum) || !Number.isFinite(episodeNum)) return null

  const videoFiles = (Array.isArray(files) ? files : []).filter(f =>
    VIDEO_EXTENSIONS.some(ext => String(f.name || '').toLowerCase().endsWith(ext)) &&
    !isLegacyAviVideoName(f.name)
  )
  if (videoFiles.length === 0) return null

  const seRegex = new RegExp(`\\bS0?${seasonNum}[ ._-]*E0?${episodeNum}\\b`, 'i')
  const xRegex = new RegExp(`\\b${seasonNum}x0?${episodeNum}\\b`, 'i')
  const seasonEpisodeRegex = new RegExp(`\\bSeason[ ._-]*${seasonNum}[ ._-]*Episode[ ._-]*${episodeNum}\\b`, 'i')
  const episodeOnlyRegex = new RegExp(`\\bEpisode[ ._-]*0?${episodeNum}\\b`, 'i')

  let best = null
  let bestScore = -1
  for (const file of videoFiles) {
    const name = String(file?.name || '')
    const lowerName = name.toLowerCase()
    let score = -1
    if (seRegex.test(name)) score = 100
    else if (xRegex.test(name)) score = 95
    else if (seasonEpisodeRegex.test(name)) score = 85
    else if (episodeOnlyRegex.test(name)) score = 30
    else continue

    if (!isSampleVideoName(lowerName)) score += 5
    score += Math.min(20, Number(file?.size || 0) / 1e9)

    if (score > bestScore) {
      best = file
      bestScore = score
    }
  }

  if (best) return best

  // Avoid returning the wrong episode from multi-file season packs.
  if (videoFiles.length === 1) return videoFiles[0]
  return null
}

// Sort: on-seedbox first, then non-zero peers first within each group.
function sortStreams(streams) {
  function seeders(stream) {
    return Math.max(0, Number(stream?.behaviorHints?.sourceSeeders || 0))
  }

  function compatibilityRank(stream) {
    const codec = String(stream?.behaviorHints?.sourceCodec || '').toLowerCase()
    const hdr = String(stream?.behaviorHints?.sourceHdr || '').toLowerCase()
    const text = `${stream?.name || ''} ${stream?.description || ''}`.toLowerCase()
    const combined = `${codec} ${hdr} ${text}`

    const hasDv = /\bdolby\s*vision\b|\bdv\b/.test(combined)
    const hasH265 = /\bhevc\b|\bh265\b|\bx265\b/.test(combined)
    const hasAv1 = /\bav1\b/.test(combined)
    const hasH264 = /\bavc\b|\bh264\b|\bx264\b/.test(combined)

    // Lower rank is better (more compatible with typical desktop/mobile decoders).
    if (hasH264 && !hasDv) return 0
    if (hasH265 || hasAv1) return hasDv ? 3 : 2
    if (hasDv) return 3
    return 1
  }

  function rank(stream) {
    const mode = String(stream?.behaviorHints?.sourceMode || '').toLowerCase()
    if (mode === 'seedbox') return 0
    if (mode === 'buffering') return 1
    if (mode === 'tracker') return 2
    if (mode === 'notice') return 3
    const streamName = String(stream?.name || '')
    if (streamName.includes('[EXTRACTED]') || streamName.includes('[DL]') || streamName.includes('[SB]')) return 0
    if (streamName.includes('[BUF]')) return 1
    return 2
  }

  function qualityScore(stream) {
    const hint = String(stream?.behaviorHints?.sourceQuality || '').toLowerCase()
    const name = String(stream?.name || '').toLowerCase()
    const text = `${hint} ${name}`
    if (/\b2160p\b|\b4k\b/.test(text)) return 3
    if (/\b1080p\b/.test(text)) return 2
    if (/\b720p\b/.test(text)) return 1
    return 0
  }

  function sizeBytes(stream) {
    return Math.max(0, Number(stream?.behaviorHints?.sourceSize || stream?.behaviorHints?.videoSize || 0))
  }

  return streams.sort((a, b) => {
    const ra = rank(a)
    const rb = rank(b)
    if (ra !== rb) return ra - rb

    // Local-ready sources stay at the very top irrespective of quality.
    if (ra === 0) {
      const za = sizeBytes(a)
      const zb = sizeBytes(b)
      if (za !== zb) return zb - za
      return 0
    }

    const sa = seeders(a)
    const sb = seeders(b)
    const az = sa > 0 ? 0 : 1
    const bz = sb > 0 ? 0 : 1
    if (az !== bz) return az - bz
    const qa = qualityScore(a)
    const qb = qualityScore(b)
    if (qa !== qb) return qb - qa
    const za = sizeBytes(a)
    const zb = sizeBytes(b)
    if (za !== zb) return zb - za
    if (sa !== sb) return sb - sa
    return 0
  })
}

module.exports = {
  formatSize,
  buildOnSeedboxStream,
  buildOnBufferingStream,
  buildOnArchiveStream,
  buildOnTrackerStream,
  buildInfoStream,
  isSampleVideoName,
  isArchiveFileName,
  hasPackedArchiveFiles,
  findPackedArchiveFiles,
  arePackedArchiveFilesReady,
  findVideoFile,
  findEpisodeFile,
  titleLooksLegacyAvi,
  isLegacyAviVideoName,
  hasLegacyAviVideoFiles,
  sortStreams
}
