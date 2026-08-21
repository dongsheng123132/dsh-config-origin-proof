import { createHash, randomUUID } from 'node:crypto'
import { link, lstat, mkdir, readFile, realpath, unlink, writeFile } from 'node:fs/promises'
import path from 'node:path'

const MAX_BYTES = 4_194_304
const ID = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/
const HASH = /^[a-f0-9]{64}$/
const FORBIDDEN = /^(authorization|secret|token|password|credentialValue|value|content|text|prompt|message|prose)$/i
const sha256 = value => createHash('sha256').update(value).digest('hex')
const stable = value => Array.isArray(value) ? value.map(stable) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])])) : value
const stableJson = value => `${JSON.stringify(stable(value), null, 2)}\n`

export class ConfigOriginProofError extends Error { constructor(code, message) { super(message); this.name = 'ConfigOriginProofError'; this.code = code } }
function object(value, label) { if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ConfigOriginProofError('INVALID_SCHEMA', `${label} must be an object`) }
function noSecrets(value, at = '$') { if (Array.isArray(value)) return value.forEach((item, i) => noSecrets(item, `${at}[${i}]`)); if (!value || typeof value !== 'object') return; for (const [key, child] of Object.entries(value)) { if (FORBIDDEN.test(key)) throw new ConfigOriginProofError('FORBIDDEN_FIELD', `forbidden raw-value field at ${at}.${key}`); noSecrets(child, `${at}.${key}`) } }
function inlineText(value, label) { if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') > MAX_BYTES) throw new ConfigOriginProofError('INPUT_TOO_LARGE', `${label} must be a string of at most ${MAX_BYTES} bytes`); return value }

function parse(recordingJson) {
  const raw = inlineText(recordingJson, 'recordingJson'); let recording
  try { recording = JSON.parse(raw) } catch { throw new ConfigOriginProofError('INVALID_JSON', 'recordingJson is not valid JSON') }
  object(recording, 'recording'); noSecrets(recording)
  if (recording.schemaVersion !== 1) throw new ConfigOriginProofError('INVALID_SCHEMA', 'schemaVersion must be 1')
  object(recording.subject, 'subject'); if (!ID.test(recording.subject.id) || typeof recording.subject.revision !== 'string' || !recording.subject.revision) throw new ConfigOriginProofError('INVALID_SCHEMA', 'subject is invalid')
  if (!Array.isArray(recording.sources) || !recording.sources.length || !Array.isArray(recording.claims)) throw new ConfigOriginProofError('INVALID_SCHEMA', 'sources and claims must be arrays')
  const sources = new Map()
  for (const [i, source] of recording.sources.entries()) { object(source, `sources[${i}]`); if (!ID.test(source.id) || sources.has(source.id) || typeof source.writable !== 'boolean' || !['operator', 'user', 'composition', 'workspace', 'default'].includes(source.trust)) throw new ConfigOriginProofError('INVALID_SCHEMA', `sources[${i}] is invalid or duplicate`); sources.set(source.id, source) }
  object(recording.orders, 'orders'); const orders = new Map()
  for (const domain of ['non-secret', 'credential-reference']) { const order = recording.orders[domain]; if (!Array.isArray(order) || !order.length || new Set(order).size !== order.length || order.some(id => !sources.has(id))) throw new ConfigOriginProofError('INVALID_SCHEMA', `orders.${domain} must be a unique source sequence`); orders.set(domain, order) }
  return { raw, recording, sources, orders }
}

function inspectParsed(context) { return { schemaVersion: 1, operation: 'inspect', returnsRawValues: false, subject: context.recording.subject, recordingSha256: sha256(context.raw), sourceIds: [...context.sources.keys()].sort(), orders: Object.fromEntries(context.orders), claimIds: context.recording.claims.map(({ claimId }) => claimId).sort() } }
function verifyParsed(context) {
  const findings = []; const claims = []; const claimIds = new Set()
  for (const [i, claim] of context.recording.claims.entries()) {
    object(claim, `claims[${i}]`)
    if (!ID.test(claim.claimId) || claimIds.has(claim.claimId) || !['non-secret', 'credential-reference'].includes(claim.domain) || !Array.isArray(claim.observations)) throw new ConfigOriginProofError('INVALID_SCHEMA', `claims[${i}] is invalid or duplicate`)
    claimIds.add(claim.claimId); const order = context.orders.get(claim.domain); const seen = new Set(); const present = new Map()
    for (const [j, observation] of claim.observations.entries()) { object(observation, `claims[${i}].observations[${j}]`); if (!context.sources.has(observation.sourceId) || !order.includes(observation.sourceId) || seen.has(observation.sourceId) || !['present', 'absent', 'unobserved'].includes(observation.status) || (observation.status === 'present' ? !HASH.test(observation.valueSha256) : observation.valueSha256 !== undefined)) throw new ConfigOriginProofError('INVALID_SCHEMA', `claims[${i}].observations[${j}] is invalid`); seen.add(observation.sourceId); if (observation.status === 'present') present.set(observation.sourceId, observation.valueSha256) }
    const winnerSourceId = order.find(id => present.has(id)) ?? null; const winnerValueSha256 = winnerSourceId ? present.get(winnerSourceId) : null
    if (winnerSourceId !== (claim.expectedWinnerSourceId ?? null)) findings.push({ code: 'WINNER_MISMATCH', claimId: claim.claimId, expectedSourceId: claim.expectedWinnerSourceId ?? null, actualSourceId: winnerSourceId })
    if (winnerValueSha256 !== (claim.expectedValueSha256 ?? null)) findings.push({ code: 'VALUE_DIGEST_MISMATCH', claimId: claim.claimId, expectedSha256: claim.expectedValueSha256 ?? null, actualSha256: winnerValueSha256 })
    const unobservedHigherPrioritySourceIds = order.slice(0, winnerSourceId ? order.indexOf(winnerSourceId) : order.length).filter(id => !seen.has(id) || claim.observations.find(item => item.sourceId === id)?.status === 'unobserved')
    if (unobservedHigherPrioritySourceIds.length) findings.push({ code: 'HIGHER_PRIORITY_SOURCE_UNOBSERVED', claimId: claim.claimId, sourceIds: unobservedHigherPrioritySourceIds })
    claims.push({ claimId: claim.claimId, domain: claim.domain, winnerSourceId, winnerValueSha256, shadowedSourceIds: order.filter(id => present.has(id) && id !== winnerSourceId), unobservedHigherPrioritySourceIds })
  }
  return { schemaVersion: 1, operation: 'verify', returnsRawValues: false, subject: context.recording.subject, recordingSha256: sha256(context.raw), status: findings.length ? 'failed' : 'verified', claims, findings }
}

async function safeRoot(root) { const resolved = await realpath(root); const info = await lstat(resolved); if (!info.isDirectory() || info.isSymbolicLink()) throw new ConfigOriginProofError('UNSAFE_PATH', 'workspaceRoot must be a real directory'); return resolved }
async function safeFile(rootValue, relative) { if (typeof relative !== 'string' || !relative || path.isAbsolute(relative)) throw new ConfigOriginProofError('UNSAFE_PATH', 'recordingPath must be workspace-relative'); const root = await safeRoot(rootValue); const target = path.resolve(root, relative); const rel = path.relative(root, target); if (rel.startsWith('..') || path.isAbsolute(rel)) throw new ConfigOriginProofError('UNSAFE_PATH', 'recordingPath escapes workspaceRoot'); const info = await lstat(target); if (!info.isFile() || info.isSymbolicLink() || info.size > MAX_BYTES) throw new ConfigOriginProofError('UNSAFE_PATH', 'recordingPath must be a bounded regular non-symlink file'); return { root, target: await realpath(target) } }
async function artifactDir(rootValue, relative) { if (typeof relative !== 'string' || !relative || path.isAbsolute(relative)) throw new ConfigOriginProofError('UNSAFE_PATH', 'artifactDir must be workspace-relative'); const root = await safeRoot(rootValue); const target = path.resolve(root, relative); const rel = path.relative(root, target); if (rel.startsWith('..') || path.isAbsolute(rel)) throw new ConfigOriginProofError('UNSAFE_PATH', 'artifactDir escapes workspaceRoot'); await mkdir(target, { recursive: true }); const info = await lstat(target); if (!info.isDirectory() || info.isSymbolicLink()) throw new ConfigOriginProofError('UNSAFE_PATH', 'artifactDir must be a real directory'); return { root, target: await realpath(target) } }
async function publish(root, relative, report) { const directory = await artifactDir(root, relative); const body = stableJson(report); const digest = sha256(body); const filename = `config-origin-${digest}.json`; const target = path.join(directory.target, filename); const temporary = path.join(directory.target, `.${filename}.${randomUUID()}.tmp`); try { await writeFile(temporary, body, { flag: 'wx' }); try { await link(temporary, target) } catch (error) { if (error.code !== 'EEXIST') throw error } const reread = await readFile(target, 'utf8'); if (reread !== body || sha256(reread) !== digest) throw new ConfigOriginProofError('WRITE_VERIFY_FAILED', 'artifact read-back failed'); return { path: path.relative(directory.root, target).replaceAll(path.sep, '/'), sha256: digest, bytes: Buffer.byteLength(body), verifiedByReadBack: true } } finally { try { await unlink(temporary) } catch {} } }

export function inspectConfigOriginInline({ recordingJson }) { return { ...inspectParsed(parse(recordingJson)), operation: 'inspect-inline', proofOnly: true, filesystemAccess: false, networkAccess: false } }
export function verifyConfigOriginInline({ recordingJson }) { return { ...verifyParsed(parse(recordingJson)), operation: 'verify-inline', proofOnly: true, filesystemAccess: false, networkAccess: false } }
export async function inspectConfigOrigin({ workspaceRoot = process.cwd(), recordingPath }) { const { target } = await safeFile(workspaceRoot, recordingPath); return inspectParsed(parse(await readFile(target, 'utf8'))) }
export async function verifyConfigOrigin({ workspaceRoot = process.cwd(), recordingPath, artifactDir }) { const { target } = await safeFile(workspaceRoot, recordingPath); const report = verifyParsed(parse(await readFile(target, 'utf8'))); return { ...report, artifact: await publish(workspaceRoot, artifactDir, report) } }
