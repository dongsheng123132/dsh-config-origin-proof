import assert from 'node:assert/strict'
import { cp, mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { ConfigOriginProofError, inspectConfigOriginInline, verifyConfigOrigin, verifyConfigOriginInline } from '../lib/config-origin-proof.mjs'
const example = await readFile(new URL('../examples/recording.json', import.meta.url), 'utf8')
const fixture = async () => { const root = await mkdtemp(path.join(tmpdir(), 'dsh-config-origin-')); await cp(new URL('../examples/', import.meta.url), root, { recursive: true }); return root }
test('verifies winner and discloses shadowed source without raw values', () => { const result = verifyConfigOriginInline({ recordingJson: example }); assert.equal(result.status, 'verified'); assert.equal(result.claims[0].winnerSourceId, 'user-settings'); assert.deepEqual(result.claims[0].shadowedSourceIds, ['composition']); assert.equal(result.returnsRawValues, false) })
test('detects winner and digest mismatches', () => { const value = JSON.parse(example); value.claims[0].expectedWinnerSourceId = 'composition'; value.claims[0].expectedValueSha256 = 'c'.repeat(64); const result = verifyConfigOriginInline({ recordingJson: JSON.stringify(value) }); assert.equal(result.status, 'failed'); assert.deepEqual(result.findings.map(({ code }) => code), ['WINNER_MISMATCH', 'VALUE_DIGEST_MISMATCH']) })
test('fails closed when a higher-priority source is unobserved', () => { const value = JSON.parse(example); value.claims[0].observations[0].status = 'unobserved'; const result = verifyConfigOriginInline({ recordingJson: JSON.stringify(value) }); assert.equal(result.findings.some(({ code }) => code === 'HIGHER_PRIORITY_SOURCE_UNOBSERVED'), true) })
test('rejects raw or secret-shaped fields', () => { const value = JSON.parse(example); value.claims[0].value = 'raw'; assert.throws(() => verifyConfigOriginInline({ recordingJson: JSON.stringify(value) }), error => error instanceof ConfigOriginProofError && error.code === 'FORBIDDEN_FIELD') })
test('inspect is proof-only and content addressed', () => { const result = inspectConfigOriginInline({ recordingJson: example }); assert.equal(result.filesystemAccess, false); assert.match(result.recordingSha256, /^[a-f0-9]{64}$/) })
test('file verification writes and reads back one content-addressed report', async () => { const root = await fixture(); const result = await verifyConfigOrigin({ workspaceRoot: root, recordingPath: 'recording.json', artifactDir: 'artifacts' }); assert.equal(result.status, 'verified'); assert.equal(result.artifact.verifiedByReadBack, true); assert.equal((await readFile(path.join(root, result.artifact.path), 'utf8')).includes('bbbbbbbb'), true) })
test('rejects traversal', async () => { const root = await fixture(); await assert.rejects(() => verifyConfigOrigin({ workspaceRoot: root, recordingPath: '../recording.json', artifactDir: 'artifacts' }), /escapes workspaceRoot/) })
