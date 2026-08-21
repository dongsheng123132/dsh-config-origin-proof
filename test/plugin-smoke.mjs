import assert from 'node:assert/strict'
import { cp, mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import * as plugin from '../index.js'
const root = await mkdtemp(path.join(tmpdir(), 'dsh-config-origin-plugin-')); await cp(new URL('../examples/', import.meta.url), root, { recursive: true }); const tools = plugin.createDefinitions({}, { workspaceRoot: root })
assert.deepEqual(plugin.inject, ['tools']); assert.equal('default' in plugin, false); assert.deepEqual(tools.map(({ name }) => name), ['dsh_config_origin_inspect', 'dsh_config_origin_verify']); const result = await tools[1].execute({ recordingPath: 'recording.json', artifactDir: 'artifacts' }); assert.equal(result.status, 'verified'); assert.equal(result.artifact.verifiedByReadBack, true); console.log(JSON.stringify({ ok: true, hostNeutral: true, tools: tools.map(({ name }) => name), status: result.status }))
