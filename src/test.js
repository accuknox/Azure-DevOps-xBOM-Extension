/* eslint-disable */
// Lightweight test harness (no framework) for the AccuKnox xBOM task.
// Stubs XbomScanner.exec to capture argument vectors instead of running knoxctl,
// and asserts the command lines match the accuknox/xbom-action reference.
//
// Run:  node test.js     (build with `npx tsc` first)

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { XbomScanner, releaseTarget } = require('./xbom');
const { validateInputs } = require('./index');

let passed = 0;
let failed = 0;
function check(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  ✓ ${name}`);
  } catch (e) {
    failed++;
    console.error(`  ✗ ${name}\n      ${e.message}`);
  }
}

async function checkAsync(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`  ✓ ${name}`);
  } catch (e) {
    failed++;
    console.error(`  ✗ ${name}\n      ${e.message}`);
  }
}

const baseInputs = {
  bomType: 'sbom',
  scanPath: '.',
  imageRef: '',
  aibomSource: 'huggingface',
  aibomModel: '',
  awsRegion: '',
  awsAccessKeyId: '',
  awsSecretAccessKey: '',
};

/** Scanner with exec stubbed out; captured holds the last argv. */
function stubScanner() {
  const scanner = new XbomScanner({
    endpoint: 'cspm.example.com',
    token: 't',
    label: 'l',
    version: 'v0.10.0',
    skipTlsVerify: false,
  });
  const captured = { args: null, env: null };
  scanner.knoxctlBin = '/fake/knoxctl';
  scanner.exec = (args, extraEnv = {}) => {
    captured.args = args;
    captured.env = extraEnv;
    return Promise.resolve(0);
  };
  return { scanner, captured };
}

async function main() {
  console.log('releaseTarget');

  check('maps the three supported operating systems', () => {
    assert.strictEqual(releaseTarget('linux', 'x64'), 'linux_amd64');
    assert.strictEqual(releaseTarget('darwin', 'arm64'), 'darwin_arm64');
    assert.strictEqual(releaseTarget('win32', 'x64'), 'windows_amd64');
  });

  check('maps both supported architectures', () => {
    assert.strictEqual(releaseTarget('linux', 'arm64'), 'linux_arm64');
    assert.strictEqual(releaseTarget('darwin', 'x64'), 'darwin_amd64');
  });

  check('rejects a platform with no knoxctl build', () => {
    assert.throws(() => releaseTarget('aix', 'x64'), /Unsupported agent platform/);
  });

  check('rejects an architecture with no knoxctl build', () => {
    assert.throws(() => releaseTarget('linux', 'ppc64'), /Unsupported agent architecture/);
  });

  check('rejects windows arm64, which upstream does not publish', () => {
    assert.throws(() => releaseTarget('win32', 'arm64'), /no windows_arm64 build/);
  });

  check('resolves for the agent actually running the tests', () => {
    assert.match(releaseTarget(), /^(linux|darwin|windows)_(amd64|arm64)$/);
  });

  console.log('validateInputs');

  check('accepts a plain SBOM', () => {
    assert.strictEqual(validateInputs({ ...baseInputs }), null);
  });

  check('rejects an unknown bomType', () => {
    const err = validateInputs({ ...baseInputs, bomType: 'xbom' });
    assert.match(err, /bomType must be one of/);
  });

  check('rejects an unknown aibomSource', () => {
    const err = validateInputs({ ...baseInputs, bomType: 'aibom', aibomSource: 'openai' });
    assert.match(err, /aibomSource must be one of/);
  });

  check('requires aibomModel for huggingface', () => {
    const err = validateInputs({ ...baseInputs, bomType: 'aibom' });
    assert.match(err, /aibomModel is required/);
  });

  check('requires AWS credentials for bedrock', () => {
    const err = validateInputs({ ...baseInputs, bomType: 'aibom', aibomSource: 'bedrock', awsRegion: 'us-east-1' });
    assert.match(err, /awsRegion, awsAccessKeyId and awsSecretAccessKey are required/);
  });

  check('accepts a complete bedrock config', () => {
    const ok = validateInputs({
      ...baseInputs,
      bomType: 'aibom',
      aibomSource: 'bedrock',
      awsRegion: 'us-east-1',
      awsAccessKeyId: 'AKIA',
      awsSecretAccessKey: 'secret',
    });
    assert.strictEqual(ok, null);
  });

  console.log('generate');

  await checkAsync('SBOM from filesystem scans the path', async () => {
    const { scanner, captured } = stubScanner();
    await scanner.generate({ ...baseInputs, scanPath: 'src' }, '/out/bom.json');
    assert.deepStrictEqual(captured.args, [
      'pkgscan', 'scan', 'src', '-o', 'cyclonedx-json=/out/bom.json', '--quiet',
    ]);
  });

  await checkAsync('SBOM prefers the image over the path', async () => {
    const { scanner, captured } = stubScanner();
    await scanner.generate({ ...baseInputs, scanPath: 'src', imageRef: 'myapp:abc' }, '/out/bom.json');
    assert.strictEqual(captured.args[2], 'myapp:abc');
  });

  await checkAsync('CBOM picks the image subcommand when an image is set', async () => {
    const { scanner, captured } = stubScanner();
    await scanner.generate({ ...baseInputs, bomType: 'cbom', imageRef: 'myapp:abc' }, '/out/bom.json');
    assert.deepStrictEqual(captured.args, [
      'cbom', 'image', '--image', 'myapp:abc', '--out', '/out/bom.json', '--format', 'json',
    ]);
  });

  await checkAsync('CBOM falls back to the source subcommand', async () => {
    const { scanner, captured } = stubScanner();
    await scanner.generate({ ...baseInputs, bomType: 'cbom' }, '/out/bom.json');
    assert.strictEqual(captured.args[1], 'source');
  });

  await checkAsync('AIBOM bedrock keeps credentials out of argv', async () => {
    const { scanner, captured } = stubScanner();
    await scanner.generate(
      {
        ...baseInputs,
        bomType: 'aibom',
        aibomSource: 'bedrock',
        awsRegion: 'us-east-1',
        awsAccessKeyId: 'AKIA',
        awsSecretAccessKey: 'secret',
      },
      '/out/bom.json'
    );
    assert.ok(!captured.args.includes('AKIA'), 'access key leaked into argv');
    assert.ok(!captured.args.includes('secret'), 'secret key leaked into argv');
    assert.strictEqual(captured.env.AWS_ACCESS_KEY_ID, 'AKIA');
    assert.strictEqual(captured.env.AWS_SECRET_ACCESS_KEY, 'secret');
  });

  console.log('validate / patch');

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'xbom-test-'));
  const bomPath = path.join(tmp, 'bom.json');

  check('validate rejects a missing file', () => {
    const { scanner } = stubScanner();
    assert.throws(() => scanner.validate(path.join(tmp, 'nope.json')), /BOM file not found/);
  });

  check('validate rejects a truncated file', () => {
    const { scanner } = stubScanner();
    fs.writeFileSync(bomPath, '{}');
    assert.throws(() => scanner.validate(bomPath), /suspiciously small/);
  });

  check('validate rejects malformed JSON', () => {
    const { scanner } = stubScanner();
    fs.writeFileSync(bomPath, 'not json'.padEnd(80, '!'));
    assert.throws(() => scanner.validate(bomPath), /not valid JSON/);
  });

  check('patch stamps project fields and keeps $schema first', () => {
    const { scanner } = stubScanner();
    fs.writeFileSync(
      bomPath,
      JSON.stringify({
        $schema: 'https://cyclonedx.org/schema/bom-1.6.schema.json',
        bomFormat: 'CycloneDX',
        metadata: { component: { name: '.' } },
      })
    );
    const bom = scanner.validate(bomPath);
    scanner.patch(bom, bomPath, { projectName: 'proj', projectClassifier: 'application', imageRef: '' });

    const out = JSON.parse(fs.readFileSync(bomPath, 'utf8'));
    assert.deepStrictEqual(Object.keys(out).slice(0, 3), ['$schema', 'project_name', 'project_classifier']);
    assert.strictEqual(out.project_name, 'proj');
    assert.strictEqual(out.project_classifier, 'application');
    // "." is replaced with the repo name so the Console shows something meaningful.
    assert.notStrictEqual(out.metadata.component.name, '.');
  });

  check('patch preserves the full image reference including the tag', () => {
    const { scanner } = stubScanner();
    fs.writeFileSync(
      bomPath,
      JSON.stringify({ bomFormat: 'CycloneDX', metadata: { component: { name: 'myapp' } } })
    );
    const bom = scanner.validate(bomPath);
    scanner.patch(bom, bomPath, { projectName: 'p', projectClassifier: 'container', imageRef: 'myapp:v1.0.0' });

    const out = JSON.parse(fs.readFileSync(bomPath, 'utf8'));
    assert.strictEqual(out.metadata.component.name, 'myapp:v1.0.0');
    assert.ok(!('$schema' in out), 'must not invent a $schema key');
  });

  fs.rmSync(tmp, { recursive: true, force: true });

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
}

main();
