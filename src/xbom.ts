import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as https from 'https';
import { spawn } from 'child_process';

const KNOXCTL_BASE_URL = 'https://github.com/accuknox/accuknox-cli-v2/releases/download';

/**
 * The <os>_<arch> segment of the knoxctl release asset name, for the agent we
 * are running on. Releases carry linux/darwin (amd64 + arm64) and windows
 * (amd64 only), so an arm64 Windows agent has nothing to download.
 */
export function releaseTarget(platform: string = process.platform, arch: string = process.arch): string {
  const osName = { linux: 'linux', darwin: 'darwin', win32: 'windows' }[platform];
  if (!osName) {
    throw new Error(`Unsupported agent platform '${platform}'. knoxctl ships linux, darwin and windows builds.`);
  }

  const archName = { x64: 'amd64', arm64: 'arm64' }[arch];
  if (!archName) {
    throw new Error(`Unsupported agent architecture '${arch}'. knoxctl ships amd64 and arm64 builds.`);
  }

  if (osName === 'windows' && archName !== 'amd64') {
    throw new Error(`knoxctl has no windows_${archName} build. Use an amd64 Windows agent, or a Linux agent.`);
  }

  return `${osName}_${archName}`;
}

export interface XbomConfig {
  endpoint: string;
  token: string;
  label: string;
  version: string;
  skipTlsVerify: boolean;
}

export interface GenerateInputs {
  bomType: string;
  scanPath: string;
  imageRef: string;
  aibomSource: string;
  aibomModel: string;
  awsRegion: string;
  awsAccessKeyId: string;
  awsSecretAccessKey: string;
}

export interface PatchInputs {
  projectName: string;
  projectClassifier: string;
  imageRef: string;
}

export class XbomScanner {
  private cfg: XbomConfig;
  private knoxctlBin: string = '';

  readonly repoName: string;

  constructor(cfg: XbomConfig) {
    this.cfg = cfg;
    // BUILD_REPOSITORY_NAME is "project/repo" on some providers; keep the last segment.
    this.repoName = (process.env.BUILD_REPOSITORY_NAME || 'repo').split('/').pop() as string;
  }

  /** Default BOM path when the user does not supply one: <repo>-<bom-type>.json */
  defaultOutputFile(bomType: string): string {
    const dir = process.env.BUILD_SOURCESDIRECTORY || process.cwd();
    return path.join(dir, `${this.repoName}-${bomType}.json`);
  }

  /** Download and extract the knoxctl binary once. */
  async setup(): Promise<void> {
    const semver = this.cfg.version.replace(/^v/, '');
    const binDir = path.join(os.tmpdir(), 'knoxctl-bin');
    const tarball = path.join(os.tmpdir(), 'knoxctl.tar.gz');
    const url = `${KNOXCTL_BASE_URL}/${this.cfg.version}/knoxctl_${semver}_${releaseTarget()}.tar.gz`;

    fs.mkdirSync(binDir, { recursive: true });
    console.log(`Downloading knoxctl ${this.cfg.version} for ${releaseTarget()}...`);
    await this.download(url, tarball);

    // ponytail: shelling out to tar beats pulling in a tar library. bsdtar ships
    // in Windows Server 2019+ and every macOS/Linux image, so this is portable.
    const code = await this.spawnAndWait('tar', ['-xzf', tarball, '-C', binDir], process.env);
    if (code !== 0) {
      throw new Error(`Failed to extract knoxctl archive (tar exited ${code}).`);
    }

    const bin = path.join(binDir, process.platform === 'win32' ? 'knoxctl.exe' : 'knoxctl');
    if (!fs.existsSync(bin)) {
      throw new Error(`knoxctl not found at ${bin} after extraction.`);
    }
    if (process.platform !== 'win32') {
      fs.chmodSync(bin, 0o755);
    }
    this.knoxctlBin = bin;
    console.log(`knoxctl installed at ${bin}`);
    await this.exec(['version']);
  }

  private download(url: string, dest: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const file = fs.createWriteStream(dest);
      const request = (currentUrl: string, redirects: number) => {
        if (redirects > 10) {
          reject(new Error('Too many redirects while downloading knoxctl.'));
          return;
        }
        https
          .get(currentUrl, (res) => {
            if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
              res.resume();
              request(res.headers.location, redirects + 1);
              return;
            }
            if (res.statusCode !== 200) {
              res.resume();
              reject(new Error(`Failed to download knoxctl. HTTP ${res.statusCode}`));
              return;
            }
            res.pipe(file);
            file.on('finish', () => file.close(() => resolve()));
          })
          .on('error', (err) => {
            fs.unlink(dest, () => reject(err));
          });
      };
      request(url, 0);
    });
  }

  private spawnAndWait(cmd: string, args: string[], env: NodeJS.ProcessEnv): Promise<number> {
    return new Promise((resolve) => {
      const child = spawn(cmd, args, { env, stdio: 'inherit', shell: false });
      child.on('error', (err) => {
        console.error(`Failed to start ${cmd}: ${err.message}`);
        resolve(1);
      });
      child.on('close', (code) => resolve(code === null ? 1 : code));
    });
  }

  /** Run knoxctl with the given args; resolves the exit code. */
  private exec(args: string[], extraEnv: NodeJS.ProcessEnv = {}): Promise<number> {
    if (!this.knoxctlBin) {
      throw new Error('knoxctl not set up. Call setup() first.');
    }
    console.log(`Executing: knoxctl ${args.join(' ')}`);
    return this.spawnAndWait(this.knoxctlBin, args, { ...process.env, ...extraEnv });
  }

  /** Generate the requested BOM into bomFile. Resolves the knoxctl exit code. */
  async generate(i: GenerateInputs, bomFile: string): Promise<number> {
    switch (i.bomType) {
      case 'sbom': {
        const source = i.imageRef || i.scanPath;
        console.log(`SBOM source: ${source}`);
        return this.exec(['pkgscan', 'scan', source, '-o', `cyclonedx-json=${bomFile}`, '--quiet']);
      }

      case 'cbom': {
        if (i.imageRef) {
          console.log(`CBOM scanning image: ${i.imageRef}`);
          return this.exec(['cbom', 'image', '--image', i.imageRef, '--out', bomFile, '--format', 'json']);
        }
        console.log(`CBOM scanning source: ${i.scanPath}`);
        return this.exec(['cbom', 'source', i.scanPath, '--out', bomFile, '--format', 'json']);
      }

      case 'aibom': {
        if (i.aibomSource === 'bedrock') {
          console.log(`AIBOM scanning AWS Bedrock in region: ${i.awsRegion}`);
          // Credentials go through the environment, never argv — argv is world-readable via ps.
          return this.exec(
            ['aibom', 'bedrock', '--region', i.awsRegion, '--out', bomFile, '--format', 'json'],
            {
              AWS_ACCESS_KEY_ID: i.awsAccessKeyId,
              AWS_SECRET_ACCESS_KEY: i.awsSecretAccessKey,
              AWS_REGION: i.awsRegion,
            }
          );
        }
        console.log(`AIBOM scanning model: ${i.aibomModel}`);
        return this.exec(['aibom', 'generate', '--model', i.aibomModel, '--out', bomFile, '--format', 'json']);
      }

      default:
        throw new Error(`Unknown bomType '${i.bomType}'.`);
    }
  }

  /** Fail loudly if the scan produced nothing usable. Returns the parsed BOM. */
  validate(bomFile: string): any {
    if (!fs.existsSync(bomFile)) {
      throw new Error(`BOM file not found at ${bomFile} — the scan did not write any output.`);
    }
    const size = fs.statSync(bomFile).size;
    const raw = fs.readFileSync(bomFile, 'utf8');
    if (size < 50) {
      throw new Error(`BOM file is suspiciously small (${size} bytes): ${raw.slice(0, 500)}`);
    }
    try {
      const bom = JSON.parse(raw);
      console.log(`BOM file OK (${size} bytes, valid JSON)`);
      return bom;
    } catch (err: any) {
      throw new Error(`BOM file is not valid JSON (${err.message}). First 500 bytes: ${raw.slice(0, 500)}`);
    }
  }

  /**
   * Stamp the project fields the Console keys on, and fix up the root component
   * name. knoxctl may drop the tag when deriving the name from a scanned image,
   * so force it back to the exact reference the user passed.
   */
  patch(bom: any, bomFile: string, i: PatchInputs): void {
    console.log(`Patching BOM: project=${i.projectName} classifier=${i.projectClassifier}`);
    console.log(`  root name before: ${bom?.metadata?.component?.name}`);

    if (bom.metadata && bom.metadata.component) {
      if (i.imageRef) {
        bom.metadata.component.name = i.imageRef;
      } else if (bom.metadata.component.name === '.') {
        bom.metadata.component.name = this.repoName;
      }
    }

    // The Console expects $schema first, then the project fields, then the rest.
    const { $schema, ...rest } = bom;
    const patched = {
      ...($schema ? { $schema } : {}),
      project_name: i.projectName,
      project_classifier: i.projectClassifier,
      ...rest,
    };

    fs.writeFileSync(bomFile, JSON.stringify(patched, null, 2));
    console.log(`  root name after:  ${patched?.metadata?.component?.name}`);
  }

  /** Upload the BOM to the AccuKnox Console. Resolves the HTTP status code. */
  upload(bomFile: string): Promise<number> {
    const boundary = `----AccuKnoxBoundary${process.pid}${Date.now()}`;
    const fileBuf = fs.readFileSync(bomFile);
    const head = Buffer.from(
      `--${boundary}\r\n` +
        `Content-Disposition: form-data; name="file"; filename="${path.basename(bomFile)}"\r\n` +
        `Content-Type: application/json\r\n\r\n`
    );
    const tail = Buffer.from(`\r\n--${boundary}--\r\n`);
    const body = Buffer.concat([head, fileBuf, tail]);

    const query = `data_type=SBOM&save_to_s3=True&label_id=${encodeURIComponent(this.cfg.label)}`;
    const options: https.RequestOptions = {
      host: this.cfg.endpoint,
      path: `/api/v1/artifact/?${query}`,
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.cfg.token}`,
        'Content-Type': `multipart/form-data; boundary=${boundary}`,
        'Content-Length': body.length,
      },
      rejectUnauthorized: !this.cfg.skipTlsVerify,
    };

    console.log(`Uploading BOM to https://${this.cfg.endpoint}/api/v1/artifact/`);
    return new Promise((resolve, reject) => {
      const req = https.request(options, (res) => {
        let responseBody = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => (responseBody += chunk));
        res.on('end', () => {
          if (responseBody) console.log(responseBody);
          resolve(res.statusCode || 0);
        });
      });
      req.on('error', reject);
      req.write(body);
      req.end();
    });
  }
}
