import tl = require('azure-pipelines-task-lib');
import * as path from 'path';
import { XbomScanner, XbomConfig, GenerateInputs, PatchInputs } from './xbom';

export const VALID_BOM_TYPES = ['sbom', 'cbom', 'aibom'];
export const VALID_AIBOM_SOURCES = ['huggingface', 'bedrock'];

/** Mirrors the validation the GitHub action does before touching the CLI. */
export function validateInputs(i: GenerateInputs): string | null {
  if (!VALID_BOM_TYPES.includes(i.bomType)) {
    return `bomType must be one of ${VALID_BOM_TYPES.join(', ')} (got '${i.bomType}').`;
  }

  if (i.bomType === 'aibom') {
    if (!VALID_AIBOM_SOURCES.includes(i.aibomSource)) {
      return `aibomSource must be one of ${VALID_AIBOM_SOURCES.join(', ')} (got '${i.aibomSource}').`;
    }
    if (i.aibomSource === 'bedrock') {
      if (!i.awsRegion || !i.awsAccessKeyId || !i.awsSecretAccessKey) {
        return 'awsRegion, awsAccessKeyId and awsSecretAccessKey are required when aibomSource is bedrock.';
      }
    } else if (!i.aibomModel) {
      return 'aibomModel is required when bomType is aibom and aibomSource is huggingface.';
    }
  }

  if (i.bomType === 'aibom' && i.imageRef) {
    return 'imageRef is not supported for aibom.';
  }

  return null;
}

export async function run(): Promise<void> {
  try {
    const bomType = (tl.getInput('bomType', true) as string).toLowerCase();
    const scanPath = tl.getInput('scanPath', false) || '.';
    const imageRef = (tl.getInput('imageRef', false) || '').trim();

    const gen: GenerateInputs = {
      bomType,
      scanPath,
      imageRef,
      aibomSource: (tl.getInput('aibomSource', false) || 'huggingface').toLowerCase(),
      aibomModel: (tl.getInput('aibomModel', false) || '').trim(),
      awsRegion: (tl.getInput('awsRegion', false) || '').trim(),
      awsAccessKeyId: (tl.getInput('awsAccessKeyId', false) || '').trim(),
      awsSecretAccessKey: (tl.getInput('awsSecretAccessKey', false) || '').trim(),
    };

    const validationError = validateInputs(gen);
    if (validationError) {
      tl.setResult(tl.TaskResult.Failed, validationError);
      return;
    }

    if (imageRef && scanPath !== '.') {
      console.log('WARNING: both imageRef and a non-default scanPath were provided. imageRef takes precedence.');
    }

    const cfg: XbomConfig = {
      endpoint: tl.getInput('accuknoxEndpoint', true) as string,
      token: tl.getInput('accuknoxToken', true) as string,
      label: tl.getInput('accuknoxLabel', true) as string,
      version: tl.getInput('knoxctlVersion', false) || 'v0.10.0',
      skipTlsVerify: tl.getBoolInput('skipTlsVerify', false),
    };

    const patch: PatchInputs = {
      projectName: tl.getInput('projectName', true) as string,
      projectClassifier: tl.getInput('projectClassifier', true) as string,
      imageRef,
    };

    const scanner = new XbomScanner(cfg);
    const bomFile = tl.getInput('outputFile', false) || scanner.defaultOutputFile(bomType);

    await scanner.setup();

    const exitCode = await scanner.generate(gen, bomFile);
    if (exitCode !== 0) {
      tl.setResult(tl.TaskResult.Failed, `knoxctl exited ${exitCode} while generating the ${bomType.toUpperCase()}.`);
      return;
    }

    const bom = scanner.validate(bomFile);
    scanner.patch(bom, bomFile, patch);

    const status = await scanner.upload(bomFile);
    if (status < 200 || status >= 300) {
      tl.setResult(tl.TaskResult.Failed, `Upload to the AccuKnox Console failed (HTTP ${status}).`);
      return;
    }
    console.log(`Upload succeeded (HTTP ${status}).`);

    // Attach the BOM to the build so it can be downloaded from the run summary.
    const artifactName = `${bomType}-${process.env.BUILD_BUILDID || 'local'}`;
    console.log(`##vso[artifact.upload artifactname=${artifactName}]${path.resolve(bomFile)}`);

    tl.setResult(tl.TaskResult.Succeeded, `${bomType.toUpperCase()} generated and uploaded successfully.`);
  } catch (err: any) {
    tl.setResult(tl.TaskResult.Failed, err.message);
  }
}

// Only auto-run when invoked directly by the Azure DevOps agent (not when imported by tests).
if (require.main === module) {
  run();
}
