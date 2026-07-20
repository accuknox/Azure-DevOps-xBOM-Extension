# AccuKnox xBOM Scan

Generate a CycloneDX Bill of Materials from your Azure Pipeline and upload it to the AccuKnox Console.

One task covers three BOM types — pick what you need with the **BOM Type** input.

## Features

- **Three BOM types, one task** – SBOM (packages and dependencies), CBOM (cryptographic assets) and AIBOM (AI/ML model inventory).
- **Scan a path or an image** – Point SBOM and CBOM at a source tree or at a container image built earlier in the same job.
- **AI model inventory** – Generate an AIBOM from a HuggingFace model or from every foundation model in an AWS Bedrock region.
- **CycloneDX 1.6** – Standard, portable output.
- **Uploaded and archived** – Results land in the AccuKnox Console and the BOM is attached to the pipeline run as a downloadable artifact.

> ⚠️ **Linux agents only.** The task downloads a `linux_amd64` CLI build. Use `ubuntu-latest` or a Linux self-hosted agent.

## Setup

Store the credentials as **secret** pipeline variables: `ACCUKNOX_ENDPOINT`, `ACCUKNOX_TOKEN`, `ACCUKNOX_LABEL`.

Then create a Project in the AccuKnox Console under **SBOM → Projects**. The `projectName` and `projectClassifier` inputs must exactly match that Project.

## Inputs

| Name | Description | Required |
|---|---|---|
| `bomType` | `sbom`, `cbom` or `aibom` | **Yes** |
| `accuknoxEndpoint` | AccuKnox hostname, no `https://` | **Yes** |
| `accuknoxToken` | AccuKnox API token | **Yes** |
| `accuknoxLabel` | AccuKnox label | **Yes** |
| `projectName` | Project name, as created in the Console | **Yes** |
| `projectClassifier` | `application`, `container`, `firmware`, `library` or `machine-learning-model` | **Yes** |
| `scanPath` | Directory to scan (SBOM/CBOM) | No (default: `.`) |
| `imageRef` | Container image to scan; takes precedence over `scanPath` | No |
| `aibomSource` | `huggingface` or `bedrock` | No (default: `huggingface`) |
| `aibomModel` | HuggingFace model ID | Only for `huggingface` |
| `awsRegion`, `awsAccessKeyId`, `awsSecretAccessKey` | AWS credentials for the Bedrock inventory | Only for `bedrock` |
| `outputFile` | Where to write the BOM | No |
| `knoxctlVersion` | CLI release tag | No (default: `v0.10.0`) |
| `skipTlsVerify` | Disable TLS verification on upload | No (default: `false`) |

All examples assume the credentials are defined as pipeline variables: `ACCUKNOX_ENDPOINT`, `ACCUKNOX_TOKEN`, `ACCUKNOX_LABEL`.

### 1. SBOM from a filesystem

```yaml
- task: AccuKnox-xBOM@1
  inputs:
    bomType: sbom
    scanPath: '.'
    accuknoxEndpoint: $(ACCUKNOX_ENDPOINT)
    accuknoxToken: $(ACCUKNOX_TOKEN)
    accuknoxLabel: $(ACCUKNOX_LABEL)
    projectName: my-project
    projectClassifier: application
```

### 2. SBOM from a container image

```yaml
- script: |
    IMAGE="myapp:$(Build.SourceVersion)"
    docker build -t "$IMAGE" .
    echo "##vso[task.setvariable variable=IMAGE]$IMAGE"
  displayName: Build image

- task: AccuKnox-xBOM@1
  inputs:
    bomType: sbom
    imageRef: $(IMAGE)
    accuknoxEndpoint: $(ACCUKNOX_ENDPOINT)
    accuknoxToken: $(ACCUKNOX_TOKEN)
    accuknoxLabel: $(ACCUKNOX_LABEL)
    projectName: my-project
    projectClassifier: container
```

### 3. CBOM from Go source

```yaml
- task: AccuKnox-xBOM@1
  inputs:
    bomType: cbom
    scanPath: '.'
    accuknoxEndpoint: $(ACCUKNOX_ENDPOINT)
    accuknoxToken: $(ACCUKNOX_TOKEN)
    accuknoxLabel: $(ACCUKNOX_LABEL)
    projectName: my-project
    projectClassifier: application
```

### 4. CBOM from a container image

```yaml
- task: AccuKnox-xBOM@1
  inputs:
    bomType: cbom
    imageRef: $(IMAGE)
    accuknoxEndpoint: $(ACCUKNOX_ENDPOINT)
    accuknoxToken: $(ACCUKNOX_TOKEN)
    accuknoxLabel: $(ACCUKNOX_LABEL)
    projectName: my-project
    projectClassifier: container
```

### 5. AIBOM from a HuggingFace model

```yaml
- task: AccuKnox-xBOM@1
  inputs:
    bomType: aibom
    aibomSource: huggingface
    aibomModel: google-bert/bert-base-uncased
    accuknoxEndpoint: $(ACCUKNOX_ENDPOINT)
    accuknoxToken: $(ACCUKNOX_TOKEN)
    accuknoxLabel: $(ACCUKNOX_LABEL)
    projectName: my-project
    projectClassifier: machine-learning-model
```

### 6. AIBOM from AWS Bedrock

```yaml
- task: AccuKnox-xBOM@1
  inputs:
    bomType: aibom
    aibomSource: bedrock
    awsRegion: us-east-1
    awsAccessKeyId: $(AWS_ACCESS_KEY_ID)
    awsSecretAccessKey: $(AWS_SECRET_ACCESS_KEY)
    accuknoxEndpoint: $(ACCUKNOX_ENDPOINT)
    accuknoxToken: $(ACCUKNOX_TOKEN)
    accuknoxLabel: $(ACCUKNOX_LABEL)
    projectName: my-project
    projectClassifier: machine-learning-model
```

## Downloading the BOM

The BOM is attached to the pipeline run as an artifact named `<bomType>-<buildId>`. Open the run and use **Related → Published artifacts** to download it.

## Results

Findings are available in the AccuKnox Console under **SBOM → Projects**, filtered by the project you configured.
