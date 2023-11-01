# Deprecation Notice

This GitHub Action has been deprecated and is no longer being maintained. Similar functionality is now available through the consolidated [fortify/github-action](https://github.com/marketplace/actions/fortify-ast-scan) and its sub-actions.

# Generate SARIF from Fortify on Demand

Build secure software fast with [Fortify](https://www.microfocus.com/en-us/solutions/application-security). Fortify offers end-to-end application security solutions with the flexibility of testing on-premises and on-demand to scale and cover the entire software development lifecycle.  With Fortify, find security issues early and fix at the speed of DevOps. 

This GitHub Action invokes the Fortify on Demand (FoD) API to generate a SARIF log file of Static Application Security Testing (SAST) results. The SARIF output is optimized for subsequent import into GitHub to display vulnerabilities in the Security Code Scanning Alerts.

## Usage

The primary use case for this action is after completion of a FoD SAST scan. See the [Fortify on Demand Scan](https://github.com/marketplace/actions/fortify-on-demand-scan) action for more details on how to initiate a FoD SAST scan, including polling for completion, in your workflow. The following sample workflow demonstrates steps to import results from FoD into GitHub Security Code Scanning:

```yaml
name: Import FoD SAST Results
on: [workflow dispatch]
      
jobs:                                                  
  Import-FoD-SAST:
    runs-on: ubuntu-latest

    steps:
      # Pull SAST issues from Fortify on Demand and generate SARIF output
      - name: Download Results
        uses: fortify/gha-fod-generate-sarif@master
        with:
          base-url: https://ams.fortify.com/
          tenant: ${{ secrets.FOD_TENANT }}
          user: ${{ secrets.FOD_USER }}
          password: ${{ secrets.FOD_PAT }}
          release-id: ${{ secrets.FOD_RELEASE_ID }}
          output: ./sarif/output.sarif
      
      # Import Fortify on Demand results to GitHub Security Code Scanning
      - name: Import Results
        uses: github/codeql-action/upload-sarif@v1
        with:
          sarif_file: ./sarif/output.sarif

```

For sample workflows implementing this and other Fortify actions, see:
  * [EightBall](https://github.com/fortify/gha-sample-workflows-eightball/tree/master/.github/workflows)
  * [SSC JS SandBox](https://github.com/fortify/gha-sample-workflows-ssc-js-sandbox/tree/master/.github/workflows)

### Considerations

* Issues that are marked as Fix Validated or are suppressed in FoD are ignored.
* SARIF is designed specifically for SAST findings, so this action ignores FoD Dynamic (DAST), Mobile (MAST) and Open Source/Software Composition (OSS/SCA) issues.
* GitHub Code Scanning currently supports SARIF files with up to 1,000 issues. If the FoD release contains more than 1,000 issues, this action will iteratively remove lower priority issues - low, then medium, then high - in an attempt generate an importable SARIF file.  If there are more than 1,000 critical issues, the action will abort.
* All issues are created with the SARIF level of `warning`. Fortify Priority Order (severity) is assigned via tags for filtering.
* If you are not already a Fortify customer, check out our [Free Trial](https://www.microfocus.com/en-us/products/application-security-testing/free-trial)


## Inputs

### `base-url`
**Required** The base URL for the Fortify on Demand environment where your data resides.

### `tenant` + `user` + `password` OR `client-id` + `client-secret`
**Required** Credentials for authenticating to Fortify on Demand. Strongly recommend use of GitHub Secrets for credential management.  Personal Access Tokens require the `view-apps` and  `view-issues` API scopes.  Client credentials require the `Read Only` (or higher) role.

### `release-id`
**Required** The target FoD release ID to pull SAST issues from.

### `output`
**Required** The location of generated SARIF output.

## Outputs
SARIF log file that is optimized for subsequent import and viewing in GitHub Security Code Scanning
