# Generate SARIF from Fortify on Demand

Build secure software fast with [Fortify](https://www.microfocus.com/en-us/solutions/application-security). Fortify offers end-to-end application security solutions with the flexibility of testing on-premises and on-demand to scale and cover the entire software development lifecycle.  With Fortify, find security issues early and fix at the speed of DevOps. 

This GitHub Action invokes the Fortify on Demand (FoD) API to generate a SARIF log file of Static Application Security Testing (SAST) results. The SARIF output is optimized for subsequent import into GitHub to display vulnerabilities in the Security Code Scanning Alerts.
## Usage

The primary use case for this action would be after a FoD SAST scan has been completed. See the [Fortify on Demand Scan](https://github.com/marketplace/actions/fortify-on-demand-scan) action for more details on how to initiate a FoD SAST scan in your workflow. The following sample workflow demonstrates steps to import results from FoD into GitHub Security Code Scanning:

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
          release-id: ${{ secrets.FOD_RELEASE_ID2 }}
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


¹ Note that in combination with FoD Uploader, *only* the ScanCentral `Package` command is relevant. Other ScanCentral commands are not used in combination with FoD Uploader, and none of the other ScanCentral components like ScanCentral Controller or ScanCentral Sensor are used when submitting scans to FoD.

### Considerations

* Be sure to consider the appropriate event triggers in your workflows, based on your project and branching strategy
* 1k limit
* Uploadsarif action limitations
* Does not import suppressed or fixed issues
* If you are not already a Fortify customer, check out our [Free Trial](https://www.microfocus.com/en-us/products/application-security-testing/free-trial)


## Inputs

### `base-url`
**Required** The base URL for the Fortify on Demand environment where your data resides.

### `tenant` + `user` + `password` OR `client` + `secret`
**Required** Credentials for authenticating to Fortify on Demand. Strongly recommend use of GitHub Secrets for credential management.

### `release-id`
**Required** The target FoD release ID to pull SAST issues from.

## Outputs

### `output`
**Required** The location of generated SARIF output.
