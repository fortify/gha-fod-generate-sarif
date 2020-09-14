import * as core from '@actions/core';
import request from 'superagent';
import prefix from 'superagent-prefix';
import Throttle from 'superagent-throttle';
import sarif from './sarif/sarif-schema-2.1.0';
import htmlToText from 'html-to-text';
import fs from 'fs-extra';
import path from 'path';
 
const INPUT = {
    base_url: core.getInput('base-url', { required: true }),
    tenant: core.getInput('tenant', { required: false }),
    user: core.getInput('user', { required: false }),
    password: core.getInput('password', { required: false }),
    client_id: core.getInput('client-id', { required: false }),
    client_secret: core.getInput('client-secret', { required: false }),
    release_id: core.getInput('release-id', { required: true }),
    output: core.getInput('output', { required: true })
}

const throttle10perSec = new Throttle({
    active: true,     // set false to pause queue
    rate: 2,          // how many requests can be sent every `ratePer`
    ratePer: 4000,   // number of ms in which `rate` requests may be sent
    concurrent: 1     // how many requests can be sent concurrently
  })

var currentScanSummary: any;
var sarifToolDriverRules = [] as any;
var sarifResults = [] as any;

function getApiBaseUrl(baseUrlString: string) : URL {
    let baseUrl = new URL(baseUrlString);
    if ( !baseUrl.hostname.startsWith('api') ) {
        baseUrl.hostname = 'api.' + baseUrl.hostname;
    }
    return baseUrl;
}

function getApiBaseUrlString(baseUrlString: string) : string {
    return getApiBaseUrl(baseUrlString).toString();
}

function getAuthScope() {
    return "view-apps view-issues";
}

function getPasswordAuthPayload() {
    return {
        scope: getAuthScope(),
        grant_type: 'password',
        username: INPUT.tenant + '\\' + INPUT.user,
        password: INPUT.password
    };
}

function getClientCredentialsAuthPayload() {

    return {
        scope: getAuthScope(),
        grant_type: 'client_credentials',
        client_id: INPUT.client_id,
        client_secret: INPUT.client_secret
    };
}

function getAuthPayload() {
    if ( INPUT.client_id && INPUT.client_secret ) {
        return getClientCredentialsAuthPayload();
    } else if ( INPUT.tenant && INPUT.user && INPUT.password ) {
        return getPasswordAuthPayload();
    } else {
        throw 'Either client-id and client-secret, or tenant, user and password must be specified';
    }
}

function getReleaseId() : any {
    // TODO Add support for getting release id by application/release name
    return INPUT.release_id;
}

//type sarifLog = sarif.StaticAnalysisResultsFormatSARIFVersion210JSONSchema;

function getLog() : any {
    return {
        $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        version: '2.1.0',
        runs: [
            {
                tool: {
                    driver: { 
                        name: 'Fortify on Demand',
                        rules: []
                    }
                }
                ,results: []
            }
        ]
    };
}

async function main() {
    const auth = getAuthPayload();
    await authenticate(INPUT.base_url, auth)
        .then(process)
        .catch(resp=>console.error(resp));
}

async function authenticate(baseUrlString: string, auth: any) : Promise<request.SuperAgentStatic> {
    const apiBaseUrl = getApiBaseUrlString(baseUrlString);
    const tokenEndPoint = `${apiBaseUrl}/oauth/token`;
    return request.post(tokenEndPoint)
        .type('form')
        .send(auth)
        .then(resp=>createAgent(baseUrlString, resp.body));
}

function createAgent(apiBaseUrl:string, tokenResponseBody:any) : request.SuperAgentStatic {
    return request.agent()
        .set('Authorization', 'Bearer '+tokenResponseBody.access_token)
        .use(prefix(apiBaseUrl))
}

async function process(request: request.SuperAgentStatic) : Promise<void> {
    const releaseId = getReleaseId();

    const releaseDetails = getReleaseDetails(request, releaseId);

    releaseDetails.then(
        resp=>{
            const details = resp;
            
            let status = details.staticAnalysisStatusType;
            let suspended = details.suspended;
            let totalVulnCount = details.issueCount;
            let mediumCount = details.medium;
            let highCount = details.high;
            let criticalCount = details.critical;

            if (status == 'Completed' && !suspended) {

                const scanSummary = getScanSummary(request, details.currentStaticScanId);
                scanSummary.then(
                    res=>{
                        currentScanSummary = res;
                    }
                )
                .catch(err=>{throw err});
    
                console.debug(`Total vuln count is ${totalVulnCount}`);

                let severity = {};

                if (totalVulnCount <= 1000) {
                    severity = {
                        critical: true,
                        high: true,
                        medium: true,
                        low: true
                    }
                }
                else if ((criticalCount + highCount + mediumCount) <= 1000) {
                    severity = {
                        critical: true,
                        high: true,
                        medium: true,
                        low: false
                    };
                }
                else if ((criticalCount + highCount + mediumCount) > 1000 
                    && (criticalCount + highCount) <= 1000) {
                        severity = {
                            critical: true,
                            high: true,
                            medium: false,
                            low: false
                        };
                }
                else if ((criticalCount + highCount + mediumCount) > 1000 
                    && (criticalCount + highCount) > 1000
                    && criticalCount <= 1000) {
                        severity = {
                            critical: true,
                            high: false,
                            medium: false,
                            low: false
                        };
                }
                return processSelectVulnerabilities(request, releaseId, 0, severity).then(writeSarif);

            }
            else {
                console.info(`The scan is incomplete.  Results are not available.`);
            }
            
        }
    )
    .catch(err=>{throw err});

}

async function writeSarif() : Promise<void> {

    let sarifLog = getLog();

    if (sarifToolDriverRules.length > 0 && sarifResults.length > 0) {

        console.info(`Gathering issues...`);   

        sarifLog.runs[0].tool.driver.version = 
            currentScanSummary.staticScanSummaryDetails.engineVersion + ' ' + 
            currentScanSummary.staticScanSummaryDetails.rulePackVersion;

        for (var i=0; i<sarifToolDriverRules.length; i++) {
            sarifLog.runs[0].tool.driver.rules?.push(sarifToolDriverRules[i]);
        }
        for (var j=0; j<sarifResults.length; j++) {
            sarifLog.runs[0].results?.push(sarifResults[j]);
        }      
    }

    console.info(`Writing SARIF...`);

    const file = INPUT.output;
    return fs.ensureFile(file).then(()=>fs.writeJSON(file, sarifLog, {spaces: 2}));

}

async function processSelectVulnerabilities(request: request.SuperAgentStatic, releaseId:string, offset:number, severity:any) : Promise<any> {
    const limit = 50;
    console.info(`Loading next ${limit} issues (offset ${offset})`);

    let filters = "scantype:Static";
    if (severity.critical && severity.high && severity.medium && severity.low) {
        filters += "+severityString:Critical|High|Medium|Low";
    }
    else if (severity.critical && severity.high && severity.medium && !severity.low) {
        filters += "+severityString:Critical|High|Medium";
    }
    else if (severity.critical && severity.high && !severity.medium && !severity.low) {
        filters += "+severityString:Critical|High";
    }
    else if (severity.critical && !severity.high && !severity.medium && !severity.low) {
        filters += "+severityString:Critical";
    }

    return request.get(`/api/v3/releases/${releaseId}/vulnerabilities`)
        .query({filters: filters, excludeFilters: true, offset: offset, limit: limit})
        .then(
            async resp=>{
                const vulns = resp.body.items;
                return await Promise.all(vulns.map((vuln:any)=>processVulnerability(request, releaseId, vuln)))
                .then(()=>{
                    if ( resp.body.totalCount>offset+limit ) {
                        processSelectVulnerabilities(request, releaseId, offset+limit, severity)
                            .then(writeSarif);
                    }
                })
            }
        )
        .catch(err=>{throw err});
}

async function getScanSummary(request: request.SuperAgentStatic, scanId:string) : Promise<any> {
    console.debug(`Loading summary for scan ${scanId}`);
    return request.get(`/api/v3/scans/${scanId}/summary`)
    .then(resp=>{
        const scanSummary = resp.body;
        return scanSummary;
    })
    .catch(err=>{throw err});
}

async function getReleaseDetails(request: request.SuperAgentStatic, releaseId:string) : Promise<any> {
    console.debug(`Loading details for release ${releaseId}`);
    return request.get(`/api/v3/releases/${releaseId}`)
        .query({filters: 'scantype:Static'})
        .then(resp=>{
            const releaseDetails = resp.body;
            return releaseDetails;
        })
        .catch(err=>{throw err});
}

async function processVulnerability(request: request.SuperAgentStatic, releaseId:string, vuln: any) : Promise<void> {
    console.debug(`Loading details for vulnerability ${vuln.vulnId}`);
    return request.get(`/api/v3/releases/${releaseId}/vulnerabilities/${vuln.vulnId}/details`)
        .use(throttle10perSec.plugin())
        .then(resp=>{
            const details = resp.body;
            sarifToolDriverRules.push(getSarifReportingDescriptor(vuln, details));
            sarifResults.push(getSarifResult(vuln, details));

            console.info(`Saving issue details for ${vuln.vulnId}`);
        })
        .catch(err=>console.error(`${err} - Ignoring vulnerability ${vuln.vulnId}`));
}

function getSarifResult(vuln:any, details:any) : any {
    return {
        ruleId: getRuleId(vuln, details),
        message: { text: convertHtmlToText(details.summary) },
        level: getSarifLevel(vuln.severity),
        partialFingerprints: {
            issueInstanceId: vuln.instanceId
        },
        locations: [
            {
                physicalLocation: {
                    artifactLocation: {
                        uri: vuln.primaryLocationFull
                    },
                    region: {
                        startLine: vuln.lineNumber,
                        endLine: vuln.lineNumber,
                        startColumn: 1,
                        endColumn: 80
                    }
                }
            }
        ]
    }
}

function getSarifLevel(severity:number) : "none" | "note" | "warning" | "error" | undefined {
    return 'warning'; // TODO map severity
}

function getSarifReportingDescriptor(vuln:any, details:any) : any {
    return {
        id: getRuleId(vuln, details),
        shortDescription: { text: vuln.category },
        fullDescription: {text: convertHtmlToText(details.summary) },
        help: {
            text:     getSarifReportingDescriptorHelpText(vuln, details),
            markdown: getSarifReportingDescriptorHelpMarkdown(vuln, details)
        },
        properties: {
            tags: [vuln.severityString]
        }
    };
}

function getSarifReportingDescriptorHelpText(vuln:any, details:any) : string {
    return `For detailed recommendations, code examples, dataflow diagram and more, see ${INPUT.base_url}/Redirect/Issues/${vuln.vulnId}.`;
}

function getSarifReportingDescriptorHelpMarkdown(vuln:any, details:any) : string {
    return `For detailed recommendations, code examples, dataflow diagram and more, log in to [Fortify on Demand](${INPUT.base_url}/Redirect/Issues/${vuln.vulnId}).`;
}

function convertHtmlToText(html:string) {
    return htmlToText.fromString(html, {preserveNewlines: true, wordwrap: false});
}

function getRuleId(vuln:any, details:any) {
    return `${vuln.id}`;
}

main();