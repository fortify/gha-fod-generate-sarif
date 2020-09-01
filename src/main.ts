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
    rate: 10,          // how many requests can be sent every `ratePer`
    ratePer: 1000,   // number of ms in which `rate` requests may be sent
    concurrent: 10     // how many requests can be sent concurrently
  })

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

function getReleaseId() : string {
    // TODO Add support for getting release id by application/release name
    return INPUT.release_id;
}

type sarifLog = sarif.StaticAnalysisResultsFormatSARIFVersion210JSONSchema;

function getLog() : sarifLog {
    return {
        $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        version: '2.1.0',
        runs: [
            {
                tool: {
                    driver: { 
                        name: 'Fortify',
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
    authenticate(INPUT.base_url, auth)
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
    return processAllVulnerabilities(getLog(), request, releaseId, 0)
        .then(writeSarif);
}

async function writeSarif(sarifLog: sarifLog) : Promise<void> {
    const file = INPUT.output;
    return fs.ensureFile(file).then(()=>fs.writeJSON(file, sarifLog, {spaces: 2}));
}

async function processAllVulnerabilities(sarifLog: sarifLog, request: request.SuperAgentStatic, releaseId:string, offset:number) : Promise<sarifLog> {
    const limit = 50;
    return request.get(`/api/v3/releases/${releaseId}/vulnerabilities`)
        .query({offset: offset, limit: limit})
        .then(
            resp=>{
                const vulns = resp.body.items;
                return Promise.all(vulns.map((vuln:any)=>processVulnerability(sarifLog, request, releaseId, vuln)))
                .then(()=>{
                    if ( resp.body.totalCount>offset+limit ) {
                        processAllVulnerabilities(sarifLog, request, releaseId, offset+limit);
                    }
                    return sarifLog;
                })
            }
        )
        .catch(err=>{throw err});
}

async function processVulnerability(sarifLog: sarifLog, request: request.SuperAgentStatic, releaseId:string, vuln: any) : Promise<void> {
    if ( vuln.scantype!='Static' ) { return Promise.resolve(); } // Ignore all non-static findings
    return request.get(`/api/v3/releases/${releaseId}/vulnerabilities/${vuln.vulnId}/details`)
        .use(throttle10perSec.plugin())
        .then(resp=>{
            const details = resp.body;
            sarifLog.runs[0].tool.driver.rules?.push(getSarifReportingDescriptor(vuln, details));
            sarifLog.runs[0].results?.push(getSarifResult(vuln, details));
        })
        .catch(err=>console.error(`${err} - Ignoring vulnerability ${vuln.vulnId}`));
}

function getSarifResult(vuln:any, details:any) : sarif.Result {
    return {
        ruleId: details.ruleId,
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

function getSarifReportingDescriptor(vuln:any, details:any) : sarif.ReportingDescriptor {
    return {
        id: details.ruleId,
        shortDescription: { text: vuln.category },
        fullDescription: {text: convertHtmlToText(details.explanation) }
    };
}

function convertHtmlToText(html:string) {
    return htmlToText.fromString(html, {preserveNewlines: true, wordwrap: false});
}

main();