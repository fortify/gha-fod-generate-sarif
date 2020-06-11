import * as core from '@actions/core';
import request from 'superagent';
import prefix from 'superagent-prefix';
import Throttle from 'superagent-throttle';
import * as sarif from './sarif/sarif-schema-2.1.0';
import htmlToText from 'html-to-text';
import { promises } from 'fs';

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
    const tenant = core.getInput('tenant', { required: true });
    const user = core.getInput('user', { required: true });
    const password = core.getInput('password', { required: true });

    return {
        scope: getAuthScope(),
        grant_type: 'password',
        username: tenant + '\\' + user,
        password: password
    };
}

function getClientCredentialsAuthPayload() {
    const client_id = core.getInput('client-id', { required: true });
    const client_secret = core.getInput('client-secret', { required: true });

    return {
        scope: getAuthScope(),
        grant_type: 'client_credentials',
        client_id: client_id,
        client_secret: client_secret
    };
}

function getAuthPayload() {
    if ( core.getInput('user', { required: false }) ) {
        return getPasswordAuthPayload();
    } else {
        return getClientCredentialsAuthPayload();
    }
}

function getReleaseId() : string {
    // TODO Add support for getting release id by application/release name
    return core.getInput('release-id', { required: true });
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
                        fullName: 'Fortify on Demand',
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
    authenticate('https://ams.fortify.com', auth)
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
        .then(sarifLog=>console.info(JSON.stringify(sarifLog, null, 2)));
}

async function processAllVulnerabilities(sarifLog: sarifLog, request: request.SuperAgentStatic, releaseId:string, offset:number) : Promise<sarifLog> {
    const limit = 50;
    return request.get(`/api/v3/releases/${releaseId}/vulnerabilities`)
        .query({offset: offset, limit: limit})
        .then(
            resp=>{
                const vulns = resp.body.items;
                //vulns.forEach((vuln:any)=>processVulnerability(sarifLog, request, releaseId, vuln));
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
    return request.get(`/api/v3/releases/${releaseId}/vulnerabilities/${vuln.vulnId}/details`)
        .use(throttle10perSec.plugin())
        .then(resp=>{
            const details = resp.body;
            console.info(`Processing vuln ${vuln.instanceId}`);
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
                        startColumn: 0,
                        endColumn: undefined
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