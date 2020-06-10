import * as core from '@actions/core';
import * as agent from 'superagent';
import prefix from 'superagent-prefix';
import Throttle from 'superagent-throttle';
import * as sarif from 'sarif';
import htmlToText from 'html-to-text';

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

async function authenticate(baseUrlString: string, auth: any) : Promise<any> {
    const apiBaseUrl = getApiBaseUrlString(baseUrlString);
    const tokenEndPoint = `${apiBaseUrl}/oauth/token`;
    return agent.post(tokenEndPoint)
        .type('form')
        .send(auth)
        .then(resp=>agent.agent()
            .set('Authorization', 'Bearer '+resp.body.access_token)
            .use(prefix(apiBaseUrl))
        );
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

function getLog() : sarif.Log {
    return {
        version: '2.1.0',
        runs: [
            {
                tool: {
                    driver:
                        {
                            name: 'Fortify'
                        }
                }
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

async function process(agent:any) {
    const releaseId = getReleaseId();
    processAllVulnerabilities(agent, releaseId, 0);
}

async function processAllVulnerabilities(agent: any, releaseId:string, offset:number) : Promise<void> {
    const limit = 50;
    return await agent.get(`/api/v3/releases/${releaseId}/vulnerabilities`)
        .query({offset: offset, limit: limit})
        .then(
            (resp: any)=>{
                resp.body.items.forEach((vuln:any)=>processVulnerability(agent, releaseId, vuln));
                if ( resp.body.totalCount>offset+limit ) {
                    processAllVulnerabilities(agent, releaseId, offset+limit);
                }
            }
        );
}

async function processVulnerability(agent: any, releaseId:string, vuln: any) : Promise<void> {
    return await agent.get(`/api/v3/releases/${releaseId}/vulnerabilities/${vuln.vulnId}/details`)
        .use(throttle10perSec.plugin())
        .then((resp: any)=>{
            const details = resp.body;
            //console.log(vuln);
            //console.log(details);
            console.log(JSON.stringify(getSarifResult(vuln, details), null, 2));
            console.log(JSON.stringify(getSarifReportingDescriptor(vuln, details), null, 2));
        });
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