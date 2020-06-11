# SARIF Schema

The files in this directory have been downloaded/generated as follows:
* `npm install json-schema-to-typescript --global`
* `curl https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json -o sarif-schema-2.1.0.json`
* `json2ts sarif-schema-2.1.0.json > sarif-schema-2.1.0.d.ts`