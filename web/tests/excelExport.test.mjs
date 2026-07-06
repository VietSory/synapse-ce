import test from 'node:test'
import assert from 'node:assert/strict'

const { buildStyledExcelWorkbook } = await import('../.tmp/excel-test/excelExport.js')

function baseComponent(overrides) {
  return {
    name: '',
    version: '',
    purl: '',
    licenses: [],
    licenseSource: '',
    licenseConfidence: '',
    unknownReason: '',
    firstParty: false,
    location: '',
    ...overrides,
  }
}

function baseVulnerability(overrides) {
  return {
    id: '',
    source: 'osv',
    severity: 'high',
    cvssVector: '',
    cvssScore: 0,
    component: '',
    version: '',
    fixedVersion: '',
    description: '',
    kev: false,
    epss: 0,
    path: [],
    direct: true,
    sources: [],
    confidence: '',
    detections: [],
    firstParty: false,
    unversioned: false,
    ...overrides,
  }
}

function sampleScan() {
  return {
    target: '/work/acme-repo',
    scanMode: 'full',
    languages: [],
    components: [
      baseComponent({ name: 'lodash', version: '4.17.20', location: '/work/acme-repo/services/api/package-lock.json' }),
      baseComponent({ name: 'react', version: '18.2.0', location: '/work/acme-repo/apps/web/package.json' }),
    ],
    dependencies: [],
    vulnerabilities: [
      baseVulnerability({ id: 'CVE-2021-23337', component: 'lodash', version: '4.17.20', fixedVersion: '4.17.21', severity: 'high' }),
      baseVulnerability({ id: 'GHSA-react-demo', component: 'react', version: '18.2.0', fixedVersion: '18.2.1', severity: 'medium' }),
    ],
    licenses: [{ license: 'MIT', category: 'permissive', verdict: 'allow', riskCategory: 'permissive', severity: 'low', components: ['lodash@4.17.20'] }],
    findings: [],
    toolVersions: {},
    vulnDBSnapshot: '',
    completeness: { lockfiles: [], componentsTotal: 0, componentsResolved: 0, confident: true, warning: '' },
    licenseCoverage: { total: 0, detected: 0, unknown: 0, pct: 0 },
    manifest: { toolVersions: {}, vulnDBSnapshot: '', grypeDBVersion: '', correlationVersion: 0, sbomSha256: '', reproScore: 0, pinnedInputs: [], unpinnedInputs: [] },
    findingQuality: { rawFindings: 0, actionable: 0, background: 0, production: 0, development: 0, exampleTest: 0, thirdParty: 0, firstPartyHistorical: 0, versionCoveragePct: 0, pathCoveragePct: 0, confidence: '', byPriority: {} },
    debugEvents: [],
  }
}

function rows(sheet) {
  const range = sheet['!ref']
  assert.ok(range, 'sheet has a range')
  const [start, end] = range.split(':')
  const startRow = Number(start.replace(/^[A-Z]+/, ''))
  const endRow = Number(end.replace(/^[A-Z]+/, ''))
  const endCol = end.replace(/[0-9]+$/, '')
  const colCount = endCol.charCodeAt(0) - 'A'.charCodeAt(0) + 1
  const out = []
  for (let r = startRow; r <= endRow; r++) {
    const row = []
    for (let c = 0; c < colCount; c++) row.push(sheet[`${String.fromCharCode('A'.charCodeAt(0) + c)}${r}`]?.v ?? '')
    out.push(row)
  }
  return out
}

test('service mode keeps the existing per-service workbook shape', () => {
  const { wb } = buildStyledExcelWorkbook(sampleScan(), 'service')

  assert.deepEqual(wb.SheetNames, ['Vulnerability_apps', 'Licenses_apps', 'Vulnerability_services', 'Licenses_services'])
  assert.deepEqual(rows(wb.Sheets.Vulnerability_services)[0], ['Package', 'Advisory ID', 'Severity', 'Installed Version', 'Fix To'])
})

test('summary mode merges all data into Vulnerabilities and Licenses with source path context', () => {
  const { wb } = buildStyledExcelWorkbook(sampleScan(), 'summary')

  assert.deepEqual(wb.SheetNames, ['Vulnerabilities', 'Licenses'])
  const vulnSheet = wb.Sheets.Vulnerabilities
  const licenseSheet = wb.Sheets.Licenses

  assert.deepEqual(rows(vulnSheet)[0], ['Source Path', 'Package', 'Advisory ID', 'Severity', 'Installed Version', 'Fix To'])
  assert.deepEqual(rows(licenseSheet)[0], ['Source Path', 'Package', 'License', 'Severity', 'Recommendation (multiple licenses)'])
  assert.equal(vulnSheet['!autofilter'].ref, 'A1:F3')
  assert.equal(vulnSheet['!sheetView'][0].state, 'frozen')

  const vulnerabilityRows = rows(vulnSheet).slice(1)
  assert.ok(vulnerabilityRows.some((row) => row[0] === 'services/api/package-lock.json' && row[1] === 'lodash'))
  assert.ok(vulnerabilityRows.some((row) => row[0] === 'apps/web/package.json' && row[1] === 'react'))

  const licenseRows = rows(licenseSheet).slice(1)
  assert.ok(licenseRows.some((row) => row[0] === 'services/api/package-lock.json' && row[1] === 'lodash' && row[2] === 'MIT'))
  assert.ok(!licenseRows.some((row) => row[0] === 'services/api/package-lock.json' && row[1] === 'lodash' && row[2] === 'UNKNOWN'))
  assert.ok(licenseRows.some((row) => row[0] === 'apps/web/package.json' && row[1] === 'react' && row[2] === 'UNKNOWN'))
})
