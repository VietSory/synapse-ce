import type { Finding } from './types'

export const ratedFindingDimensionValues = [
  'security',
  'reliability',
  'maintainability',
] as const

export type RatedFindingDimension = (typeof ratedFindingDimensionValues)[number]

const dimensionKinds: Record<RatedFindingDimension, ReadonlySet<string>> = {
  security: new Set(['', 'sca', 'sast', 'secret', 'misconfig', 'exploitation', 'dast']),
  reliability: new Set(['reliability']),
  maintainability: new Set(['quality']),
}

export function findingMatchesRatedDimension(
  finding: Pick<Finding, 'kind'>,
  dimension: RatedFindingDimension,
): boolean {
  return dimensionKinds[dimension].has(finding.kind)
}

export function ratedFindingDimensionLabel(dimension: RatedFindingDimension): string {
  switch (dimension) {
    case 'security':
      return 'Security dimension'
    case 'reliability':
      return 'Reliability dimension'
    case 'maintainability':
      return 'Maintainability dimension'
  }
}
