import { describe, expect, it } from 'vitest'
import { findingMatchesRatedDimension, ratedFindingDimensionLabel } from './ratedFindingDimensions'

describe('rated finding dimensions', () => {
  it.each(['', 'sca', 'sast', 'secret', 'misconfig', 'exploitation', 'dast'])(
    'includes security kind %j',
    (kind) => {
      expect(findingMatchesRatedDimension({ kind }, 'security')).toBe(true)
    },
  )

  it.each(['reliability', 'quality', 'recon', 'manual', 'threat', 'hypothesis'])(
    'excludes unrelated security kind %j',
    (kind) => {
      expect(findingMatchesRatedDimension({ kind }, 'security')).toBe(false)
    },
  )

  it('maps reliability and maintainability to exactly their rating kinds', () => {
    for (const kind of ['', 'sca', 'sast', 'secret', 'misconfig', 'exploitation', 'dast', 'quality']) {
      expect(findingMatchesRatedDimension({ kind }, 'reliability')).toBe(false)
    }
    expect(findingMatchesRatedDimension({ kind: 'reliability' }, 'reliability')).toBe(true)

    for (const kind of ['', 'sca', 'sast', 'secret', 'misconfig', 'exploitation', 'dast', 'reliability']) {
      expect(findingMatchesRatedDimension({ kind }, 'maintainability')).toBe(false)
    }
    expect(findingMatchesRatedDimension({ kind: 'quality' }, 'maintainability')).toBe(true)
  })

  it('provides visible labels without mutating findings', () => {
    const finding = Object.freeze({ kind: 'sast' })
    expect(findingMatchesRatedDimension(finding, 'security')).toBe(true)
    expect(finding).toEqual({ kind: 'sast' })
    expect(ratedFindingDimensionLabel('security')).toBe('Security dimension')
    expect(ratedFindingDimensionLabel('reliability')).toBe('Reliability dimension')
    expect(ratedFindingDimensionLabel('maintainability')).toBe('Maintainability dimension')
  })
})
