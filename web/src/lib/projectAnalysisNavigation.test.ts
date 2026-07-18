import { describe, expect, it } from 'vitest'
import {
  normalizeProjectAnalysisSearch,
  parseProjectAnalysisFocus,
  projectAnalysisLandmarkFor,
  projectAnalysisLandmarks,
  projectAnalysisPath,
  projectAnalysisFocusValues,
  projectOverviewPath,
  serializeProjectAnalysisFocus,
} from './projectAnalysisNavigation'

describe('projectAnalysisNavigation focus contract', () => {
  it('parses and serializes every supported focus', () => {
    for (const focus of projectAnalysisFocusValues) {
      expect(parseProjectAnalysisFocus(focus)).toBe(focus)
      expect(serializeProjectAnalysisFocus(focus)).toBe(focus)
    }
  })

  it.each([null, '', ' ', 'issues', 'hotspots', 'measures', 'foo', 'Security'])(
    'rejects unsupported focus %j',
    (value) => {
      expect(parseProjectAnalysisFocus(value)).toBeNull()
    },
  )

  it('serializes encoded Analysis and Overview locations', () => {
    const key = 'team/demo project/đ'
    expect(projectAnalysisPath(key, 'security', 'overall')).toBe(
      '/code-quality/projects/team%2Fdemo%20project%2F%C4%91/analysis?focus=security&lens=overall',
    )
    expect(projectAnalysisPath(key)).toBe('/code-quality/projects/team%2Fdemo%20project%2F%C4%91/analysis')
    expect(projectOverviewPath(key, 'new-code')).toBe(
      '/code-quality/projects/team%2Fdemo%20project%2F%C4%91?lens=new-code',
    )
  })

  it('normalizes invalid focus and lens while preserving unrelated parameters', () => {
    const normalized = normalizeProjectAnalysisSearch(new URLSearchParams('focus=issues&lens=bad&trace=keep'))
    expect(normalized.focus).toBeNull()
    expect(normalized.lens).toBe('overall')
    expect(normalized.changed).toBe(true)
    expect(normalized.params.toString()).toBe('lens=overall&trace=keep')
  })

  it('canonicalizes new-code focus to the new-code lens without mutating valid input', () => {
    const normalized = normalizeProjectAnalysisSearch(new URLSearchParams('focus=new-code&lens=overall&trace=keep'))
    expect(normalized.focus).toBe('new-code')
    expect(normalized.lens).toBe('new-code')
    expect(normalized.params.toString()).toBe('focus=new-code&lens=new-code&trace=keep')

    const valid = new URLSearchParams('focus=coverage&lens=overall')
    const unchanged = normalizeProjectAnalysisSearch(valid)
    expect(unchanged.changed).toBe(false)
    expect(unchanged.params.toString()).toBe(valid.toString())
  })

  it('maps semantic focus to stable lens-aware landmarks', () => {
    expect(projectAnalysisLandmarkFor('security', 'overall')).toBe(projectAnalysisLandmarks.findings)
    expect(projectAnalysisLandmarkFor('reliability', 'overall')).toBe(projectAnalysisLandmarks.findings)
    expect(projectAnalysisLandmarkFor('maintainability', 'overall')).toBe(projectAnalysisLandmarks.findings)
    expect(projectAnalysisLandmarkFor('coverage', 'overall')).toBe(projectAnalysisLandmarks.coverage)
    expect(projectAnalysisLandmarkFor('duplications', 'overall')).toBe(projectAnalysisLandmarks.duplications)
    expect(projectAnalysisLandmarkFor('security', 'new-code')).toBe(projectAnalysisLandmarks.newCode)
    expect(projectAnalysisLandmarkFor('new-code', 'overall')).toBe(projectAnalysisLandmarks.newCode)
  })
})
