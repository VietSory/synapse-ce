import { act, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { projectAnalysisLandmarks } from '../../lib/projectAnalysisNavigation'
import { ProjectAnalysisFocusController } from './ProjectAnalysisFocusController'

describe('ProjectAnalysisFocusController', () => {
  const scrollIntoView = vi.fn()

  beforeEach(() => {
    vi.useFakeTimers()
    scrollIntoView.mockReset()
    Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', { configurable: true, value: scrollIntoView })
    setReducedMotion(false)
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it.each([
    ['security', 'overall', projectAnalysisLandmarks.findings, 'Analysis findings'],
    ['coverage', 'overall', projectAnalysisLandmarks.coverage, 'Coverage'],
    ['duplications', 'overall', projectAnalysisLandmarks.duplications, 'Duplicated blocks'],
    ['new-code', 'new-code', projectAnalysisLandmarks.newCode, 'New Code period'],
  ] as const)('focuses %s details and smoothly scrolls after they render', async (focusValue, lens, landmark, headingName) => {
    render(
      <>
        <ProjectAnalysisFocusController projectKey="synapse" analysisRevision={0} focus={focusValue} lens={lens} />
        <h2 id={landmark} tabIndex={-1}>{headingName}</h2>
      </>,
    )

    expect(scrollIntoView).not.toHaveBeenCalled()
    const heading = screen.getByRole('heading', { name: headingName })
    const focus = vi.spyOn(heading, 'focus')
    await flushFocusTimer()
    expect(scrollIntoView).toHaveBeenCalledOnce()
    expect(scrollIntoView).toHaveBeenCalledWith({ block: 'start', behavior: 'smooth' })
    expect(heading).toHaveFocus()
    expect(focus).toHaveBeenCalledWith({ preventScroll: true })
  })

  it('does nothing without a focus query', async () => {
    render(<ProjectAnalysisFocusController projectKey="synapse" analysisRevision={0} focus={null} lens="overall" />)
    await flushFocusTimer()
    expect(scrollIntoView).not.toHaveBeenCalled()
  })

  it('handles each navigation signature once and refocuses on a new focus', async () => {
    const { rerender } = render(
      <>
        <ProjectAnalysisFocusController projectKey="synapse" analysisRevision={0} focus="security" lens="overall" />
        <h2 id={projectAnalysisLandmarks.findings} tabIndex={-1}>Analysis findings</h2>
        <h2 id={projectAnalysisLandmarks.coverage} tabIndex={-1}>Coverage</h2>
      </>,
    )
    await flushFocusTimer()

    rerender(
      <>
        <ProjectAnalysisFocusController projectKey="synapse" analysisRevision={0} focus="security" lens="overall" />
        <h2 id={projectAnalysisLandmarks.findings} tabIndex={-1}>Analysis findings</h2>
        <h2 id={projectAnalysisLandmarks.coverage} tabIndex={-1}>Coverage</h2>
      </>,
    )
    await flushFocusTimer()
    expect(scrollIntoView).toHaveBeenCalledTimes(1)

    rerender(
      <>
        <ProjectAnalysisFocusController projectKey="synapse" analysisRevision={0} focus="coverage" lens="overall" />
        <h2 id={projectAnalysisLandmarks.findings} tabIndex={-1}>Analysis findings</h2>
        <h2 id={projectAnalysisLandmarks.coverage} tabIndex={-1}>Coverage</h2>
      </>,
    )
    await flushFocusTimer()
    expect(scrollIntoView).toHaveBeenCalledTimes(2)
    expect(screen.getByRole('heading', { name: 'Coverage' })).toHaveFocus()
  })

  it('allows the same focus after an analysis revision changes', async () => {
    const heading = <h2 id={projectAnalysisLandmarks.coverage} tabIndex={-1}>Coverage</h2>
    const { rerender } = render(
      <><ProjectAnalysisFocusController projectKey="synapse" analysisRevision={0} focus="coverage" lens="overall" />{heading}</>,
    )
    await flushFocusTimer()
    rerender(<><ProjectAnalysisFocusController projectKey="synapse" analysisRevision={1} focus="coverage" lens="overall" />{heading}</>)
    await flushFocusTimer()
    expect(scrollIntoView).toHaveBeenCalledTimes(2)
  })

  it('reports a missing target without focusing a fallback', async () => {
    render(
      <>
        <ProjectAnalysisFocusController projectKey="synapse" analysisRevision={0} focus="coverage" lens="overall" />
        <h2 id={projectAnalysisLandmarks.findings} tabIndex={-1}>Analysis findings</h2>
      </>,
    )
    await flushFocusTimer()
    expect(screen.getByRole('status')).toHaveTextContent('The requested detail is unavailable for this analysis.')
    expect(scrollIntoView).not.toHaveBeenCalled()
    expect(screen.getByRole('heading', { name: 'Analysis findings' })).not.toHaveFocus()
  })

  it('uses automatic scrolling when reduced motion is preferred', async () => {
    setReducedMotion(true)
    render(
      <>
        <ProjectAnalysisFocusController projectKey="synapse" analysisRevision={0} focus="coverage" lens="overall" />
        <h2 id={projectAnalysisLandmarks.coverage} tabIndex={-1}>Coverage</h2>
      </>,
    )
    await flushFocusTimer()
    expect(scrollIntoView).toHaveBeenCalledWith({ block: 'start', behavior: 'auto' })
  })

  it('cancels stale Project and unmounted focus actions', async () => {
    const { rerender, unmount } = render(
      <>
        <ProjectAnalysisFocusController projectKey="alpha" analysisRevision={0} focus="coverage" lens="overall" />
        <h2 id={projectAnalysisLandmarks.coverage} tabIndex={-1}>Coverage</h2>
      </>,
    )
    const heading = screen.getByRole('heading', { name: 'Coverage' })
    const focus = vi.spyOn(heading, 'focus')
    rerender(
      <>
        <ProjectAnalysisFocusController projectKey="beta" analysisRevision={0} focus="coverage" lens="overall" />
        <h2 id={projectAnalysisLandmarks.coverage} tabIndex={-1}>Coverage</h2>
      </>,
    )
    unmount()
    await flushFocusTimer()
    expect(scrollIntoView).not.toHaveBeenCalled()
    expect(focus).not.toHaveBeenCalled()
  })
})

function setReducedMotion(matches: boolean) {
  Object.defineProperty(window, 'matchMedia', {
    configurable: true,
    value: vi.fn().mockReturnValue({ matches }),
  })
}

async function flushFocusTimer() {
  await act(async () => {
    await vi.runOnlyPendingTimersAsync()
  })
}
