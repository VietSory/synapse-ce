import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { projectAnalysisLandmarks } from '../../lib/projectAnalysisNavigation'
import { ProjectCoverageDetail } from './ProjectCoverageDetail'

describe('ProjectCoverageDetail', () => {
  it('renders the exact stored line counts and shared percentage precision', () => {
    render(<ProjectCoverageDetail coverage={{ coveredLines: 723, totalLines: 1000 }} />)
    const heading = screen.getByRole('heading', { name: 'Coverage' })
    expect(heading).toHaveAttribute('id', projectAnalysisLandmarks.coverage)
    expect(heading).toHaveAttribute('tabindex', '-1')
    expect(screen.getByText('72.3%')).toBeInTheDocument()
    expect(screen.getByText('723')).toBeInTheDocument()
    expect(screen.getByText('277')).toBeInTheDocument()
    expect(screen.getByText('1,000')).toBeInTheDocument()
    expect(screen.getByText('Covered lines')).toBeInTheDocument()
    expect(screen.getByText('Uncovered lines')).toBeInTheDocument()
    expect(screen.getByText('Executable lines')).toBeInTheDocument()
  })

  it.each([
    [{ coveredLines: 1, totalLines: 2500 }, '<0.1%'],
    [{ coveredLines: 2499, totalLines: 2500 }, '99.9%'],
    [{ coveredLines: 2500, totalLines: 2500 }, '100%'],
  ] as const)('preserves honest percentage boundary %j as %s', (coverage, expected) => {
    render(<ProjectCoverageDetail coverage={coverage} />)
    expect(screen.getByText(expected)).toBeInTheDocument()
  })

  it('renders honest no-report and no-executable-lines states', () => {
    const { rerender } = render(<ProjectCoverageDetail coverage={null} />)
    expect(screen.getByText('No coverage report was supplied for this analysis.')).toBeInTheDocument()
    expect(screen.queryByText('0%')).not.toBeInTheDocument()

    rerender(<ProjectCoverageDetail coverage={{ coveredLines: 0, totalLines: 0 }} />)
    expect(screen.getByText('No executable lines were found in this analysis.')).toBeInTheDocument()
    expect(screen.queryByText('100%')).not.toBeInTheDocument()
  })
})
