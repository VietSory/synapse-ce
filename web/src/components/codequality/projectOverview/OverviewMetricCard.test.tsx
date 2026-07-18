import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { overviewDetailTarget } from '../../../lib/projectOverviewDetailTargets'
import { metricCardsForLens, type OverviewMetricCardModel } from '../../../lib/projectOverviewPresentation'
import { buildAnalyzedOverview, unavailablePercentage } from '../../../test/projectOverviewFixtures'
import { OverviewMetricCard } from './OverviewMetricCard'

describe('OverviewMetricCard detail links', () => {
  it('renders a keyboard-reachable, metric-specific link for a truthful target', async () => {
    const card = metricCardsForLens(buildAnalyzedOverview().lenses.overall)[0]
    const target = overviewDetailTarget('synapse', 'overall', card)
    renderCard(card, target)

    const link = screen.getByRole('link', { name: 'View Security details' })
    expect(link).toHaveAttribute('href', '/code-quality/projects/synapse/analysis?focus=security&lens=overall')
    await userEvent.tab()
    expect(link).toHaveFocus()
    expect(link).toHaveClass('focus-visible:ring-2')
    expect(screen.getByRole('heading', { name: 'Security' }).closest('section')).not.toHaveAttribute('role', 'link')
  })

  it.each(['unavailable', 'not_supplied', 'not_applicable'] as const)(
    'keeps %s metrics non-interactive with their reason visible',
    (availability) => {
      const card: OverviewMetricCardModel = {
        key: 'coverage',
        kind: 'percentage',
        label: 'Coverage',
        metric: { ...unavailablePercentage('coverage_not_supplied'), availability },
      }
      renderCard(card, overviewDetailTarget('synapse', 'overall', card))

      expect(screen.queryByRole('link')).not.toBeInTheDocument()
      expect(screen.getByText('No coverage report was supplied.')).toBeInTheDocument()
      expect(screen.getByText('Details not available yet')).toBeInTheDocument()
    },
  )

  it('preserves honest percentage formatting when the card has a target', () => {
    const card: OverviewMetricCardModel = {
      key: 'coverage',
      kind: 'percentage',
      label: 'Coverage',
      metric: { availability: 'available', value: 99.96, unavailableReason: null },
    }
    renderCard(card, overviewDetailTarget('synapse', 'overall', card))
    expect(screen.getByText('99.9%')).toBeInTheDocument()
    expect(screen.queryByText('100%')).not.toBeInTheDocument()
  })
})

function renderCard(
  card: OverviewMetricCardModel,
  detailTarget: ReturnType<typeof overviewDetailTarget>,
) {
  return render(
    <MemoryRouter>
      <OverviewMetricCard card={card} detailTarget={detailTarget} lensLabel="Overall Code" />
    </MemoryRouter>,
  )
}
