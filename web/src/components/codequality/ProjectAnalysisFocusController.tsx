import { useEffect, useRef, useState } from 'react'
import {
  projectAnalysisLandmarkFor,
  type ProjectAnalysisFocus,
  type ProjectCodeLens,
} from '../../lib/projectAnalysisNavigation'

interface ProjectAnalysisFocusControllerProps {
  projectKey: string
  analysisRevision: number
  focus: ProjectAnalysisFocus | null
  lens: ProjectCodeLens
}

export function ProjectAnalysisFocusController({
  projectKey,
  analysisRevision,
  focus,
  lens,
}: ProjectAnalysisFocusControllerProps) {
  const handledSignature = useRef<string | null>(null)
  const [missingSignature, setMissingSignature] = useState<string | null>(null)
  const signature = focus === null ? null : `${projectKey}:${analysisRevision}:${lens}:${focus}`

  useEffect(() => {
    if (signature === null || focus === null || handledSignature.current === signature) return
    let active = true
    const timeout = window.setTimeout(() => {
      if (!active) return
      handledSignature.current = signature
      const target = document.getElementById(projectAnalysisLandmarkFor(focus, lens))
      if (!target) {
        setMissingSignature(signature)
        return
      }

      setMissingSignature(null)
      const prefersReducedMotion = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false
      target.scrollIntoView?.({
        block: 'start',
        behavior: prefersReducedMotion ? 'auto' : 'smooth',
      })
      target.focus({ preventScroll: true })
    }, 0)

    return () => {
      active = false
      window.clearTimeout(timeout)
    }
  }, [focus, lens, signature])

  if (signature === null || missingSignature !== signature) return null
  return (
    <p role="status" className="rounded-lg border border-border bg-elevated px-4 py-3 text-sm text-mutedfg">
      The requested detail is unavailable for this analysis.
    </p>
  )
}
