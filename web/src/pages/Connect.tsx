import { KeyRound, Loader2, ShieldCheck } from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { useAuth } from '../auth/AuthContext'
import { Button, Card, ErrorState, Field, Input } from '../components/ui'
import logoFull from '../assets/logo-full-dark.png'

export function Connect() {
  const { phase, aup, error, connecting, connect, acceptAup, logout } = useAuth()
  const [token, setToken] = useState('')
  const [accepting, setAccepting] = useState(false)

  if (phase === 'connecting') {
    return (
      <Center>
        <Loader2 className="size-6 animate-spin text-accent" />
        <p className="mt-3 text-sm text-mutedfg">Restoring session…</p>
      </Center>
    )
  }

  return (
    <Center>
      <div className="mb-7 flex flex-col items-center gap-3 text-center">
        <img src={logoFull} alt="Synapse" className="h-20 w-auto" />
        <p className="text-xs text-mutedfg">Security &amp; pentest operations</p>
      </div>

      {phase === 'need-aup' && aup ? (
        <Card title="Acceptable Use Policy" className="w-full max-w-lg animate-fade-in">
          <p className="whitespace-pre-line text-sm leading-relaxed text-mutedfg">{aup.text}</p>
          <div className="mt-5 flex items-center justify-between gap-3">
            <button
              type="button"
              onClick={logout}
              className="text-xs text-mutedfg underline-offset-2 hover:text-foreground hover:underline"
            >
              Use a different token
            </button>
            <Button
              variant="brand"
              loading={accepting}
              onClick={async () => {
                setAccepting(true)
                try {
                  await acceptAup()
                } finally {
                  setAccepting(false)
                }
              }}
            >
              <ShieldCheck className="size-4" /> Accept &amp; continue
            </Button>
          </div>
          <p className="mt-3 text-center text-[11px] text-subtlefg">Policy version {aup.version}</p>
        </Card>
      ) : (
        <Card className="w-full max-w-[420px] animate-fade-in">
          <form
            onSubmit={(e) => {
              e.preventDefault()
              connect(token)
            }}
            className="space-y-4"
          >
            <div className="flex items-center gap-2 text-sm font-medium">
              <KeyRound className="size-4 text-brand" /> Connect to the API
            </div>
            <Field label="API token">
              <Input
                type="password"
                autoFocus
                value={token}
                onChange={(e) => setToken(e.target.value)}
                placeholder="paste token…"
                className="font-mono"
                aria-label="API token"
              />
            </Field>
            {error && <ErrorState message={error} />}
            <Button variant="brand" type="submit" loading={connecting} className="w-full">
              Connect
            </Button>
          </form>
        </Card>
      )}
    </Center>
  )
}

function Center({ children }: { children: ReactNode }) {
  return <div className="bg-auth flex min-h-screen flex-col items-center justify-center px-4">{children}</div>
}
