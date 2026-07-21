import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach } from 'vitest'

// React Router passes jsdom's AbortSignal to Node's native Request during navigation.
// Node rejects that cross-realm signal, though jsdom never performs the request.
const NativeRequest = globalThis.Request
if (NativeRequest) {
  globalThis.Request = new Proxy(NativeRequest, {
    construct(target, [input, init]) {
      if (!init?.signal) return new target(input, init)
      const { signal: _, ...withoutSignal } = init
      return new target(input, withoutSignal)
    },
  }) as typeof Request
}

afterEach(() => {
  cleanup()
})
