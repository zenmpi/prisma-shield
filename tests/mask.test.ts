import { describe, it, expect } from 'vitest'
import { handleMasking } from '../src/modules/mask'
import type { MaskConfig } from '../src/types'

const maskConfig: MaskConfig = {
  rules: {
    user: {
      email: {
        admin: 'none',
        support: 'partial',
        analyst: 'full',
      },
      ssn: {
        admin: 'partial',
        support: 'full',
        analyst: 'full',
      },
      phone: {
        admin: 'none',
        support: 'partial',
        analyst: 'full',
      },
      name: {
        admin: 'none',
        support: 'partial',
        analyst: 'hash',
      },
    },
  },
}

describe('handleMasking — none strategy', () => {
  it('should return value unchanged', () => {
    const result = handleMasking({ email: 'john@test.com' }, 'User', 'admin', maskConfig)
    expect(result.email).toBe('john@test.com')
  })
})

describe('handleMasking — full strategy', () => {
  it('should return ********', () => {
    const result = handleMasking({ email: 'john@test.com' }, 'User', 'analyst', maskConfig)
    expect(result.email).toBe('********')
  })
})

describe('handleMasking — partial strategy', () => {
  it('should partially mask email (j***@test.com)', () => {
    const result = handleMasking({ email: 'john@test.com' }, 'User', 'support', maskConfig)
    expect(result.email).toBe('j***@test.com')
  })

  it('should partially mask phone (****1234)', () => {
    const result = handleMasking({ phone: '+1-555-123-4567' }, 'User', 'support', maskConfig)
    expect(result.phone).toBe('****4567')
  })

  it('should partially mask SSN (***-**-6789)', () => {
    const result = handleMasking({ ssn: '123-45-6789' }, 'User', 'admin', maskConfig)
    expect(result.ssn).toBe('***-**-6789')
  })

  it('should partially mask name (J***)', () => {
    const result = handleMasking({ name: 'John' }, 'User', 'support', maskConfig)
    expect(result.name).toBe('J***')
  })
})

describe('handleMasking — hash strategy', () => {
  it('should return first 8 chars of SHA256 hash', () => {
    const result = handleMasking({ name: 'John' }, 'User', 'analyst', maskConfig)
    expect(result.name).toMatch(/^[0-9a-f]{8}$/)
  })

  it('should produce consistent hash for same input', () => {
    const r1 = handleMasking({ name: 'John' }, 'User', 'analyst', maskConfig)
    const r2 = handleMasking({ name: 'John' }, 'User', 'analyst', maskConfig)
    expect(r1.name).toBe(r2.name)
  })
})

describe('handleMasking — custom function', () => {
  it('should apply custom masking function', () => {
    const customConfig: MaskConfig = {
      rules: {
        user: {
          email: {
            custom: (value: string) => `***${value.split('@')[1]}`,
          },
        },
      },
    }

    const result = handleMasking({ email: 'john@test.com' }, 'User', 'custom', customConfig)
    expect(result.email).toBe('***test.com')
  })
})

describe('handleMasking — edge cases', () => {
  it('should apply full mask for unknown role (secure by default)', () => {
    const result = handleMasking({ email: 'john@test.com' }, 'User', 'unknown_role', maskConfig)
    expect(result.email).toBe('********')
  })

  it('should return null as-is', () => {
    const result = handleMasking({ email: null }, 'User', 'analyst', maskConfig)
    expect(result.email).toBeNull()
  })

  it('should return undefined as-is', () => {
    const result = handleMasking({ email: undefined }, 'User', 'analyst', maskConfig)
    expect(result.email).toBeUndefined()
  })

  it('should handle null result', () => {
    expect(handleMasking(null, 'User', 'admin', maskConfig)).toBeNull()
  })

  it('should handle undefined result', () => {
    expect(handleMasking(undefined, 'User', 'admin', maskConfig)).toBeUndefined()
  })

  it('should handle array of results', () => {
    const items = [
      { email: 'a@test.com', name: 'Alice' },
      { email: 'b@test.com', name: 'Bob' },
    ]
    const result = handleMasking(items, 'User', 'analyst', maskConfig)
    expect(result[0].email).toBe('********')
    expect(result[1].email).toBe('********')
    expect(result[0].name).toMatch(/^[0-9a-f]{8}$/)
  })

  it('should not mask fields without rules', () => {
    const result = handleMasking(
      { email: 'john@test.com', age: 30 },
      'User',
      'analyst',
      maskConfig,
    )
    expect(result.email).toBe('********')
    expect(result.age).toBe(30)
  })

  it('should not mask model without rules', () => {
    const data = { title: 'Hello', content: 'World' }
    const result = handleMasking(data, 'Post', 'analyst', maskConfig)
    expect(result).toEqual(data)
  })
})
