import { describe, it, expect, vi } from 'vitest'
import { validateConfig } from '../src/utils/validate'
import { generateKey } from '../src/crypto/keys'
import { ShieldConfigError } from '../src/utils/errors'
import type { ShieldConfig } from '../src/types'

const validKey = generateKey()
const validBlindKey = generateKey()

describe('validateConfig', () => {
  it('should throw if config is not an object', () => {
    expect(() => validateConfig(null as any)).toThrow(ShieldConfigError)
    expect(() => validateConfig(undefined as any)).toThrow(ShieldConfigError)
  })

  it('should throw if no modules are configured', () => {
    expect(() => validateConfig({} as ShieldConfig)).toThrow('at least one module')
  })

  // Encrypt validation
  it('should throw if encrypt.key is missing', () => {
    expect(() =>
      validateConfig({ encrypt: { key: '', blindIndexKey: validBlindKey, fields: { user: ['email'] } } }),
    ).toThrow('encrypt.key is required')
  })

  it('should throw if encrypt.key is invalid', () => {
    expect(() =>
      validateConfig({ encrypt: { key: 'badkey', blindIndexKey: validBlindKey, fields: { user: ['email'] } } }),
    ).toThrow('encrypt.key is invalid')
  })

  it('should throw if encrypt.blindIndexKey is missing', () => {
    expect(() =>
      validateConfig({ encrypt: { key: validKey, blindIndexKey: '', fields: { user: ['email'] } } }),
    ).toThrow('encrypt.blindIndexKey is required')
  })

  it('should throw if encrypt.fields is empty', () => {
    expect(() =>
      validateConfig({ encrypt: { key: validKey, blindIndexKey: validBlindKey, fields: {} } }),
    ).toThrow('non-empty object')
  })

  it('should throw if encrypt.fields has empty array', () => {
    expect(() =>
      validateConfig({ encrypt: { key: validKey, blindIndexKey: validBlindKey, fields: { user: [] } } }),
    ).toThrow('non-empty array')
  })

  it('should pass with valid encrypt config', () => {
    expect(() =>
      validateConfig({ encrypt: { key: validKey, blindIndexKey: validBlindKey, fields: { user: ['email'] } } }),
    ).not.toThrow()
  })

  // RLS validation
  it('should throw if rls.context is not a function', () => {
    expect(() =>
      validateConfig({
        rls: { context: 'not a function' as any, policies: { user: () => ({}) } },
      }),
    ).toThrow('must be a function')
  })

  it('should throw if rls.policies is empty', () => {
    expect(() =>
      validateConfig({
        rls: { context: () => ({ userId: '1', role: 'admin' }), policies: {} },
      }),
    ).toThrow('non-empty object')
  })

  it('should throw if rls.policies value is not a function', () => {
    expect(() =>
      validateConfig({
        rls: { context: () => ({ userId: '1', role: 'admin' }), policies: { user: 'bad' as any } },
      }),
    ).toThrow('must be a function')
  })

  // Audit validation
  it('should throw if audit enabled without adapter', () => {
    expect(() =>
      validateConfig({ audit: { enabled: true, adapter: undefined as any } }),
    ).toThrow('audit.adapter is required')
  })

  it('should throw if audit adapter has no log method', () => {
    expect(() =>
      validateConfig({ audit: { enabled: true, adapter: {} as any } }),
    ).toThrow('log() method')
  })

  // Mask validation
  it('should warn if mask without rls', () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
    validateConfig({ mask: { rules: { user: { email: { admin: 'none' } } } } })
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('mask module is configured without rls'),
    )
    warnSpy.mockRestore()
  })

  it('should not warn if mask with rls', () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
    validateConfig({
      mask: { rules: { user: { email: { admin: 'none' } } } },
      rls: { context: () => ({ userId: '1', role: 'admin' }), policies: { user: () => ({}) } },
    })
    expect(warnSpy).not.toHaveBeenCalled()
    warnSpy.mockRestore()
  })
})
