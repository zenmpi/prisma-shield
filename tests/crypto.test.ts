import { describe, it, expect } from 'vitest'
import { encrypt, decrypt } from '../src/crypto/aes'
import { generateBlindIndex } from '../src/crypto/hmac'
import { parseKey, generateKey } from '../src/crypto/keys'

const TEST_KEY = generateKey()
const TEST_BLIND_KEY = generateKey()

describe('AES-256-GCM', () => {
  it('should encrypt and decrypt a string', () => {
    const plaintext = 'hello@example.com'
    const ciphertext = encrypt(plaintext, TEST_KEY)
    const decrypted = decrypt(ciphertext, TEST_KEY)
    expect(decrypted).toBe(plaintext)
  })

  it('should produce different ciphertext for the same plaintext (random IV)', () => {
    const plaintext = 'test@test.com'
    const ct1 = encrypt(plaintext, TEST_KEY)
    const ct2 = encrypt(plaintext, TEST_KEY)
    expect(ct1).not.toBe(ct2)
  })

  it('should handle empty string', () => {
    const ciphertext = encrypt('', TEST_KEY)
    const decrypted = decrypt(ciphertext, TEST_KEY)
    expect(decrypted).toBe('')
  })

  it('should handle unicode characters', () => {
    const plaintext = 'Привіт Світ 🌍'
    const ciphertext = encrypt(plaintext, TEST_KEY)
    const decrypted = decrypt(ciphertext, TEST_KEY)
    expect(decrypted).toBe(plaintext)
  })

  it('should handle long strings', () => {
    const plaintext = 'a'.repeat(10000)
    const ciphertext = encrypt(plaintext, TEST_KEY)
    const decrypted = decrypt(ciphertext, TEST_KEY)
    expect(decrypted).toBe(plaintext)
  })

  it('should fail to decrypt with wrong key', () => {
    const ciphertext = encrypt('secret', TEST_KEY)
    const wrongKey = generateKey()
    expect(() => decrypt(ciphertext, wrongKey)).toThrow()
  })

  it('should fail to decrypt corrupted ciphertext', () => {
    const ciphertext = encrypt('secret', TEST_KEY)
    const corrupted = ciphertext.slice(0, -4) + 'AAAA'
    expect(() => decrypt(corrupted, TEST_KEY)).toThrow()
  })

  it('should fail to decrypt too-short ciphertext', () => {
    expect(() => decrypt(Buffer.from('short').toString('base64'), TEST_KEY)).toThrow(
      'Invalid ciphertext: too short',
    )
  })

  it('should produce base64-encoded output', () => {
    const ciphertext = encrypt('test', TEST_KEY)
    expect(() => Buffer.from(ciphertext, 'base64')).not.toThrow()
    const decoded = Buffer.from(ciphertext, 'base64')
    // IV(12) + AuthTag(16) + at least some ciphertext
    expect(decoded.length).toBeGreaterThanOrEqual(28)
  })
})

describe('HMAC-SHA256 Blind Index', () => {
  it('should generate consistent hash for same value', () => {
    const h1 = generateBlindIndex('test@example.com', TEST_BLIND_KEY)
    const h2 = generateBlindIndex('test@example.com', TEST_BLIND_KEY)
    expect(h1).toBe(h2)
  })

  it('should normalize input (lowercase + trim)', () => {
    const h1 = generateBlindIndex('Test@Example.COM', TEST_BLIND_KEY)
    const h2 = generateBlindIndex('  test@example.com  ', TEST_BLIND_KEY)
    expect(h1).toBe(h2)
  })

  it('should produce different hash for different values', () => {
    const h1 = generateBlindIndex('alice@test.com', TEST_BLIND_KEY)
    const h2 = generateBlindIndex('bob@test.com', TEST_BLIND_KEY)
    expect(h1).not.toBe(h2)
  })

  it('should produce different hash with different key', () => {
    const key2 = generateKey()
    const h1 = generateBlindIndex('test', TEST_BLIND_KEY)
    const h2 = generateBlindIndex('test', key2)
    expect(h1).not.toBe(h2)
  })

  it('should return a hex string', () => {
    const hash = generateBlindIndex('test', TEST_BLIND_KEY)
    expect(hash).toMatch(/^[0-9a-f]{64}$/)
  })
})

describe('Key Management', () => {
  it('should generate a valid base64 key', () => {
    const key = generateKey()
    const buffer = Buffer.from(key, 'base64')
    expect(buffer.length).toBe(32)
  })

  it('should parse a base64 string key', () => {
    const key = generateKey()
    const buffer = parseKey(key)
    expect(buffer.length).toBe(32)
  })

  it('should parse a Buffer key', () => {
    const buffer = Buffer.alloc(32, 1)
    const parsed = parseKey(buffer)
    expect(parsed).toBe(buffer)
  })

  it('should reject a Buffer key with wrong length', () => {
    const buffer = Buffer.alloc(16, 1)
    expect(() => parseKey(buffer)).toThrow('Key must be 32 bytes')
  })

  it('should reject a base64 key with wrong length', () => {
    const shortKey = Buffer.alloc(16).toString('base64')
    expect(() => parseKey(shortKey)).toThrow('must decode to 32 bytes')
  })
})
