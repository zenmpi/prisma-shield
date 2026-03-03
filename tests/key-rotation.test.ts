import { describe, it, expect } from 'vitest'
import { reEncryptRecord, rotateKeys } from '../src/modules/key-rotation'
import { encrypt } from '../src/crypto/aes'
import { decrypt } from '../src/crypto/aes'
import { generateBlindIndex } from '../src/crypto/hmac'
import { generateKey } from '../src/crypto/keys'
import type { KeyRotationConfig } from '../src/modules/key-rotation'

const oldKey = generateKey()
const newKey = generateKey()
const oldBlindKey = generateKey()
const newBlindKey = generateKey()

const rotationConfig: KeyRotationConfig = {
  oldKey,
  newKey,
  oldBlindIndexKey: oldBlindKey,
  newBlindIndexKey: newBlindKey,
}

describe('reEncryptRecord', () => {
  it('should re-encrypt fields with new key', () => {
    const record = {
      id: 1,
      email: encrypt('john@test.com', oldKey),
      email_idx: generateBlindIndex('john@test.com', oldBlindKey),
      name: 'John',
    }

    const updates = reEncryptRecord(record, ['email'], rotationConfig)

    // Should be decryptable with new key
    expect(decrypt(updates.email, newKey)).toBe('john@test.com')
    // Should NOT be decryptable with old key
    expect(() => decrypt(updates.email, oldKey)).toThrow()
    // Blind index should match new key
    expect(updates.email_idx).toBe(generateBlindIndex('john@test.com', newBlindKey))
    // Should not include non-encrypted fields
    expect(updates.name).toBeUndefined()
    expect(updates.id).toBeUndefined()
  })

  it('should skip null values', () => {
    const record = { id: 1, email: null, name: 'John' }
    const updates = reEncryptRecord(record, ['email'], rotationConfig)
    expect(updates.email).toBeUndefined()
  })

  it('should handle multiple fields', () => {
    const record = {
      id: 1,
      email: encrypt('john@test.com', oldKey),
      ssn: encrypt('123-45-6789', oldKey),
    }

    const updates = reEncryptRecord(record, ['email', 'ssn'], rotationConfig)
    expect(decrypt(updates.email, newKey)).toBe('john@test.com')
    expect(decrypt(updates.ssn, newKey)).toBe('123-45-6789')
  })
})

describe('rotateKeys', () => {
  it('should rotate keys for all records', () => {
    const records = [
      { id: 1, email: encrypt('a@test.com', oldKey) },
      { id: 2, email: encrypt('b@test.com', oldKey) },
      { id: 3, email: encrypt('c@test.com', oldKey) },
    ]

    const result = rotateKeys(records, ['email'], rotationConfig)

    expect(result.processed).toBe(3)
    expect(result.failed).toBe(0)
    expect(result.updates).toHaveLength(3)

    expect(result.updates[0].id).toBe(1)
    expect(decrypt(result.updates[0].data.email, newKey)).toBe('a@test.com')

    expect(result.updates[2].id).toBe(3)
    expect(decrypt(result.updates[2].data.email, newKey)).toBe('c@test.com')
  })

  it('should track failures', () => {
    const records = [
      { id: 1, email: encrypt('a@test.com', oldKey) },
      { id: 2, email: 'not-encrypted-data' }, // will fail decryption
      { id: 3, email: encrypt('c@test.com', oldKey) },
    ]

    const result = rotateKeys(records, ['email'], rotationConfig)

    expect(result.processed).toBe(2)
    expect(result.failed).toBe(1)
    expect(result.errors).toHaveLength(1)
    expect(result.errors[0].id).toBe(2)
  })

  it('should use custom id field', () => {
    const records = [
      { uuid: 'abc', email: encrypt('a@test.com', oldKey) },
    ]

    const result = rotateKeys(records, ['email'], rotationConfig, 'uuid')
    expect(result.updates[0].id).toBe('abc')
  })
})
