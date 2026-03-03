import { describe, it, expect, vi } from 'vitest'
import {
  encryptFieldValues,
  decryptFieldValues,
  transformWhereClause,
  handleEncryption,
  handleDecryption,
  processEncryptionForWrite,
} from '../src/modules/encrypt'
import { decrypt } from '../src/crypto/aes'
import { generateBlindIndex } from '../src/crypto/hmac'
import { generateKey } from '../src/crypto/keys'
import type { EncryptConfig } from '../src/types'

const TEST_KEY = generateKey()
const TEST_BLIND_KEY = generateKey()

const config: EncryptConfig = {
  key: TEST_KEY,
  blindIndexKey: TEST_BLIND_KEY,
  fields: {
    user: ['email', 'ssn'],
    payment: ['cardNumber'],
  },
}

describe('encryptFieldValues', () => {
  it('should encrypt specified fields and generate blind indexes', () => {
    const data = { email: 'john@test.com', name: 'John' }
    const result = encryptFieldValues(data, ['email'], TEST_KEY, TEST_BLIND_KEY, 'User', 'create')

    expect(result.email).not.toBe('john@test.com')
    expect(result.email_idx).toBe(generateBlindIndex('john@test.com', TEST_BLIND_KEY))
    expect(result.name).toBe('John')

    // Verify we can decrypt the encrypted value
    expect(decrypt(result.email, TEST_KEY)).toBe('john@test.com')
  })

  it('should not encrypt null values', () => {
    const data = { email: null, name: 'John' }
    const result = encryptFieldValues(data, ['email'], TEST_KEY, TEST_BLIND_KEY, 'User', 'create')
    expect(result.email).toBeNull()
    expect(result.email_idx).toBeUndefined()
  })

  it('should not encrypt undefined values', () => {
    const data = { name: 'John' }
    const result = encryptFieldValues(data, ['email'], TEST_KEY, TEST_BLIND_KEY, 'User', 'create')
    expect(result.email).toBeUndefined()
    expect(result.email_idx).toBeUndefined()
  })

  it('should encrypt multiple fields', () => {
    const data = { email: 'john@test.com', ssn: '123-45-6789', name: 'John' }
    const result = encryptFieldValues(
      data,
      ['email', 'ssn'],
      TEST_KEY,
      TEST_BLIND_KEY,
      'User',
      'create',
    )

    expect(decrypt(result.email, TEST_KEY)).toBe('john@test.com')
    expect(decrypt(result.ssn, TEST_KEY)).toBe('123-45-6789')
    expect(result.email_idx).toBeDefined()
    expect(result.ssn_idx).toBeDefined()
    expect(result.name).toBe('John')
  })
})

describe('decryptFieldValues', () => {
  it('should decrypt encrypted fields and remove index fields', () => {
    const encrypted = encryptFieldValues(
      { email: 'john@test.com', name: 'John' },
      ['email'],
      TEST_KEY,
      TEST_BLIND_KEY,
      'User',
      'create',
    )

    const result = decryptFieldValues(encrypted, ['email'], TEST_KEY, 'User')
    expect(result.email).toBe('john@test.com')
    expect(result.email_idx).toBeUndefined()
    expect(result.name).toBe('John')
  })

  it('should handle null values in decryption', () => {
    const data = { email: null, name: 'John' }
    const result = decryptFieldValues(data, ['email'], TEST_KEY, 'User')
    expect(result.email).toBeNull()
  })

  it('should return [DECRYPTION_FAILED] for invalid ciphertext', () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const data = { email: 'not-valid-ciphertext', name: 'John' }
    const result = decryptFieldValues(data, ['email'], TEST_KEY, 'User')
    expect(result.email).toBe('[DECRYPTION_FAILED]')
    consoleSpy.mockRestore()
  })
})

describe('transformWhereClause', () => {
  it('should replace field with blind index in where clause', () => {
    const where = { email: 'john@test.com' }
    const result = transformWhereClause(where, ['email'], TEST_BLIND_KEY)

    expect(result.email).toBeUndefined()
    expect(result.email_idx).toBe(generateBlindIndex('john@test.com', TEST_BLIND_KEY))
  })

  it('should not transform non-string values in where clause', () => {
    const where = { email: { contains: 'john' } }
    const result = transformWhereClause(where, ['email'], TEST_BLIND_KEY)

    expect(result.email).toEqual({ contains: 'john' })
    expect(result.email_idx).toBeUndefined()
  })

  it('should not transform fields not in the encrypted list', () => {
    const where = { name: 'John', email: 'john@test.com' }
    const result = transformWhereClause(where, ['email'], TEST_BLIND_KEY)

    expect(result.name).toBe('John')
    expect(result.email).toBeUndefined()
    expect(result.email_idx).toBeDefined()
  })
})

describe('handleEncryption', () => {
  it('should return unchanged args when model has no encrypted fields', () => {
    const args = { data: { name: 'John' } }
    const result = handleEncryption(args, 'Post', 'create', config)

    expect(result.args).toEqual(args)
    expect(result.shouldDecrypt).toBe(false)
  })

  it('should encrypt data for create operation', () => {
    const args = { data: { email: 'john@test.com', name: 'John' } }
    const result = handleEncryption(args, 'User', 'create', config)

    expect(result.args.data.email).not.toBe('john@test.com')
    expect(result.args.data.email_idx).toBeDefined()
    expect(result.args.data.name).toBe('John')
    expect(result.shouldDecrypt).toBe(true)
  })

  it('should transform where clause for findMany', () => {
    const args = { where: { email: 'john@test.com' } }
    const result = handleEncryption(args, 'User', 'findMany', config)

    expect(result.args.where.email).toBeUndefined()
    expect(result.args.where.email_idx).toBeDefined()
    expect(result.shouldDecrypt).toBe(true)
  })

  it('should handle upsert', () => {
    const args = {
      where: { email: 'john@test.com' },
      create: { email: 'john@test.com', name: 'John' },
      update: { email: 'new@test.com' },
    }
    const result = handleEncryption(args, 'User', 'upsert', config)

    expect(result.args.create.email_idx).toBeDefined()
    expect(result.args.update.email_idx).toBeDefined()
    expect(result.shouldDecrypt).toBe(true)
  })
})

describe('handleDecryption', () => {
  it('should decrypt a single result', () => {
    const encrypted = encryptFieldValues(
      { email: 'john@test.com', name: 'John' },
      ['email', 'ssn'],
      TEST_KEY,
      TEST_BLIND_KEY,
      'User',
      'create',
    )

    const result = handleDecryption(encrypted, 'User', config)
    expect(result.email).toBe('john@test.com')
    expect(result.email_idx).toBeUndefined()
  })

  it('should decrypt an array of results', () => {
    const items = [
      encryptFieldValues(
        { email: 'a@test.com', name: 'Alice' },
        ['email', 'ssn'],
        TEST_KEY,
        TEST_BLIND_KEY,
        'User',
        'create',
      ),
      encryptFieldValues(
        { email: 'b@test.com', name: 'Bob' },
        ['email', 'ssn'],
        TEST_KEY,
        TEST_BLIND_KEY,
        'User',
        'create',
      ),
    ]

    const result = handleDecryption(items, 'User', config)
    expect(result[0].email).toBe('a@test.com')
    expect(result[1].email).toBe('b@test.com')
  })

  it('should return null/undefined as-is', () => {
    expect(handleDecryption(null, 'User', config)).toBeNull()
    expect(handleDecryption(undefined, 'User', config)).toBeUndefined()
  })

  it('should return unchanged result for model without encrypted fields', () => {
    const data = { title: 'Hello' }
    expect(handleDecryption(data, 'Post', config)).toEqual(data)
  })
})

describe('processEncryptionForWrite (createMany)', () => {
  it('should encrypt each record in createMany', () => {
    const args = {
      data: [
        { email: 'a@test.com', name: 'A' },
        { email: 'b@test.com', name: 'B' },
      ],
    }

    const result = processEncryptionForWrite(args, ['email', 'ssn'], config, 'User', 'createMany')
    expect(result.data).toHaveLength(2)
    expect(decrypt(result.data[0].email, TEST_KEY)).toBe('a@test.com')
    expect(decrypt(result.data[1].email, TEST_KEY)).toBe('b@test.com')
    expect(result.data[0].email_idx).toBeDefined()
    expect(result.data[1].email_idx).toBeDefined()
  })
})
