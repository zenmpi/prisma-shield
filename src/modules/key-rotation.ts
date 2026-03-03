import { encrypt, decrypt } from '../crypto/aes'
import { generateBlindIndex } from '../crypto/hmac'

export interface KeyRotationConfig {
  oldKey: string | Buffer
  newKey: string | Buffer
  oldBlindIndexKey: string | Buffer
  newBlindIndexKey: string | Buffer
}

export interface KeyRotationResult {
  processed: number
  failed: number
  errors: Array<{ id: unknown; field: string; error: string }>
}

/**
 * Re-encrypts a single record's fields with new keys.
 * Returns a new object with only the re-encrypted fields and their new blind indexes.
 * The caller is responsible for updating the record in the database.
 */
export function reEncryptRecord(
  record: Record<string, any>,
  fields: string[],
  config: KeyRotationConfig,
): Record<string, any> {
  const updates: Record<string, any> = {}

  for (const field of fields) {
    const value = record[field]
    if (value === null || value === undefined) continue

    // Decrypt with old key
    const plaintext = decrypt(String(value), config.oldKey)

    // Re-encrypt with new key
    updates[field] = encrypt(plaintext, config.newKey)

    // Re-generate blind index with new key
    updates[`${field}_idx`] = generateBlindIndex(plaintext, config.newBlindIndexKey)
  }

  return updates
}

/**
 * Rotates encryption keys for all records in a dataset.
 * Accepts an array of records and returns update payloads for each.
 *
 * Usage:
 * ```ts
 * const users = await prisma.user.findMany()
 * const results = rotateKeys(users, ['email', 'ssn'], rotationConfig)
 * for (const { id, updates } of results.updates) {
 *   await prisma.user.update({ where: { id }, data: updates })
 * }
 * ```
 */
export function rotateKeys(
  records: Array<Record<string, any>>,
  fields: string[],
  config: KeyRotationConfig,
  idField = 'id',
): KeyRotationResult & { updates: Array<{ id: unknown; data: Record<string, any> }> } {
  const result: KeyRotationResult & {
    updates: Array<{ id: unknown; data: Record<string, any> }>
  } = {
    processed: 0,
    failed: 0,
    errors: [],
    updates: [],
  }

  for (const record of records) {
    try {
      const updates = reEncryptRecord(record, fields, config)
      result.updates.push({ id: record[idField], data: updates })
      result.processed++
    } catch (err) {
      result.failed++
      result.errors.push({
        id: record[idField],
        field: 'unknown',
        error: (err as Error).message,
      })
    }
  }

  return result
}
