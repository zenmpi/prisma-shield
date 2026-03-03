import { encrypt, decrypt } from '../crypto/aes'
import { generateBlindIndex } from '../crypto/hmac'
import type { EncryptConfig } from '../types'
import { ShieldDecryptionError, ShieldEncryptionError } from '../utils/errors'

const WRITE_OPERATIONS = new Set([
  'create',
  'update',
  'upsert',
  'createMany',
  'createManyAndReturn',
  'updateMany',
])

const READ_OPERATIONS = new Set([
  'findFirst',
  'findMany',
  'findUnique',
  'findUniqueOrThrow',
  'findFirstOrThrow',
])

const WHERE_OPERATIONS = new Set([
  'findFirst',
  'findMany',
  'findUnique',
  'findUniqueOrThrow',
  'findFirstOrThrow',
  'update',
  'updateMany',
  'delete',
  'deleteMany',
  'upsert',
])

export function getEncryptedFields(config: EncryptConfig, model: string): string[] | undefined {
  const normalized = model.toLowerCase()
  return config.fields[normalized]
}

export function encryptFieldValues(
  data: Record<string, any>,
  fields: string[],
  key: string | Buffer,
  blindIndexKey: string | Buffer,
  model: string,
  operation: string,
): Record<string, any> {
  const result = { ...data }

  for (const field of fields) {
    if (field in result && result[field] !== null && result[field] !== undefined) {
      const value = String(result[field])
      try {
        result[field] = encrypt(value, key)
        result[`${field}_idx`] = generateBlindIndex(value, blindIndexKey)
      } catch (err) {
        throw new ShieldEncryptionError(model, field, operation, err as Error)
      }
    }
  }

  return result
}

export function decryptFieldValues(
  data: Record<string, any>,
  fields: string[],
  key: string | Buffer,
  model: string,
): Record<string, any> {
  const result = { ...data }

  for (const field of fields) {
    if (field in result && result[field] !== null && result[field] !== undefined) {
      try {
        result[field] = decrypt(String(result[field]), key)
      } catch (err) {
        console.error(new ShieldDecryptionError(model, field, err as Error))
        result[field] = '[DECRYPTION_FAILED]'
      }
    }
    // Remove blind index fields from response
    delete result[`${field}_idx`]
  }

  return result
}

export function transformWhereClause(
  where: Record<string, any>,
  fields: string[],
  blindIndexKey: string | Buffer,
): Record<string, any> {
  const result = { ...where }

  for (const field of fields) {
    if (field in result) {
      const value = result[field]
      // Only transform direct equality matches (string values)
      if (typeof value === 'string') {
        const hmac = generateBlindIndex(value, blindIndexKey)
        result[`${field}_idx`] = hmac
        delete result[field]
      }
    }
  }

  return result
}

function encryptDataPayload(
  data: any,
  fields: string[],
  key: string | Buffer,
  blindIndexKey: string | Buffer,
  model: string,
  operation: string,
): any {
  if (Array.isArray(data)) {
    return data.map((item) => encryptFieldValues(item, fields, key, blindIndexKey, model, operation))
  }
  return encryptFieldValues(data, fields, key, blindIndexKey, model, operation)
}

function decryptResult(
  result: any,
  fields: string[],
  key: string | Buffer,
  model: string,
): any {
  if (result === null || result === undefined) return result
  if (Array.isArray(result)) {
    return result.map((item) => decryptFieldValues(item, fields, key, model))
  }
  return decryptFieldValues(result, fields, key, model)
}

export function processEncryptionForWrite(
  args: any,
  fields: string[],
  config: EncryptConfig,
  model: string,
  operation: string,
): any {
  const newArgs = { ...args }

  if (operation === 'createMany' || operation === 'createManyAndReturn') {
    if (newArgs.data) {
      newArgs.data = encryptDataPayload(
        newArgs.data,
        fields,
        config.key,
        config.blindIndexKey,
        model,
        operation,
      )
    }
  } else if (operation === 'upsert') {
    if (newArgs.create) {
      newArgs.create = encryptFieldValues(
        newArgs.create,
        fields,
        config.key,
        config.blindIndexKey,
        model,
        operation,
      )
    }
    if (newArgs.update) {
      newArgs.update = encryptFieldValues(
        newArgs.update,
        fields,
        config.key,
        config.blindIndexKey,
        model,
        operation,
      )
    }
  } else {
    if (newArgs.data) {
      newArgs.data = encryptFieldValues(
        newArgs.data,
        fields,
        config.key,
        config.blindIndexKey,
        model,
        operation,
      )
    }
  }

  return newArgs
}

export function processEncryptionForWhere(
  args: any,
  fields: string[],
  blindIndexKey: string | Buffer,
): any {
  if (!args.where) return args
  const newArgs = { ...args }
  newArgs.where = transformWhereClause(newArgs.where, fields, blindIndexKey)
  return newArgs
}

export function handleEncryption(
  args: any,
  model: string,
  operation: string,
  config: EncryptConfig,
): { args: any; shouldDecrypt: boolean } {
  const fields = getEncryptedFields(config, model)
  if (!fields || fields.length === 0) {
    return { args, shouldDecrypt: false }
  }

  let newArgs = { ...args }

  // Transform where clause for operations that use it
  if (WHERE_OPERATIONS.has(operation)) {
    newArgs = processEncryptionForWhere(newArgs, fields, config.blindIndexKey)
  }

  // Encrypt data for write operations
  if (WRITE_OPERATIONS.has(operation)) {
    newArgs = processEncryptionForWrite(newArgs, fields, config, model, operation)
  }

  const shouldDecrypt = READ_OPERATIONS.has(operation) || operation === 'create' || operation === 'update' || operation === 'upsert' || operation === 'createManyAndReturn'

  return { args: newArgs, shouldDecrypt }
}

export function handleDecryption(
  result: any,
  model: string,
  config: EncryptConfig,
): any {
  const fields = getEncryptedFields(config, model)
  if (!fields || fields.length === 0) return result
  return decryptResult(result, fields, config.key, model)
}
