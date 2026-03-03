import { parseKey } from '../crypto/keys'
import { ShieldConfigError } from './errors'
import type { ShieldConfig } from '../types'

export function validateConfig(config: ShieldConfig): void {
  if (!config || typeof config !== 'object') {
    throw new ShieldConfigError('Shield config must be an object.')
  }

  const hasAnyModule = config.encrypt || config.rls || config.audit || config.mask
  if (!hasAnyModule) {
    throw new ShieldConfigError(
      'Shield config must include at least one module (encrypt, rls, audit, or mask).',
    )
  }

  if (config.encrypt) {
    validateEncryptConfig(config)
  }

  if (config.rls) {
    validateRlsConfig(config)
  }

  if (config.audit) {
    validateAuditConfig(config)
  }

  if (config.mask) {
    validateMaskConfig(config)
  }
}

function validateEncryptConfig(config: ShieldConfig): void {
  const enc = config.encrypt!

  if (!enc.key) {
    throw new ShieldConfigError('encrypt.key is required.')
  }
  try {
    parseKey(enc.key)
  } catch {
    throw new ShieldConfigError('encrypt.key is invalid. Provide a base64-encoded 256-bit key.')
  }

  if (!enc.blindIndexKey) {
    throw new ShieldConfigError('encrypt.blindIndexKey is required.')
  }
  try {
    parseKey(enc.blindIndexKey)
  } catch {
    throw new ShieldConfigError(
      'encrypt.blindIndexKey is invalid. Provide a base64-encoded 256-bit key.',
    )
  }

  if (!enc.fields || typeof enc.fields !== 'object' || Object.keys(enc.fields).length === 0) {
    throw new ShieldConfigError('encrypt.fields must be a non-empty object mapping models to field arrays.')
  }

  for (const [model, fields] of Object.entries(enc.fields)) {
    if (!Array.isArray(fields) || fields.length === 0) {
      throw new ShieldConfigError(
        `encrypt.fields.${model} must be a non-empty array of field names.`,
      )
    }
  }
}

function validateRlsConfig(config: ShieldConfig): void {
  const rls = config.rls!

  if (typeof rls.context !== 'function') {
    throw new ShieldConfigError('rls.context must be a function returning ShieldContext.')
  }

  if (!rls.policies || typeof rls.policies !== 'object' || Object.keys(rls.policies).length === 0) {
    throw new ShieldConfigError('rls.policies must be a non-empty object mapping models to policy functions.')
  }

  for (const [model, policyFn] of Object.entries(rls.policies)) {
    if (typeof policyFn !== 'function') {
      throw new ShieldConfigError(`rls.policies.${model} must be a function.`)
    }
  }
}

function validateAuditConfig(config: ShieldConfig): void {
  const audit = config.audit!

  if (audit.enabled && !audit.adapter) {
    throw new ShieldConfigError('audit.adapter is required when audit is enabled.')
  }

  if (audit.adapter && typeof audit.adapter.log !== 'function') {
    throw new ShieldConfigError('audit.adapter must implement a log() method.')
  }
}

function validateMaskConfig(config: ShieldConfig): void {
  const mask = config.mask!

  if (!mask.rules || typeof mask.rules !== 'object') {
    throw new ShieldConfigError('mask.rules must be an object.')
  }

  if (!config.rls) {
    console.warn(
      '[prisma-shield] Warning: mask module is configured without rls. Masking requires a user role from context. Configure rls.context to enable masking.',
    )
  }
}
