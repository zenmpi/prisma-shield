import { createShieldExtension } from './extension'
import { validateConfig } from './utils/validate'
import type { ShieldConfig } from './types'

export function shield(config: ShieldConfig) {
  validateConfig(config)
  return createShieldExtension(config)
}

// Types
export type {
  ShieldConfig,
  EncryptConfig,
  RlsConfig,
  AuditConfig,
  MaskConfig,
  ShieldContext,
  AuditEntry,
  AuditAdapter,
  MaskingStrategy,
} from './types'

// Key rotation
export { rotateKeys, reEncryptRecord } from './modules/key-rotation'
export type { KeyRotationConfig, KeyRotationResult } from './modules/key-rotation'

// Errors
export {
  ShieldError,
  ShieldEncryptionError,
  ShieldDecryptionError,
  ShieldContextError,
  ShieldConfigError,
} from './utils/errors'

// Crypto helpers
export { generateKey } from './crypto/keys'
