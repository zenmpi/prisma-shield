export class ShieldError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ShieldError'
  }
}

export class ShieldEncryptionError extends ShieldError {
  constructor(model: string, field: string, operation: string, cause?: Error) {
    super(
      `Encryption failed for ${model}.${field} during ${operation}${cause ? `: ${cause.message}` : ''}`,
    )
    this.name = 'ShieldEncryptionError'
  }
}

export class ShieldDecryptionError extends ShieldError {
  constructor(model: string, field: string, cause?: Error) {
    super(
      `Decryption failed for ${model}.${field}${cause ? `: ${cause.message}` : ''}`,
    )
    this.name = 'ShieldDecryptionError'
  }
}

export class ShieldContextError extends ShieldError {
  constructor(message?: string) {
    super(message ?? 'Shield context is not available. Ensure context provider is configured.')
    this.name = 'ShieldContextError'
  }
}

export class ShieldConfigError extends ShieldError {
  constructor(message: string) {
    super(message)
    this.name = 'ShieldConfigError'
  }
}
