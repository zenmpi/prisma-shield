import type { AuditConfig, AuditEntry, ShieldContext } from '../types'

const ACTION_MAP: Record<string, AuditEntry['action']> = {
  create: 'create',
  createMany: 'create',
  createManyAndReturn: 'create',
  update: 'update',
  updateMany: 'update',
  upsert: 'update',
  delete: 'delete',
  deleteMany: 'delete',
  findFirst: 'read',
  findMany: 'read',
  findUnique: 'read',
  findUniqueOrThrow: 'read',
  findFirstOrThrow: 'read',
}

function mapOperationToAction(operation: string): AuditEntry['action'] {
  return ACTION_MAP[operation] ?? 'read'
}

function shouldLog(
  config: AuditConfig,
  model: string,
  operation: string,
): boolean {
  if (!config.enabled) return false

  const action = mapOperationToAction(operation)
  if (action === 'read' && !config.logReads) return false

  if (config.include && config.include.length > 0) {
    if (!config.include.includes(model.toLowerCase())) return false
  }

  if (config.exclude && config.exclude.length > 0) {
    if (config.exclude.includes(model.toLowerCase())) return false
  }

  return true
}

function sanitizeArgs(
  args: Record<string, any>,
  encryptedFields?: string[],
): Record<string, any> {
  if (!encryptedFields || encryptedFields.length === 0) return args

  const sanitized = { ...args }
  if (sanitized.data && typeof sanitized.data === 'object') {
    sanitized.data = { ...sanitized.data }
    for (const field of encryptedFields) {
      if (field in sanitized.data) {
        sanitized.data[field] = '[ENCRYPTED]'
      }
    }
  }
  if (sanitized.where && typeof sanitized.where === 'object') {
    sanitized.where = { ...sanitized.where }
    for (const field of encryptedFields) {
      if (field in sanitized.where) {
        sanitized.where[field] = '[ENCRYPTED]'
      }
    }
  }
  return sanitized
}

function getResultCount(result: any): number {
  if (result === null || result === undefined) return 0
  if (Array.isArray(result)) return result.length
  if (typeof result === 'object' && 'count' in result) return result.count
  return 1
}

export function handleAudit(
  config: AuditConfig,
  model: string,
  operation: string,
  args: Record<string, any>,
  result: any,
  duration: number,
  context: ShieldContext | null,
  encryptedFields?: string[],
): void {
  if (!shouldLog(config, model, operation)) return

  const sanitize = config.sanitize !== false
  const sanitizedArgs = sanitize ? sanitizeArgs(args, encryptedFields) : args

  const entry: AuditEntry = {
    timestamp: new Date().toISOString(),
    action: mapOperationToAction(operation),
    model: model.toLowerCase(),
    userId: context?.userId ?? null,
    ip: context?.ip,
    operation,
    args: sanitizedArgs,
    resultCount: getResultCount(result),
    duration,
  }

  // Fire-and-forget
  try {
    const maybePromise = config.adapter.log(entry)
    if (maybePromise && typeof (maybePromise as Promise<void>).catch === 'function') {
      ;(maybePromise as Promise<void>).catch((err) => {
        console.error('[prisma-shield] Audit adapter error:', err)
      })
    }
  } catch (err) {
    console.error('[prisma-shield] Audit adapter error:', err)
  }
}
