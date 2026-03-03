import type { RlsConfig, ShieldContext } from '../types'
import { ShieldContextError } from '../utils/errors'

const READ_OPERATIONS = new Set([
  'findFirst',
  'findMany',
  'findUnique',
  'findUniqueOrThrow',
  'findFirstOrThrow',
])

const UPDATE_OPERATIONS = new Set(['update', 'updateMany'])
const DELETE_OPERATIONS = new Set(['delete', 'deleteMany'])
const CREATE_OPERATIONS = new Set(['create', 'createMany', 'createManyAndReturn'])

export async function resolveContext(config: RlsConfig): Promise<ShieldContext> {
  const ctx = await config.context()
  if (!ctx || !ctx.userId || !ctx.role) {
    throw new ShieldContextError(
      'Shield context must include at least userId and role.',
    )
  }
  return ctx
}

function shouldBypass(context: ShieldContext, bypassRoles?: string[]): boolean {
  if (!bypassRoles || bypassRoles.length === 0) return false
  return bypassRoles.includes(context.role)
}

function getPolicy(
  config: RlsConfig,
  model: string,
  context: ShieldContext,
): Record<string, any> | null {
  const normalized = model.toLowerCase()
  const policyFn = config.policies[normalized]
  if (!policyFn) return null
  return policyFn(context)
}

function mergeWhere(
  existing: Record<string, any> | undefined,
  rlsFilter: Record<string, any>,
): Record<string, any> {
  if (!existing || Object.keys(existing).length === 0) {
    return rlsFilter
  }
  return { AND: [existing, rlsFilter] }
}

function applyToCreateData(
  data: Record<string, any>,
  rlsFilter: Record<string, any>,
): Record<string, any> {
  return { ...rlsFilter, ...data }
}

export async function handleRls(
  args: any,
  model: string,
  operation: string,
  config: RlsConfig,
): Promise<{ args: any; context: ShieldContext }> {
  const context = await resolveContext(config)

  if (shouldBypass(context, config.bypassRoles)) {
    return { args, context }
  }

  const policy = getPolicy(config, model, context)
  if (!policy) {
    return { args, context }
  }

  const newArgs = { ...args }

  if (READ_OPERATIONS.has(operation) || UPDATE_OPERATIONS.has(operation) || DELETE_OPERATIONS.has(operation)) {
    newArgs.where = mergeWhere(newArgs.where, policy)
  }

  if (CREATE_OPERATIONS.has(operation)) {
    if (operation === 'createMany' || operation === 'createManyAndReturn') {
      if (Array.isArray(newArgs.data)) {
        newArgs.data = newArgs.data.map((item: Record<string, any>) =>
          applyToCreateData(item, policy),
        )
      }
    } else {
      if (newArgs.data) {
        newArgs.data = applyToCreateData(newArgs.data, policy)
      }
    }
  }

  if (operation === 'upsert') {
    newArgs.where = mergeWhere(newArgs.where, policy)
    if (newArgs.create) {
      newArgs.create = applyToCreateData(newArgs.create, policy)
    }
  }

  return { args: newArgs, context }
}
