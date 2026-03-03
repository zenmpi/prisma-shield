import { createHash } from 'node:crypto'
import type { MaskConfig, MaskingStrategy } from '../types'

function applyFullMask(): string {
  return '********'
}

function applyPartialMask(value: string, field: string): string {
  // Email: j***@gmail.com
  if (field.toLowerCase().includes('email') || value.includes('@')) {
    const atIndex = value.indexOf('@')
    if (atIndex > 0) {
      const localPart = value.substring(0, atIndex)
      const domain = value.substring(atIndex)
      return localPart[0] + '***' + domain
    }
  }

  // SSN: ***-**-1234 (check before phone to avoid false match)
  if (field.toLowerCase().includes('ssn')) {
    const digits = value.replace(/\D/g, '')
    if (digits.length >= 4) {
      return '***-**-' + digits.slice(-4)
    }
  }

  // Phone: ****1234
  if (field.toLowerCase().includes('phone') || /^\+?\d[\d\s\-()]+$/.test(value)) {
    const digits = value.replace(/\D/g, '')
    if (digits.length >= 4) {
      return '****' + digits.slice(-4)
    }
  }

  // Name: J***
  if (field.toLowerCase().includes('name')) {
    return value[0] + '***'
  }

  // Default: first 2 chars + ***
  return value.substring(0, 2) + '***'
}

function applyHashMask(value: string): string {
  return createHash('sha256').update(value).digest('hex').substring(0, 8)
}

function applyMaskingStrategy(value: string, strategy: MaskingStrategy, field: string): string {
  if (typeof strategy === 'function') {
    return strategy(value)
  }

  switch (strategy) {
    case 'none':
      return value
    case 'full':
      return applyFullMask()
    case 'partial':
      return applyPartialMask(value, field)
    case 'hash':
      return applyHashMask(value)
    default:
      return applyFullMask()
  }
}

function maskRecord(
  data: Record<string, any>,
  model: string,
  role: string,
  rules: MaskConfig['rules'],
): Record<string, any> {
  const normalized = model.toLowerCase()
  const modelRules = rules[normalized]
  if (!modelRules) return data

  const result = { ...data }

  for (const [field, roleStrategies] of Object.entries(modelRules)) {
    if (!(field in result) || result[field] === null || result[field] === undefined) {
      continue
    }

    // If role not found in rules, apply full mask (secure by default)
    const strategy: MaskingStrategy = roleStrategies[role] ?? 'full'
    result[field] = applyMaskingStrategy(String(result[field]), strategy, field)
  }

  return result
}

export function handleMasking(
  result: any,
  model: string,
  role: string,
  config: MaskConfig,
): any {
  if (result === null || result === undefined) return result

  if (Array.isArray(result)) {
    return result.map((item) => maskRecord(item, model, role, config.rules))
  }

  if (typeof result === 'object') {
    return maskRecord(result, model, role, config.rules)
  }

  return result
}
