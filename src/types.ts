export interface ShieldContext {
  userId: string | number
  tenantId?: string | number
  role: string
  ip?: string
  [key: string]: any
}

export interface EncryptConfig {
  key: string | Buffer
  blindIndexKey: string | Buffer
  fields: {
    [model: string]: string[]
  }
}

export interface RlsConfig {
  context: () => ShieldContext | Promise<ShieldContext>
  policies: {
    [model: string]: (ctx: ShieldContext) => Record<string, any>
  }
  bypassRoles?: string[]
}

export interface AuditAdapter {
  log(entry: AuditEntry): void | Promise<void>
}

export interface AuditConfig {
  enabled: boolean
  adapter: AuditAdapter
  include?: string[]
  exclude?: string[]
  logReads?: boolean
  sanitize?: boolean
}

export type MaskingStrategy =
  | 'full'
  | 'partial'
  | 'hash'
  | 'none'
  | ((value: string) => string)

export interface MaskConfig {
  rules: {
    [model: string]: {
      [field: string]: {
        [role: string]: MaskingStrategy
      }
    }
  }
}

export interface ShieldConfig {
  encrypt?: EncryptConfig
  rls?: RlsConfig
  audit?: AuditConfig
  mask?: MaskConfig
}

export interface AuditEntry {
  timestamp: string
  action: 'create' | 'read' | 'update' | 'delete'
  model: string
  userId: string | number | null
  ip?: string
  operation: string
  args: Record<string, any>
  resultCount: number
  duration: number
}
