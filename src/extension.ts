import { Prisma } from '@prisma/client'
import type { ShieldConfig, ShieldContext } from './types'
import { handleEncryption, handleDecryption, getEncryptedFields } from './modules/encrypt'
import { handleRls } from './modules/rls'
import { handleAudit } from './modules/audit'
import { handleMasking } from './modules/mask'

export function createShieldExtension(config: ShieldConfig) {
  return Prisma.defineExtension({
    name: 'prisma-shield',
    query: {
      $allModels: {
        async $allOperations({ model, operation, args, query }) {
          const startTime = Date.now()
          let context: ShieldContext | null = null
          let processedArgs = { ...args }

          // Step 1: RLS — resolve context and apply row-level security
          if (config.rls) {
            const rlsResult = await handleRls(processedArgs, model, operation, config.rls)
            processedArgs = rlsResult.args
            context = rlsResult.context
          }

          // Step 2: Encryption — encrypt fields and transform where clauses
          let shouldDecrypt = false
          if (config.encrypt) {
            const encResult = handleEncryption(processedArgs, model, operation, config.encrypt)
            processedArgs = encResult.args
            shouldDecrypt = encResult.shouldDecrypt
          }

          // Step 3: Execute the actual Prisma query
          let result = await query(processedArgs)

          const duration = Date.now() - startTime

          // Step 4: Audit — log the operation (fire-and-forget)
          if (config.audit) {
            const encryptedFields = config.encrypt
              ? getEncryptedFields(config.encrypt, model)
              : undefined
            handleAudit(
              config.audit,
              model,
              operation,
              args, // original args, not processed
              result,
              duration,
              context,
              encryptedFields,
            )
          }

          // Step 5: Decryption — decrypt encrypted fields in the result
          if (shouldDecrypt && config.encrypt) {
            result = handleDecryption(result, model, config.encrypt)
          }

          // Step 6: Masking — apply data masking based on role
          if (config.mask && context) {
            result = handleMasking(result, model, context.role, config.mask)
          }

          return result
        },
      },
    },
  })
}
