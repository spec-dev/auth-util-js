import { isFunction, isObject, GenericObject } from './types'
import { SPEC_WEBHOOK_API_HEADER } from './constants'
import jwt from 'jsonwebtoken'

function getRequestHeader(maybeReq: any, header: string): string | null {
    if (!maybeReq) return null

    // req.header('...')
    if (isFunction(maybeReq.header)) {
        return maybeReq.header(header)
    }
    // req.headers['...']
    else if (isObject(maybeReq.headers)) {
        return maybeReq.headers[header] || maybeReq.headers[header.toLowerCase()]
    }
    // headers['...']
    else if (isObject(maybeReq)) {
        return maybeReq[header] || maybeReq[header.toLowerCase()]
    }

    return null
}

function getBearerToken(maybeReq: any): string | null {
    const authHeader = getRequestHeader(maybeReq, 'Authorization')
    if (!authHeader) return null

    const comps = authHeader.split(' ')
    if (comps.length !== 2) return null

    const [tokenType, token] = comps
    if (tokenType.toLowerCase() !== 'bearer') return null

    return token
}

function parseJwtClaims(token: string, jwtSecret: string): GenericObject | null {
    try {
        const claims = jwt.verify(token, jwtSecret)
        return claims as GenericObject
    } catch (err) {
        return null
    }
}

export function authSpecWebhook(
    maybeReq: any,
    specApiKey: string | undefined = process.env.SPEC_API_KEY
): boolean {
    const specApiHeader = getRequestHeader(maybeReq, SPEC_WEBHOOK_API_HEADER)
    return !!specApiHeader && specApiHeader === specApiKey
}

export function getCurrentUserAddress(
    maybeReq: any,
    specJwtSecret: string | undefined = process.env.SPEC_JWT_SECRET
): string | null {
    // Parse bearer token from request headers.
    const bearerToken = getBearerToken(maybeReq)
    if (!bearerToken) {
        return null
    }

    // Verify and parse claims from JWT.
    const claims = parseJwtClaims(bearerToken, specJwtSecret!)
    if (!claims) {
        return null
    }

    // The "sub" claim maps to the user address.
    return claims.sub
}
