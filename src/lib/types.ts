export type GenericObject = { [key: string]: any }

export const isFunction = (val: any) => typeof val === 'function'

export const isObject = (val: any) => typeof val === 'object'
