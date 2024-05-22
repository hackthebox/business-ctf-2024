import { Token } from '@ubeswap/sdk'
import { TokenInfo, TokenList } from '@uniswap/token-lists'
import { useEffect, useState } from 'react'

/**
 * Token instances created from token info.
 */
export class WrappedTokenInfo extends Token {
  public readonly tokenInfo: TokenInfo
  constructor(tokenInfo: TokenInfo) {
    super(tokenInfo.chainId, tokenInfo.address, tokenInfo.decimals, tokenInfo.symbol, tokenInfo.name)
    this.tokenInfo = tokenInfo
  }
  public get logoURI(): string | undefined {
    return this.tokenInfo.logoURI
  }
}

export type TokenAddressMap = Readonly<{
  [chainId: number]: Readonly<{
    [tokenAddress: string]: { token: WrappedTokenInfo; list: TokenList }
  }>
}>

/**
 * An empty result, useful as a default.
 */
const EMPTY_LIST: TokenAddressMap = {
  [1]: {},
}

const listCache: WeakMap<TokenList, TokenAddressMap> | null =
  typeof WeakMap !== 'undefined' ? new WeakMap<TokenList, TokenAddressMap>() : null

export function listToTokenMap(list: TokenList): TokenAddressMap {
  const result = listCache?.get(list)
  if (result) return result

  const map = list.tokens.reduce<TokenAddressMap>(
    (tokenMap, tokenInfo) => {
      const token = new WrappedTokenInfo(tokenInfo)
      if (tokenMap[token.chainId]?.[token.address] !== undefined)
        throw Error(`Duplicate tokens found for ${token.name}`)
      return {
        ...tokenMap,
        [token.chainId]: {
          ...tokenMap[token.chainId],
          [token.address]: {
            token,
            list,
          },
        },
      }
    },
    { ...EMPTY_LIST }
  )
  listCache?.set(list, map)
  return map
}

// get all the tokens from active lists, combine with local default tokens
export function useTokenList() {
  const [tokenList, setTokenList] = useState<TokenList | null>(null)
  useEffect(() => {
    const fetchTokenList = async () => {
      try {
        const response = await fetch('/constants/token-list.json')
        if (!response.ok) {
          throw new Error('Failed to fetch token list')
        }
        const data: TokenList = await response.json()
        setTokenList(data)
      } catch (error) {
        console.error('Error fetching token list:', error)
      }
    };

    fetchTokenList();
  }, []);
  return tokenList;
}

export function useCombinedActiveList(): TokenAddressMap {
  const tokenList = useTokenList()
  const defaultTokenMap = tokenList ? listToTokenMap(tokenList) : {}
  return defaultTokenMap
}

// all tokens from inactive lists
export function useCombinedInactiveList(): TokenAddressMap {
  return []
}
