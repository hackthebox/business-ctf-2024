import { Pair, Token } from '@ubeswap/sdk'
import { useCallback, useEffect, useMemo } from 'react'
import ReactGA from 'react-ga'
import { shallowEqual, useDispatch, useSelector } from 'react-redux'

import { colors } from '../../theme'
import { AppDispatch, AppState } from '../index'
import {
  addSerializedPair,
  addSerializedToken,
  SerializedPair,
  SerializedToken,
  updateUserAllowMoolaWithdrawal,
  updateUserDarkMode,
  updateUserDeadline,
  updateUserDisableSmartRouting,
  updateUserExpertMode,
  updateUserMinApprove,
  updateUserSingleHopOnly,
  updateUserSlippageTolerance,
} from './actions'

function serializeToken(token: Token): SerializedToken {
  return {
    chainId: token.chainId,
    address: token.address,
    decimals: token.decimals,
    symbol: token.symbol,
    name: token.name,
  }
}

function deserializeToken(serializedToken: SerializedToken): Token {
  return new Token(
    serializedToken.chainId,
    serializedToken.address,
    serializedToken.decimals,
    serializedToken.symbol,
    serializedToken.name
  )
}

export function useIsDarkMode(): boolean {
  const { userDarkMode, matchesDarkMode } = useSelector<
    AppState,
    { userDarkMode: boolean | null; matchesDarkMode: boolean }
  >(
    ({ user: { matchesDarkMode, userDarkMode } }) => ({
      userDarkMode,
      matchesDarkMode,
    }),
    shallowEqual
  )

  return userDarkMode === null ? matchesDarkMode : userDarkMode
}

export function useDarkModeManager(): [boolean, () => void] {
  const dispatch = useDispatch<AppDispatch>()
  const darkMode = true // should be useIsDarkMode() but in this ctf only dark mode allowed

  useEffect(() => {
    const _colors = colors(darkMode)
  }, [darkMode])

  const toggleSetDarkMode = useCallback(() => {
    dispatch(updateUserDarkMode({ userDarkMode: !darkMode }))
  }, [darkMode, dispatch])

  return [darkMode, toggleSetDarkMode]
}

export function useIsExpertMode(): boolean {
  return useSelector<AppState, AppState['user']['userExpertMode']>((state) => state.user.userExpertMode)
}

export function useExpertModeManager(): [boolean, () => void] {
  const dispatch = useDispatch<AppDispatch>()
  const expertMode = useIsExpertMode()

  const toggleSetExpertMode = useCallback(() => {
    dispatch(updateUserExpertMode({ userExpertMode: !expertMode }))
  }, [expertMode, dispatch])

  return [expertMode, toggleSetExpertMode]
}

export function useUserMinApprove(): [boolean, (minApprove: boolean) => void] {
  const dispatch = useDispatch<AppDispatch>()
  const minApprove = useSelector<AppState, AppState['user']['userMinApprove']>((state) => state.user.userMinApprove)
  const setMinApprove = useCallback(
    (newMinApprove: boolean) => {
      dispatch(updateUserMinApprove({ userMinApprove: newMinApprove }))
    },
    [dispatch]
  )
  return [minApprove, setMinApprove]
}

export function useUserAllowMoolaWithdrawal(): [boolean, (allowMoolaWithdrawal: boolean) => void] {
  const dispatch = useDispatch<AppDispatch>()
  const allowMoolaWithdrawal = useSelector<AppState, AppState['user']['userAllowMoolaWithdrawal']>(
    (state) => state.user.userAllowMoolaWithdrawal
  )
  const setAllowMoolaWithdrawal = useCallback(
    (newallowMoolaWithdrawal: boolean) => {
      dispatch(updateUserAllowMoolaWithdrawal({ userAllowMoolaWithdrawal: newallowMoolaWithdrawal }))
    },
    [dispatch]
  )
  return [allowMoolaWithdrawal, setAllowMoolaWithdrawal]
}

export function useUserDisableSmartRouting(): [boolean, (disableSmartRouting: boolean) => void] {
  const dispatch = useDispatch<AppDispatch>()
  const disableSmartRouting = useSelector<AppState, AppState['user']['userDisableSmartRouting']>(
    (state) => state.user.userDisableSmartRouting
  )
  const setDisableSmartRouting = useCallback(
    (newSmartRouting: boolean) => {
      dispatch(updateUserDisableSmartRouting({ userDisableSmartRouting: newSmartRouting }))
    },
    [dispatch]
  )
  return [disableSmartRouting, setDisableSmartRouting]
}

export function useUserSingleHopOnly(): [boolean, (newSingleHopOnly: boolean) => void] {
  const dispatch = useDispatch<AppDispatch>()

  const singleHopOnly = useSelector<AppState, AppState['user']['userSingleHopOnly']>(
    (state) => state.user.userSingleHopOnly
  )

  const setSingleHopOnly = useCallback(
    (newSingleHopOnly: boolean) => {
      ReactGA.event({
        category: 'Routing',
        action: newSingleHopOnly ? 'enable single hop' : 'disable single hop',
      })
      dispatch(updateUserSingleHopOnly({ userSingleHopOnly: newSingleHopOnly }))
    },
    [dispatch]
  )

  return [singleHopOnly, setSingleHopOnly]
}

export function useUserSlippageTolerance(): [number, (slippage: number) => void] {
  const dispatch = useDispatch<AppDispatch>()
  const userSlippageTolerance = useSelector<AppState, AppState['user']['userSlippageTolerance']>((state) => {
    return state.user.userSlippageTolerance
  })

  const setUserSlippageTolerance = useCallback(
    (userSlippageTolerance: number) => {
      dispatch(updateUserSlippageTolerance({ userSlippageTolerance }))
    },
    [dispatch]
  )

  return [userSlippageTolerance, setUserSlippageTolerance]
}

export function useUserTransactionTTL(): [number, (slippage: number) => void] {
  const dispatch = useDispatch<AppDispatch>()
  const userDeadline = useSelector<AppState, AppState['user']['userDeadline']>((state) => {
    return state.user.userDeadline
  })

  const setUserDeadline = useCallback(
    (userDeadline: number) => {
      dispatch(updateUserDeadline({ userDeadline }))
    },
    [dispatch]
  )

  return [userDeadline, setUserDeadline]
}

export function useAddUserToken(): (token: Token) => void {
  const dispatch = useDispatch<AppDispatch>()
  return useCallback(
    (token: Token) => {
      dispatch(addSerializedToken({ serializedToken: serializeToken(token) }))
    },
    [dispatch]
  )
}

export function useUserAddedTokens(): Token[] {
  const serializedTokensMap = useSelector<AppState, AppState['user']['tokens']>(({ user: { tokens } }) => tokens)

  return useMemo(() => {
    return Object.values(serializedTokensMap[1] ?? {}).map(deserializeToken)
  }, [serializedTokensMap, 1])
}

function serializePair(pair: Pair): SerializedPair {
  return {
    token0: serializeToken(pair.token0),
    token1: serializeToken(pair.token1),
  }
}

export function usePairAdder(): (pair: Pair) => void {
  const dispatch = useDispatch<AppDispatch>()

  return useCallback(
    (pair: Pair) => {
      dispatch(addSerializedPair({ serializedPair: serializePair(pair) }))
    },
    [dispatch]
  )
}

export function useURLWarningVisible(): boolean {
  return useSelector((state: AppState) => state.user.URLWarningVisible)
}

/**
 * Given two tokens return the liquidity token that represents its liquidity shares
 * @param tokenA one of the two tokens
 * @param tokenB the other token
 */
export function toV2LiquidityToken([tokenA, tokenB]: [Token, Token]): Token {
  return new Token(tokenA.chainId, Pair.getAddress(tokenA, tokenB), 18, 'ULP', 'Ubeswap LP Token')
}
