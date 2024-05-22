import { Interface } from '@ethersproject/abi'
import { StaticJsonRpcProvider } from '@ethersproject/providers'
import { useMemo } from 'react'

import ERC20_ABI from '../constants/abis/erc20'
import { Erc20 } from '../generated'
import { getContract } from '../utils'
import { useConnectionInfo } from './useConnectionInfo'

export function useWeb3Provider() {
  /* eslint-disable-next-line */
  const [connectionInfo, isIstanceRunning] = useConnectionInfo()
  const RPC_ENDPOINT = connectionInfo['Player UUID' as keyof typeof connectionInfo]
  const provider = new StaticJsonRpcProvider(`/rpc/${RPC_ENDPOINT}`, 31337)
  return provider
}

export function useContract(address: string | undefined, ABI: Interface, withSignerIfPossible = true) {
  const library = useWeb3Provider()
  const account = undefined

  return useMemo(() => {
    if (!address || !ABI || !library) return null
    try {
      return getContract(address, ABI, library, withSignerIfPossible && account ? account : undefined)
    } catch (error) {
      console.error('Failed to get contract', error)
      return null
    }
  }, [address, ABI, library, withSignerIfPossible, account])
}

export function useTokenContract(tokenAddress: string | undefined, withSignerIfPossible?: boolean): Erc20 | null {
  return useContract(tokenAddress, ERC20_ABI, withSignerIfPossible) as Erc20 | null
}
