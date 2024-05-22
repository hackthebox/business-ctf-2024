import { formatUnits } from '@ethersproject/units'
import { ERC20_ABI } from 'constants/abis/erc20'
import { Contract, Wallet } from 'ethers'
import { useEffect, useState } from 'react'

import { useAllTokens } from './Tokens'
import { useWeb3Provider } from './useContract'

export function useConnectionInfo() {
  const [connectionInfo, setConnectionInfo] = useState([])
  const [isInstanceRunning, setIsInstanceRunning] = useState(false)

  useEffect(() => {
    const fetchData = async () => {
      try {
        const TEAM_UUID = process.env.REACT_APP_TEAM_UUID
        const response = await fetch(`/connection-info/${TEAM_UUID}`)
        const data = await response.json()
        setConnectionInfo(data)
        if (!Array.isArray(data)) {
          setIsInstanceRunning(true)
        }
      } catch (error) {
        setIsInstanceRunning(false)
      }
    }

    fetchData()
  }, [])

  return [connectionInfo, isInstanceRunning]
}

export function useBalances() {
  const provider = useWeb3Provider()
  const [connectionInfo, isInstanceRunning] = useConnectionInfo()
  const tokens = useAllTokens()
  const [HtbTokenBalance, setHtbTokenBalance] = useState(0)
  const [WethTokenBalance, setWethTokenBalance] = useState(0)

  useEffect(() => {
    async function setBalances() {
      try {
        const player_addr = connectionInfo['Player Address' as keyof typeof connectionInfo]
        const signer = new Wallet(connectionInfo['Player Private Key' as keyof typeof connectionInfo], provider)
        const HtbContract = new Contract(Object.values(tokens)[0].address, ERC20_ABI, signer)
        const WethContract = new Contract(Object.values(tokens)[1].address, ERC20_ABI, signer)
        const HtbBalance = await HtbContract.balanceOf(player_addr)
        const WethBalance = await WethContract.balanceOf(player_addr)
        const HtbBalanceInFloat = parseFloat(parseFloat(formatUnits(HtbBalance, 18)).toFixed(6))
        const WethBalanceInFloat = parseFloat(parseFloat(formatUnits(WethBalance, 18)).toFixed(6))
        setHtbTokenBalance(HtbBalanceInFloat)
        setWethTokenBalance(WethBalanceInFloat)
      } catch (error) {
        setHtbTokenBalance(0)
        setWethTokenBalance(0)
      }
    }
    if (isInstanceRunning) {
      setBalances()
    } else {
      setHtbTokenBalance(0)
      setWethTokenBalance(0)
    }
  }, [connectionInfo, isInstanceRunning, provider, tokens])
  return [HtbTokenBalance, WethTokenBalance]
}
