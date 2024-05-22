import React from 'react'
import { X } from 'react-feather'
import styled from 'styled-components'

import tokenLogo from '../../assets/images/token-logo.png'
import { BrokenswapTokenAnimated, TYPE } from '../../theme'
import { AutoColumn } from '../Column'
import { Break, CardNoise, CardSection, DataCard } from '../earn/styled'
import { RowBetween } from '../Row'

const ContentWrapper = styled(AutoColumn)`
  width: 100%;
`

const ModalUpper = styled(DataCard)`
  box-shadow: 0px 4px 10px rgba(0, 0, 0, 0.1);
  background: radial-gradient(76.02% 75.41% at 1.84% 0%, ${({ theme }) => theme.primary1} 0%, #021d43 100%), #edeef2;
  padding: 0.5rem;
`

const StyledClose = styled(X)`
  position: absolute;
  right: 16px;
  top: 16px;

  :hover {
    cursor: pointer;
  }
`

/**
 * Content for balance stats modal
 */
export default function TokenBalanceContent({
  setShowTokenBalanceModal,
  tokens,
}: {
  setShowTokenBalanceModal: any
  tokens: any
}) {
  //  const [connectionInfo, isInstanceRunning] = useConnectionInfo()
  //  const provider = useWeb3Provider()

  //  function TokenAmount(token: Token) {
  //    // @todo: fix this
  //    console.log('TokenAmount', token)
  //    console.log('PV key', connectionInfo['Player Private Key'])
  //    const wallet = new ethers.Wallet(connectionInfo['Player Private Key'], provider)
  //    const TokenBalance = useTokenBalance(undefined, token)
  //    return TokenBalance
  //  }

  return (
    <ContentWrapper gap="lg">
      <ModalUpper>
        <CardNoise />
        <CardSection gap="md">
          <RowBetween>
            <TYPE.white color="white">Your Tokens Balance</TYPE.white>
            <StyledClose stroke="white" onClick={() => setShowTokenBalanceModal(false)} />
          </RowBetween>
        </CardSection>
        <Break />
        {
          <>
            <CardSection gap="sm">
              <AutoColumn gap="md" justify="center">
                <BrokenswapTokenAnimated width="48px" src={tokenLogo} />{' '}
                <TYPE.white fontSize={48} fontWeight={600} color="white">
                  {'8'}
                </TYPE.white>
              </AutoColumn>
              <AutoColumn gap="md">
                <RowBetween>
                  <TYPE.white color="white">{'Balance'}:</TYPE.white>
                  {<TYPE.white color="white">{0}</TYPE.white>}
                </RowBetween>
              </AutoColumn>
            </CardSection>
            <Break />
          </>
        }
        <CardNoise />
      </ModalUpper>
    </ContentWrapper>
  )
}
