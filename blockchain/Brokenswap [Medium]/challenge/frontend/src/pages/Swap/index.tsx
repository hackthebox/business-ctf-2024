import { Contract } from '@ethersproject/contracts'
import { formatUnits } from '@ethersproject/units'
import { Token } from '@ubeswap/sdk'
import { ERC20_ABI } from 'constants/abis/erc20'
import { ethers } from 'ethers'
import React, { useCallback, useContext, useState } from 'react'
import { ArrowDown } from 'react-feather'
import { Text } from 'rebass'
import styled, { ThemeContext } from 'styled-components'

import AddressInputPanel from '../../components/AddressInputPanel'
import { ButtonPrimary } from '../../components/Button'
import { AutoColumn } from '../../components/Column'
import CurrencyInputPanel from '../../components/CurrencyInputPanel'
import Modal from '../../components/Modal'
import { SwapPoolTabs } from '../../components/NavigationTabs'
import { AutoRow, RowBetween } from '../../components/Row'
import { ArrowWrapper, Wrapper } from '../../components/swap/styleds'
import SwapHeader from '../../components/swap/SwapHeader'
import BROKENSWAP_ABI from '../../constants/abis/Brokenswap.json'
import { useConnectionInfo } from '../../hooks/useConnectionInfo'
import { useWeb3Provider } from '../../hooks/useContract'
import { Field } from '../../state/swap/actions'
import { useDerivedSwapInfo, useSwapActionHandlers, useSwapState } from '../../state/swap/hooks'
import { CloseIcon, LinkStyledButton } from '../../theme'
import AppBody from '../AppBody'

const ContentWrapper = styled(AutoColumn)`
  width: 100%;
  flex: 1 1;
  position: relative;
  padding: 1rem;
`
const Label = styled.span`
  font-weight: bold;
  margin-bottom: 0.5rem;
`
interface InfoLabelProps {
  label: string | undefined
  value: string | undefined
}

const InfoLabel = ({ label, value }: InfoLabelProps) => (
  <div>
    <Label>{label}: </Label>
    {value}
  </div>
)

export default function Swap() {
  const theme = useContext(ThemeContext)

  const { independentField, typedValue, recipient } = useSwapState()
  const { parsedAmount, currencies } = useDerivedSwapInfo()
  const parsedAmounts = {
    [Field.INPUT]: parsedAmount,
    [Field.OUTPUT]: parsedAmount,
  }
  const { onSwitchTokens, onCurrencySelection, onUserInput, onChangeRecipient } = useSwapActionHandlers()
  const dependentField: Field = independentField === Field.INPUT ? Field.OUTPUT : Field.INPUT

  const handleTypeInput = useCallback(
    (value: string) => {
      onUserInput(Field.INPUT, value)
    },
    [onUserInput]
  )
  const handleTypeOutput = useCallback(
    (value: string) => {
      onUserInput(Field.OUTPUT, value)
    },
    [onUserInput]
  )

  const formattedAmounts = {
    [independentField]: typedValue,
    [dependentField]: parsedAmounts[dependentField]?.toSignificant(6) ?? '',
  }

  const handleInputSelect = useCallback(
    (inputCurrency) => {
      onCurrencySelection(Field.INPUT, inputCurrency)
    },
    [onCurrencySelection]
  )

  const handleOutputSelect = useCallback(
    (outputCurrency) => onCurrencySelection(Field.OUTPUT, outputCurrency),
    [onCurrencySelection]
  )

  const [showPopup, setShowPopup] = useState(false)
  const [showTxPopup, setShowTxPopup] = useState(false)
  const [transactionInfo, setTransactionInfo] = useState({
    title: '',
    txHash: '',
    logs: [],
    errorCode: '',
    errorMessage: '',
    errorBody: '',
    revertReason: '',
  })
  const [connectionInfo, isInstanceRunning] = useConnectionInfo()
  const provider = useWeb3Provider()

  async function sendSwap(inputToken: Token | undefined, outputToken: Token | undefined, inputAmount: string) {
    if (inputToken === undefined || outputToken === undefined) {
      setTransactionInfo({
        title: 'SWAP FAILED',
        txHash: '',
        logs: [],
        errorCode: '',
        errorMessage: 'Select input and output tokens first',
        errorBody: '',
        revertReason: '',
      })
    } else {
      if (isInstanceRunning && provider) {
        try {
          console.log(
            '===========INITIALIZING SWAP===========',
            'inputToken',
            inputToken,
            'outputToken',
            outputToken,
            'inputAmount',
            inputAmount
          )
          const BROKENSWAP_ADDRESS = connectionInfo['Target Contract' as keyof typeof connectionInfo]
          const signer = new ethers.Wallet(
            connectionInfo['Player Private Key' as keyof typeof connectionInfo],
            provider
          )
          // approve transfer first
          const inputTokenContract = new Contract(inputToken.address, ERC20_ABI, signer)
          const approval = await inputTokenContract.approve(
            BROKENSWAP_ADDRESS,
            ethers.utils.parseUnits(inputAmount, 18)
          )
          const approvalRcpt = await approval.wait()
          const Brokenswap = new Contract(BROKENSWAP_ADDRESS, BROKENSWAP_ABI.abi, signer)
          const transaction = await Brokenswap.swap(
            inputToken.address,
            outputToken.address,
            ethers.utils.parseUnits(inputAmount, 18)
          )
          const TxRcpt = await transaction.wait()
          const currentBlock = await provider.getBlockNumber()
          const events: any[] = await Brokenswap.queryFilter('Swap', currentBlock, currentBlock)
          console.log('===========SWAP SUCCESSFUL===========', 'Transaction Receipt', TxRcpt)
          setTransactionInfo({
            title: 'SWAP SUCCESSFUL',
            txHash: TxRcpt.transactionHash,
            logs: events[0].topics,
            errorCode: '',
            errorMessage: '',
            errorBody: '',
            revertReason: '',
          })
          setShowTxPopup(true)
        } catch (error: any) {
          console.log('===========SWAP FAILED===========', 'ERROR', error)
          setTransactionInfo((prevState) => ({
            ...prevState,
            title: 'SWAP FAILED',
            txHash: '',
            logs: [],
            revertReason: error.reason || undefined,
            errorCode: error.code || undefined,
            errorMessage:
              error.code !== 'UNPREDICTABLE_GAS_LIMIT' && error.code !== 'SERVER_ERROR' ? error.message : undefined,
            errorBody: error.error?.error?.body ?? error.error?.body ?? error.body ?? undefined,
          }))
          setShowTxPopup(true)
        }
      } else {
        setShowPopup(true)
      }
    }
  }

  return (
    <>
      <SwapPoolTabs active={'swap'} />
      <AppBody>
        <SwapHeader title={'Swap'} />
        <Wrapper id="swap-page">
          <AutoColumn gap={'md'}>
            <CurrencyInputPanel
              label={'From'}
              value={formattedAmounts[Field.INPUT]}
              showMaxButton={false}
              showHalfButton={false}
              currency={currencies[Field.INPUT]}
              onUserInput={handleTypeInput}
              onCurrencySelect={handleInputSelect}
              otherCurrency={currencies[Field.OUTPUT]}
              id="swap-currency-input"
            />
            <AutoColumn justify="space-between">
              <AutoRow justify={'center'} style={{ padding: '0 1rem' }}>
                <ArrowWrapper clickable>
                  <ArrowDown
                    size="16"
                    onClick={() => {
                      handleTypeInput(formattedAmounts[Field.OUTPUT])
                      onSwitchTokens()
                    }}
                    color={currencies[Field.INPUT] && currencies[Field.OUTPUT] ? theme.primary1 : theme.text2}
                  />
                </ArrowWrapper>
              </AutoRow>
            </AutoColumn>
            <CurrencyInputPanel
              value={formattedAmounts[Field.OUTPUT]}
              onUserInput={handleTypeOutput}
              label={independentField === Field.INPUT ? 'To' : undefined}
              showMaxButton={false}
              currency={currencies[Field.OUTPUT]}
              hideNumericalInput={true}
              onCurrencySelect={handleOutputSelect}
              otherCurrency={currencies[Field.INPUT]}
              id="swap-currency-output"
              disabled
            />

            {recipient !== null ? (
              <>
                <AutoRow justify="space-between" style={{ padding: '0 1rem' }}>
                  <ArrowWrapper clickable={false}>
                    <ArrowDown size="16" color={theme.text2} />
                  </ArrowWrapper>
                  <LinkStyledButton id="remove-recipient-button" onClick={() => onChangeRecipient(null)}>
                    - Remove send
                  </LinkStyledButton>
                </AutoRow>
                <AddressInputPanel id="recipient" value={recipient} onChange={onChangeRecipient} />
              </>
            ) : null}
            <ButtonPrimary
              borderRadius="12px"
              onClick={() => sendSwap(currencies[Field.INPUT], currencies[Field.OUTPUT], formattedAmounts[Field.INPUT])}
            >{`${'Swap'}`}</ButtonPrimary>
            <Modal isOpen={showPopup} onDismiss={() => setShowPopup(false)}>
              <ContentWrapper>
                <AutoColumn gap="12px">
                  <RowBetween>
                    <Text fontWeight={500} fontSize={18}>
                      {'No instance found!\nStart a new instance in the Challenge Handler and then Reload the page.'}
                    </Text>
                    <CloseIcon onClick={() => setShowPopup(false)} />
                  </RowBetween>
                </AutoColumn>
              </ContentWrapper>
            </Modal>

            <Modal isOpen={showTxPopup} onDismiss={() => setShowTxPopup(false)}>
              <ContentWrapper gap={'12x'}>
                <AutoColumn gap="12px">
                  <RowBetween>
                    <Text
                      fontWeight={800}
                      fontSize={18}
                      style={transactionInfo.errorMessage === '' ? { color: '#8878C3' } : { color: '#E83B46' }}
                    >
                      {transactionInfo.title}
                    </Text>
                    <CloseIcon onClick={() => setShowTxPopup(false)} />
                  </RowBetween>
                  <RowBetween>
                    <Text fontWeight={400} fontSize={18}>
                      {transactionInfo.txHash && <InfoLabel label="Transaction Hash" value={transactionInfo.txHash} />}
                      {transactionInfo.logs && transactionInfo.logs.length == 4 && (
                        <>
                          <br />
                          <InfoLabel label="Swap Details" value={''} />
                          <InfoLabel
                            label="Input"
                            value={
                              parseFloat(formatUnits(transactionInfo.logs[1], 18)) +
                              '   ' +
                              (currencies[Field.INPUT]?.symbol ?? '')
                            }
                          />
                          <InfoLabel
                            label="Output"
                            value={
                              parseFloat(formatUnits(transactionInfo.logs[2], 18)) +
                              '   ' +
                              (currencies[Field.OUTPUT]?.symbol ?? '')
                            }
                          />
                          <InfoLabel
                            label="With Amount of Fees moved to Fees Pool"
                            value={
                              currencies[Field.INPUT]?.symbol &&
                              parseFloat(formatUnits(transactionInfo.logs[3], 18)) +
                                ' ' +
                                (currencies[Field.INPUT]?.symbol ?? '')
                            }
                          />
                          <br />
                          <InfoLabel label="NOTE" value={'\n Reload page to view updated balances'} />
                        </>
                      )}
                      {transactionInfo.errorCode && <InfoLabel label="Error code" value={transactionInfo.errorCode} />}
                      {transactionInfo.errorMessage && (
                        <InfoLabel label="Error message" value={transactionInfo.errorMessage} />
                      )}
                      {transactionInfo.errorBody && (
                        <InfoLabel label="Error body" value={JSON.parse(transactionInfo.errorBody).error.message} />
                      )}
                      {transactionInfo.revertReason && (
                        <InfoLabel label="Revert reason" value={transactionInfo.revertReason} />
                      )}
                    </Text>
                  </RowBetween>
                </AutoColumn>
              </ContentWrapper>
            </Modal>
          </AutoColumn>
        </Wrapper>
      </AppBody>
    </>
  )
}
