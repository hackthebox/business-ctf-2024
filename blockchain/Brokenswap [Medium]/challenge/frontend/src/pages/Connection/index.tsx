// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import { useConnectionInfo } from 'hooks/useConnectionInfo'
import React from 'react'
import styled from 'styled-components'

const BodyWrapper = styled.div`
  position: relative;
  width: auto;
  background: ${({ theme }) => theme.bg1};
  box-shadow: 0px 0px 1px rgba(0, 0, 0, 0.01), 0px 4px 8px rgba(0, 0, 0, 0.04), 0px 16px 24px rgba(0, 0, 0, 0.04),
    0px 24px 32px rgba(0, 0, 0, 0.01);
  border-radius: 15px;
  padding: 2rem;
  font-size: 110%;
`

const Label = styled.span`
  font-weight: bold;
  color: #8979c5;
  margin-bottom: 0.5rem;
`

// eslint-disable-next-line react/prop-types
const InfoLabel = ({ label, value }) => (
  <div>
    <Label>{label}: </Label>
    {value}
  </div>
)

export default function Connection() {
  const [connectionInfo, setConnectionInfo] = useConnectionInfo()
  return (
    <BodyWrapper>
      <InfoLabel label="Team UUID" value={connectionInfo['Team UUID']} />
      <InfoLabel label="Player UUID" value={connectionInfo['Player UUID']} />
      <InfoLabel label="RPC URL" value={connectionInfo['RPC URL']} />
      <InfoLabel label="Player Private Key" value={connectionInfo['Player Private Key']} />
      <InfoLabel label="Player Address" value={connectionInfo['Player Address']} />
      <InfoLabel label="Setup Contract" value={connectionInfo['Setup Contract']} />
      <InfoLabel label="Target Contract" value={connectionInfo['Target Contract']} />
      <InfoLabel label="Fees Pool Contract" value={connectionInfo['Fees Pool Contract']} />
      <InfoLabel label="WETH Token Contract" value={connectionInfo['WETH Token Contract']} />
      <InfoLabel label="HTB Token Contract" value={connectionInfo['HTB Token Contract']} />
    </BodyWrapper>
  )
}
