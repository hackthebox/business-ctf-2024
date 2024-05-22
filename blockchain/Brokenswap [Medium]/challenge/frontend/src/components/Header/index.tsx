import 'rc-drawer/assets/index.css'

import { CardNoise } from 'components/earn/styled'
import Modal from 'components/Modal'
import { useBalances } from 'hooks/useConnectionInfo'
import { darken } from 'polished'
import Drawer from 'rc-drawer'
import React, { useState } from 'react'
import { Moon } from 'react-feather'
import { NavLink } from 'react-router-dom'
import { Text } from 'rebass'
import styled from 'styled-components'
import { TYPE } from 'theme'
import { CountUp } from 'use-count-up'

import brokenswapIcon from '../../assets/images/brokenswap-icon.png'
import brokenswapLogo from '../../assets/images/brokenswap-logo.png'
import { useDarkModeManager } from '../../state/user/hooks'
import { CloseIcon } from '../../theme'
import { YellowCard } from '../Card'
import { AutoColumn } from '../Column'
import Row, { RowBetween, RowFixed } from '../Row'

const ContentWrapper = styled(AutoColumn)`
  width: 100%;
  flex: 1 1;
  position: relative;
  padding: 1rem;
`

const HeaderFrame = styled.div`
  display: grid;
  grid-template-columns: 1fr 120px;
  align-items: center;
  justify-content: space-between;
  align-items: center;
  flex-direction: row;
  width: 100%;
  top: 0;
  position: relative;
  border-bottom: 1px solid rgba(0, 0, 0, 0.1);
  padding: 0;
  z-index: 2;

  @media (max-width: 1115px) {
    grid-template-columns: 1fr;
    padding: 0 1rem;
    width: calc(100%);
    position: relative;
  }

  ${({ theme }) => theme.mediaWidth.upToExtraSmall`
        padding: 0.5rem 1rem;
  `}
`

const HeaderControls = styled.div`
  display: flex;
  flex-direction: row;
  align-items: center;
  justify-self: flex-end;
  padding-right: 2rem;
  justify-content: space-between;
  max-width: 40vw;
  width: 30vw;

  @media (max-width: 1115px) {
    flex-direction: row;
    justify-content: space-between;
    justify-self: center;
    width: 100%;
    max-width: 1115px;
    padding: 1rem;
    position: fixed;
    bottom: 0px;
    left: 0px;
    width: 100%;
    z-index: 99;
    height: 72px;
    border-radius: 12px 12px 0 0;
    background-color: ${({ theme }) => theme.bg1};
  }
`

const HeaderElement = styled.div`
  display: flex;
  align-items: center;

  /* addresses safari's lack of support for "gap" */
  & > *:not(:first-child) {
    margin-left: 8px;
  }

  ${({ theme }) => theme.mediaWidth.upToMedium`
   flex-direction: row-reverse;
    align-items: center;
  `};
`

const HeaderElementWrap = styled.div`
  display: flex;
  align-items: center;
  width: 100px;
`

const HeaderRow = styled(RowFixed)`
  @media (max-width: 1115px) {
    width: 100%;
  }
`

const HeaderLinks = styled(Row)`
  justify-content: center;
  @media (max-width: 1115px) {
    padding: 1rem 0 1rem 1rem;
    justify-content: flex-end;
  }
`

const AccountElement = styled.div<{ active: boolean }>`
  display: flex;
  flex-direction: row;
  align-items: center;
  background-color: ${({ theme, active }) => (!active ? theme.bg1 : theme.bg3)};
  border-radius: 12px;
  white-space: nowrap;
  width: 100%;
  cursor: pointer;

  :focus {
    border: 1px solid blue;
  }
`

const HideSmall = styled.span`
  ${({ theme }) => theme.mediaWidth.upToSmall`
    display: none;
  `};
`

const NetworkCard = styled(YellowCard)`
  border-radius: 12px;
  padding: 8px 12px;
  ${({ theme }) => theme.mediaWidth.upToSmall`
    margin: 0;
    margin-right: 0.5rem;
    width: initial;
    overflow: hidden;
    text-overflow: ellipsis;
    flex-shrink: 1;
  `};
`

const BalanceText = styled(Text)`
  ${({ theme }) => theme.mediaWidth.upToExtraSmall`
    display: none;
  `};
`

const Title = styled(NavLink)`
  display: flex;
  align-items: center;
  pointer-events: auto;
  justify-self: flex-start;
  margin-right: 12px;
  ${({ theme }) => theme.mediaWidth.upToSmall`
    justify-self: center;
  `};
  :hover {
    cursor: pointer;
  }
`

const BrokenswapIcon = styled.div`
  transition: transform 0.3s ease;
  :hover {
    transform: rotate(-5deg);
  }
`

const activeClassName = 'ACTIVE'

export const StyledNavLink = styled(NavLink).attrs({
  activeClassName,
})`
  ${({ theme }) => theme.flexRowNoWrap}
  align-items: left;
  border-radius: 3rem;
  outline: none;
  cursor: pointer;
  text-decoration: none;
  color: ${({ theme }) => theme.text2};
  font-size: 1.1rem;
  width: fit-content;
  margin: 0 11px;
  font-weight: 500;

  &.${activeClassName} {
    border-radius: 12px;
    font-weight: 600;
    color: ${({ theme }) => theme.text1};
  }

  :hover,
  :focus {
    color: ${({ theme }) => darken(0.1, theme.text1)};
  }

  @media (max-width: 320px) {
    margin: 0 8px;
  }
`

export const StyledNavLinkExtraSmall = styled(StyledNavLink).attrs({
  activeClassName,
})`
  @media (max-width: 550px) {
    display: none;
  }
`

export const StyledMenuButton = styled.button`
  position: relative;
  width: 100%;
  max-width: 40px;
  height: 100%;
  border: none;
  background-color: transparent;
  margin: 0;
  padding: 0;
  height: 35px;
  background-color: ${({ theme }) => theme.bg3};
  margin-left: 8px;
  padding: 0.15rem 0.5rem;
  border-radius: 0.5rem;

  :hover,
  :focus {
    cursor: pointer;
    outline: none;
    background-color: ${({ theme }) => theme.bg4};
  }

  svg {
    margin-top: 2px;
  }
  > * {
    stroke: ${({ theme }) => theme.text1};
  }
`

export const StyledDesktopLogo = styled.img`
  display: inline;
  @media (max-width: 1225px) {
    display: none;
  }
  @media (max-width: 1115px) {
    display: inline;
  }
  @media (max-width: 655px) {
    display: none;
  }
  @media (max-width: 550px) {
    display: inline;
  }
  @media (max-width: 415px) {
    display: none;
  }
`

export const StyledMobileLogo = styled.img`
  display: none;
  @media (max-width: 1225px) {
    display: inline;
  }
  @media (max-width: 1115px) {
    display: none;
  }
  @media (max-width: 655px) {
    display: inline;
  }
  @media (max-width: 550px) {
    display: none;
  }
  @media (max-width: 415px) {
    display: inline;
  }
`

export const BurgerElement = styled(HeaderElement)`
  display: none;
  @media (max-width: 550px) {
    display: flex;
  }
`

export const StyledDrawer = styled(Drawer)`
  & .drawer-content-wrapper {
    background: ${({ theme }) => theme.bg3};
    color: ${({ theme }) => theme.text1};
  }
`

export const StyledMenu = styled.ul`
  padding-left: 0px;
  list-style: none;
`
export const StyledMenuItem = styled.li`
  padding: 10px 0px 10px 20px;
`
export const StyledSubMenuItem = styled(StyledMenuItem)`
  padding-left: 30px;
`

export default function Header() {
  const [darkMode, toggleDarkMode] = useDarkModeManager()
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const [showTokenBalanceModal, setShowTokenBalanceModal] = useState<boolean>(true)

  const [showMessageModal, setShowMessageModal] = useState(false)
  const openMessageModal = () => {
    setShowMessageModal(true)
  }
  const [HtbTokenBalance, WethTokenBalance] = useBalances()

  return (
    <HeaderFrame>
      {/*<Modal isOpen={showTokenBalanceModal} onDismiss={() => setShowTokenBalanceModal(false)}>
        <TokenBalanceContent setShowTokenBalanceModal={setShowTokenBalanceModal} tokens={tokens} />
      </Modal>*/}
      <HeaderRow>
        <Title to="/">
          <BrokenswapIcon>
            <StyledMobileLogo width={'32px'} height={'36px'} src={brokenswapIcon} alt="Brokenswap" />
            <StyledDesktopLogo width={'400px'} height={'75px'} src={brokenswapLogo} alt="Brokenswap" />
          </BrokenswapIcon>
        </Title>
        <HeaderLinks>
          <StyledNavLink id={`swap-nav-link`} to={'/swap'}>
            {'Swap'}
          </StyledNavLink>
          <StyledNavLink id={`docs-nav-link`} to={'/docs'}>
            {'Docs'}
          </StyledNavLink>
          <StyledNavLink id={`swap-nav-link`} to={'/connection'}>
            {'Connection Info'}
          </StyledNavLink>
        </HeaderLinks>
      </HeaderRow>
      <HeaderControls>
        <HeaderElement>TOKEN BALANCES:</HeaderElement>
        <HeaderElementWrap>
          <TokenWrapper onClick={() => setShowTokenBalanceModal(true)}>
            <TokenAmount active={true} style={{ pointerEvents: 'auto' }}>
              {true && (
                <HideSmall>
                  <TYPE.white
                    style={{
                      paddingRight: '.4rem',
                    }}
                  >
                    <CountUp
                      isCounting
                      start={parseFloat('0')}
                      end={HtbTokenBalance}
                      thousandsSeparator={','}
                      duration={1}
                    />
                  </TYPE.white>
                </HideSmall>
              )}
              HTB
            </TokenAmount>
            <CardNoise />
          </TokenWrapper>
        </HeaderElementWrap>
        <HeaderElementWrap>
          <TokenWrapper onClick={() => setShowTokenBalanceModal(true)}>
            <TokenAmount active={true} style={{ pointerEvents: 'auto' }}>
              {true && (
                <HideSmall>
                  <TYPE.white
                    style={{
                      paddingRight: '.4rem',
                    }}
                  >
                    <CountUp
                      isCounting
                      start={parseFloat('0')}
                      end={WethTokenBalance}
                      thousandsSeparator={','}
                      duration={1}
                    />
                  </TYPE.white>
                </HideSmall>
              )}
              WETH
            </TokenAmount>
            <CardNoise />
          </TokenWrapper>
        </HeaderElementWrap>
        <HeaderElementWrap>
          <Modal isOpen={showMessageModal} onDismiss={() => setShowMessageModal(false)}>
            <ContentWrapper gap={'12px'}>
              <AutoColumn gap="12px">
                <RowBetween>
                  <Text fontWeight={500} fontSize={18}>
                    {'lol nice try, only dark mode allowed in this CTF sry.'}
                  </Text>
                  <CloseIcon onClick={() => setShowMessageModal(false)} />
                </RowBetween>
              </AutoColumn>
            </ContentWrapper>
          </Modal>
          <StyledMenuButton aria-label={'Toggle Dark Mode'} onClick={openMessageModal}>
            {darkMode ? <Moon size={20} /> : <Moon size={20} />}
          </StyledMenuButton>
        </HeaderElementWrap>
      </HeaderControls>
    </HeaderFrame>
  )
}

const TokenAmount = styled(AccountElement)`
  color: white;
  padding: 4px 8px;
  height: 36px;
  font-weight: 500;
  background-color: ${({ theme }) => theme.bg3};
  background: radial-gradient(174.47% 188.91% at 1.84% 0%, ${({ theme }) => theme.primary1} 0%, #2172e5 100%), #edeef2;
`

const TokenWrapper = styled.span`
  width: fit-content;
  position: relative;
  cursor: pointer;
  Connection :hover {
    opacity: 0.8;
  }
  :active {
    opacity: 0.9;
  }
`
