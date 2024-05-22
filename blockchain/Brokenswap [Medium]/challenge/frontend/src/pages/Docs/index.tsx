import React, { useEffect, useState } from 'react'
import Markdown from 'react-markdown'
import rehypeRaw from 'rehype-raw'
import styled from 'styled-components'

export default function Docs() {
  const BodyWrapper = styled.div`
    position: relative;
    max-width: '420px';
    width: 60%;
    background: ${({ theme }) => theme.bg1};
    box-shadow: 0px 0px 1px rgba(0, 0, 0, 0.01), 0px 4px 8px rgba(0, 0, 0, 0.04), 0px 16px 24px rgba(0, 0, 0, 0.04),
      0px 24px 32px rgba(0, 0, 0, 0.01);
    border-radius: 15px;
    padding: 2rem;
  `
  const [markdown, setMarkdown] = useState('')

  useEffect(() => {
    fetch('Docs.md')
      .then((response) => response.text())
      .then((text) => setMarkdown(text))
  }, [])

  return (
    <>
      <BodyWrapper>
        <Markdown rehypePlugins={[rehypeRaw]}>{markdown}</Markdown>
      </BodyWrapper>
    </>
  )
}
