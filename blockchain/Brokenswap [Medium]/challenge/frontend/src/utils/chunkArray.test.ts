import chunkArray from './chunkArray'

describe('#chunkArray', () => {
  it('size 1', () => {
    expect(chunkArray([1, 2, 3], 1)).toEqual([[1], [2], [3]])
  })
  it('size 0 throws', () => {
    expect(() => chunkArray([1, 2, 3], 0)).toThrow('maxChunkSize must be gte 1')
  })
  it('size gte items', () => {
    expect(chunkArray([1, 2, 3], 3)).toEqual([[1, 2, 3]])
    expect(chunkArray([1, 2, 3], 4)).toEqual([[1, 2, 3]])
  })
  it('size exact half', () => {
    expect(chunkArray([1, 2, 3, 4], 2)).toEqual([
      [1, 2],
      [3, 4],
    ])
  })
})
