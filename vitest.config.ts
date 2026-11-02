import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['src/**/*.test.mts', 'web/**/*.test.mts', 'worker/**/*.test.mts'],
  },
})
