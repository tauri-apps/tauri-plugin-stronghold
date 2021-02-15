import resolve from '@rollup/plugin-node-resolve'
import { terser } from 'rollup-plugin-terser'
import typescript from '@rollup/plugin-typescript'

export default {
	input: './api-src/index.ts',
	output: {
		dir: './dist',
		entryFileNames: '[name].js',
		format: 'es',
		exports: 'auto'
	},
	plugins: [
    resolve(),
	terser(),
	typescript({
      tsconfig: './api-src/tsconfig.json'
    })
	]
}
