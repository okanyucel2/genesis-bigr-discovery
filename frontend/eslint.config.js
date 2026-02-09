import vueConfig from '@genesis/eslint-config/vue'

export default [
  ...vueConfig,
  {
    rules: {
      'vue/multi-word-component-names': 'off',
    },
  },
]
