/// <reference types="vite/client" />

import 'vue-router'

declare module 'vue-router' {
  interface RouteMeta {
    /** When true, the route renders without sidebar/header (full-screen). */
    hideLayout?: boolean
  }
}
