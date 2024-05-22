import { createRouter, createWebHistory } from 'vue-router'
import HomeView from '../views/HomeView.vue'
import NotFound from '../views/NotFound.vue'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/',
      name: 'home',
      component: HomeView
    },
    {
      path: '/app',
      name: 'app',
      component: () => import('../views/AppView.vue')
    },
    {
      path: '/login',
      name: 'login',
      component: () => import('../views/LoginView.vue')
    },
    {
      path: '/app/note/:id',
      name: 'note',
      component: () => import('../views/EditorView.vue')
    },
    {
      path: '/app/support',
      name: 'support',
      component: () => import('../views/SupportView.vue')
    },
    {
      path: '/app/admin',
      name: 'admin',
      component: () => import('../views/AdminView.vue')
    },
    {
      path: '/:catchAll(.*)',
      name: 'NotFound',
      component: NotFound
    }
  ]
})

export default router
