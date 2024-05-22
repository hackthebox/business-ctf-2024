<script setup>
import { RouterLink, RouterView } from 'vue-router'
import TheTitle from './components/TheTitle.vue'
</script>

<template>
  <div class="big-title">
    <TheTitle :username="user ? user.email : null"></TheTitle>
  </div>
  <div class="frame">
    <RouterView :user="user" />
  </div>
</template>

<script>
export default {
  name: 'App',
  data() {
    return {
      user: null
    }
  },
  created() {
    this.$watch(
      () => this.$route.params,
      () => {
        this.fetchUser()
      },
      { immediate: true }
    )
  },
  methods: {
    fetchUser() {
      fetch('/api/user')
        .then((r) => r.json())
        .then((j) => {
          if (j.email) {
            this.user = j
          }
        })
    }
  }
}
</script>

<style scoped>
.big-title {
  display: flex;
  justify-content: center;
  text-align: center;
  margin-top: 30px;
}
.frame {
  background-color: #f6eee3;
  min-height: 800px;
  height: 100%;
  width: 60%;
  margin-left: 20%;
  margin-top: 20px;
  border-radius: 10px;
  box-sizing: border-box;
  padding-left: 40px;
  padding-right: 40px;
  padding-top: 20px;
}
</style>
