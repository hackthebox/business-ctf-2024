<script setup>
import { RouterLink } from 'vue-router'
</script>

<template>
  <div class="container">
    <h1>PermNotes</h1>
    <h3>The perfect place for timeless thoughts...</h3>
    <template v-if="username">
      <h2>
        Logged in as: <u>{{ username }}</u> - <a href="/auth/logout">Logout</a>
      </h2>
    </template>
    <template v-else>
      <h2>Not logged in: <RouterLink to="/login">Login</RouterLink></h2>
    </template>
  </div>
</template>

<script>
export default {
  name: 'TheTitle',
  props: {
    username: String
  }
}
</script>

<style scoped>
.container {
  border-radius: 20px;
  height: fit-content;
  width: 800px;
  align-content: center;
  justify-content: center;
  align-items: center;
  background-image: url('/src/assets/img/wood-pixel.png');
}

h1 {
  font-size: 12em;
  color: #ffdba8;
  text-shadow: rgb(153, 122, 0) 1px 0 10px;
  margin-bottom: 0px;
  margin-top: 0px;
  line-height: 120px;
}

h2 {
  margin-bottom: 0px;
  margin-top: 0px;
}

h3 {
  text-align: right;
  margin-right: 30px;
  margin-top: 0px;
  color: #ffdba8;
  text-shadow: rgb(44, 35, 0) 10px 0 10px;
}
</style>
