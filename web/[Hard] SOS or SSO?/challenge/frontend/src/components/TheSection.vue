<script setup>
import { RouterLink } from 'vue-router'
</script>

<template>
  <div class="section">
    <div class="image-container">
      <img :src="image" alt="Image" />
    </div>
    <div class="text-container">
      <h1>{{ title }}</h1>
      <p>{{ description }}</p>
      <RouterLink :to="link" class="link"> {{ linkText }}</RouterLink>
    </div>
  </div>
</template>

<script>
export default {
  name: 'TheSection',
  props: {
    image: String,
    title: String,
    description: String,
    link: String,
    linkText: String
  }
}
</script>

<style scoped>
.section {
  display: flex;
  flex-direction: row;
  gap: 10%;
}

.image-container {
  flex: 1;
}

.text-container {
  flex: 2;
}

img {
  max-width: 100%;
  height: auto;
}

p {
  font-size: 1.2em;
}

.link {
  font-size: 1.1em;
}
</style>
