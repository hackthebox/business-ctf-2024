<template>
  <div class="card">
    <h3>{{ title }}</h3>
    <p>{{ content }}</p>
  </div>
</template>

<script>
export default {
  name: 'Card',
  props: {
    title: String,
    content: String
  }
}
</script>

<style scoped>
.card {
  width: 150px;
  background-color: white;
  text-align: center;
  border-radius: 5px;
}
.card:hover {
  cursor: pointer;
}
</style>
