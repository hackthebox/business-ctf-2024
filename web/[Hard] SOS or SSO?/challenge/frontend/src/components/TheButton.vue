<template>
  <div class="button-container" :style="{ 'background-color': color ?? 'brown' }">
    <h2>{{ title }}</h2>
  </div>
</template>

<script>
export default {
  name: 'TheButton',
  props: {
    title: String,
    color: String
  }
}
</script>

<style scoped>
.button-container {
  border-radius: 5px;
  height: fit-content;
  width: fit-content;
  align-content: center;
  justify-content: center;
  align-items: center;
}

h2 {
  color: white;
  padding: 5px;
}

.button-container:hover {
  cursor: pointer;
  box-shadow: 5px 3px 1px rgba(0, 0, 0, 0.301);
}
</style>
