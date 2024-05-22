<template>
  <div class="note-preview" @click="navigateToNote()">
    <h3>{{ note.title }}</h3>
    <p>Author: {{ note.author ?? 'anonymous' }}</p>
    <p>Updated: {{ new Date(note.updatedAt).toLocaleString('en-GB', { timeZone: 'UTC' }) }}</p>
  </div>
</template>

<script>
import router from '@/router'

export default {
  name: 'Card',
  props: {
    note: Object
  },
  methods: {
    navigateToNote() {
      router.push(`/app/note/${this.note.id}`)
    }
  }
}
</script>

<style scoped>
.note-preview {
  width: 200px;
  background-color: white;
  text-align: center;
  border-radius: 5px;
  border-color: black;
}
.note-preview:hover {
  cursor: pointer;
}
.note-preview h3 {
  text-overflow: ellipsis;
}
.note-preview p {
  font-size: 0.8em;
}
</style>
