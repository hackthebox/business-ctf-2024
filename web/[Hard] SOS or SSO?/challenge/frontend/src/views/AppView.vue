<script setup>
import NotePreview from '@/components/NotePreview.vue'
import TheButton from '@/components/TheButton.vue'
import { RouterLink } from 'vue-router'
</script>

<template>
  <div class="app">
    <div v-if="notes" class="notes">
      <div v-for="(items, category) in notes" class="notes-section">
        <div v-if="items.length > 0">
          <h1>{{ category.charAt(0).toUpperCase() + category.slice(1) }} notes</h1>
          <div class="notes-collection">
            <NotePreview v-for="note in items" :note="note"></NotePreview>
          </div>
        </div>
      </div>
    </div>
    <div class="new-note">
      <h2>New Note</h2>
      <span>Title: </span><input type="text" v-model="newNoteTitle" /> <br /><br />
      <span :style="{ color: user == null ? 'gray' : 'black' }" :disabled="user == null"
        >Private: </span
      ><input type="checkbox" v-model="privateNote" :disabled="user == null" />
      <TheButton @click="createNote()" title="Create"></TheButton>
    </div>
    <div class="user-actions">
      <RouterLink to="/app/support" v-if="isAdmin || isSupport">Support portal</RouterLink>
      <RouterLink to="/app/admin" v-if="isAdmin">Admin portal</RouterLink>
    </div>
  </div>
</template>

<script>
import router from '@/router'

export default {
  name: 'AppView',
  props: {
    user: null
  },
  data() {
    return {
      newNoteTitle: '',
      privateNote: false,
      notes: null
    }
  },
  created() {
    this.$watch(
      () => this.$route.params,
      () => {
        this.fetchNotes()
      },
      { immediate: true }
    )
  },
  methods: {
    createNote() {
      fetch('/api/note', {
        method: 'POST',
        body: JSON.stringify({
          title: this.newNoteTitle,
          content:
            'W3sidHlwZSI6InAiLCJhdHRyIjp7fSwiY29udGVudCI6IldyaXRlIHlvdXIgbW9zdCBldmlsIHRob3VnaHRzISJ9XQ==',
          private: this.privateNote
        }),
        headers: {
          'X-NOTES-CSRF-PROTECTION': '1'
        }
      })
        .then((r) => r.json())
        .then((j) => router.push(`/app/note/${j.id}`))
    },
    fetchNotes() {
      fetch('/api/notes')
        .then((r) => r.json())
        .then((j) => (this.notes = j.notes))
    }
  },
  computed: {
    isAdmin() {
      return this.user !== null && this.user.role === "admin"
    },
    isSupport() {
      return this.user !== null && this.user.role === "support"
    }
  }
}
</script>

<style scoped>
.notes-collection {
  width: 100%;
  overflow-x: auto;
  white-space: nowrap;
}

.notes-collection .note-preview {
  display: inline-block;
  margin: 0 10px;
}

.new-note h2 {
  text-shadow: #fc0 1px 0 10px;
  font-size: 2em;
}

.new-note span {
  font-size: 1.5em;
}

input[disabled='']:hover,
span[disabled='true']:hover {
  cursor: not-allowed;
}

.user-actions {
  display: flex;
  font-size: 1.2em;
  gap: 10px;
}
</style>
