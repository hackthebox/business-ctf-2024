<script setup>
import TheButton from '@/components/TheButton.vue'
</script>
<template>
  <RouterLink to="/app" class="back">Back</RouterLink>
  <div class="editor" v-if="note">
    <h1>{{ note.title }}</h1>
    <div class="editor-text">
      <div>
        <component
          :is="item.type"
          v-bind="item.attr"
          v-for="(item, i) in noteContent"
          contenteditable="true"
          :ref="`item-${i}`"
          @focus="focused = i"
          @input="handleInput($event, i)"
          class="editor-element"
          >{{ noteContent[i].content }}</component
        >
      </div>
    </div>
    <div class="editor-actions">
      <img @click="addText()" src="/src/assets/img/text.png" />
      <img @click="addBold()" src="/src/assets/img/bold.png" />
      <img @click="addImg()" src="/src/assets/img/insert-picture-icon.png" />
      <img @click="addLink()" src="/src/assets/img/link.png" />
    </div>
    <div v-if="displayUrl" class="editor-url">
      <b>Insert a url: </b> <input type="text" v-model="url" ref="urlInput" />
      <TheButton @click="confirmUrl()" title="Confirm"></TheButton>
    </div>
    <div class="note-actions">
      <TheButton @click="save()" title="Save" color="#32a852"></TheButton>
      <TheButton @click="remove()" title="Delete" color="#a8323a"></TheButton>
      <TheButton @click="report()" title="Report" color="#a83281"></TheButton>
    </div>
    <p v-if="actionStatus">{{ actionStatus }}</p>
  </div>
</template>

<script>
import { RouterLink } from 'vue-router'
import router from '@/router'

export default {
  name: 'EditorView',
  data() {
    return {
      note: null,
      focused: null,
      url: null,
      noteContent: [],
      displayUrl: false,
      urlTarget: null,
      actionStatus: null
    }
  },
  components: [RouterLink],
  created() {
    this.$watch(
      () => this.$route.params,
      () => {
        this.fetchData()
      },
      { immediate: true }
    )
  },
  methods: {
    fetchData() {
      fetch(`/api/note/${this.$route.params.id}`)
        .then((r) => {
          if (r.status !== 200) {
            router.push("/app")
          }
          return r.json()
        })
        .then((j) => {
          this.note = j
          let content = JSON.parse(atob(j.content))
          this.noteContent = content.map((i) => {
            return {
              ...i,
              updated: i.content
            }
          })
        })
    },
    handleInput(event, index) {
      this.focused = index
      this.noteContent[index].updated = event.currentTarget.innerText
      if (this.noteContent[index].updated === '\n' && event.data === null) {
        this.noteContent.splice(index, 1)
      }
    },
    addText() {
      this.addElement({
        type: 'p',
        attr: {},
        content: '',
        updated: ''
      })
    },
    addBold() {
      this.addElement({
        type: 'p',
        attr: { style: 'font-weight:700' },
        content: '',
        updated: ''
      })
    },
    addImg() {
      this.displayUrl = true
      this.addElement({
        type: 'img',
        attr: { src: '', style: 'width:50%;heigth:auto' },
        content: ''
      })
      this.urlTarget = this.focused
      this.$nextTick(() => {
        this.$refs.urlInput.focus()
      })
    },
    addLink() {
      this.displayUrl = true
      this.addElement({
        type: 'a',
        attr: { href: '' },
        content: 'Link'
      })
      this.urlTarget = this.focused
      this.$nextTick(() => {
        this.$refs.urlInput.focus()
      })
    },
    addElement(data) {
      let pos = this.getNextPosition()
      this.noteContent.splice(pos, 0, data)
      this.focused = pos
      this.$nextTick(() => this.$refs[`item-${pos}`][0].focus())
    },
    confirmUrl() {
      this.displayUrl = false
      if (!this.urlTarget) {
        return
      }
      let element = this.noteContent[this.urlTarget]
      let attr = ''
      if (element.type === 'img') {
        attr = 'src'
      } else if (element.type === 'a') {
        attr = 'href'
      } else {
        return
      }
      element.attr[attr] = this.url
      this.url = ''
    },
    getNextPosition() {
      return this.focused ? this.focused + 1 : this.noteContent.length
    },
    save() {
      // Backend does not support our rich text yet, so we will encode it.
      let content = btoa(
        JSON.stringify(
          this.noteContent.map((i) => {
            return {
              type: i.type,
              attr: i.attr,
              content: i.updated
            }
          })
        )
      )
      fetch(`/api/note/${this.$route.params.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ content: content }),
        headers: {
          'X-NOTES-CSRF-PROTECTION': '1'
        }
      }).then((r) => (this.actionStatus = 'Note saved!'))
    },
    remove() {
      fetch(`/api/note/${this.$route.params.id}`, {
        method: 'DELETE',
        headers: {
          'X-NOTES-CSRF-PROTECTION': '1'
        }
      })
        .then((r) => {
          if (r.status === 403) {
            return r.json()
          }
          router.push(`/app`)
        })
        .then((j) => (this.actionStatus = j.message))
    },
    report() {
      fetch(`/api/note/${this.$route.params.id}/report`, {
        method: 'POST',
        headers: {
          'X-NOTES-CSRF-PROTECTION': '1'
        }
      })
        .then((r) => r.json())
        .then((j) => (this.actionStatus = j.message))
    }
  }
}
</script>

<style scoped>
.editor {
  margin: 30px;
  padding-top: 10px;
}
.editor-text {
  display: flex;
}
.editor-actions {
  display: flex;
  width: fit-content;
  padding: 10px;
  gap: 20px;
  background-image: url('/src/assets/img/wood-pixel.png');
  border-radius: 5px;
  height: 30px;
}

.editor-actions img {
  width: 30px;
  height: 30px;
}

.editor-actions img:hover {
  cursor: pointer;
  width: 40px;
  height: 40px;
}

.note-actions {
  margin-top: 30px;
  display: flex;
  gap: 20px;
}

.note-actions .button-container {
  flex: 1;
  text-align: center;
}

p,
a {
  font-size: 1.5em;
}
</style>
