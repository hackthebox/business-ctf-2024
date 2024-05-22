<script setup>
import Card from '@/components/Card.vue'
</script>

<template>
  <div class="app">
    <h1>Login</h1>
    <div class="idp">
      <img src="/src/assets/img/cloud.png"><h2>Click on the superpower you belong to and you will be redirected to your IdP</h2>
    </div>
    <p>Remember, no talk about nuclear devices allowed!</p>
    <p :v-if="error">{{ error }}</p>
    <div class="factions">
      <Card
        v-for="faction in factions"
        :title="faction.name"
        :content="faction.region"
        @click="chooseFaction(faction.id)"
      >
      </Card>
    </div>
  </div>
</template>

<script>
export default {
  name: 'LoginView',
  data() {
    return {
      factions: [],
      error: null
    }
  },
  methods: {
    chooseFaction(id) {
      fetch('/auth/sso', {
        method: 'POST',
        body: JSON.stringify({
          id: id
        }),
        headers: {
          'X-NOTES-CSRF-PROTECTION': '1'
        }
      })
        .then((r) => r.json())
        .then((j) => (window.location = j.url))
    }
  },
  created() {
    this.error = new URLSearchParams(window.location.search).get('error')
    fetch('/auth/sso/factions')
      .then((r) => r.json())
      .then((j) => (this.factions = j))
  }
}
</script>

<style scoped>
.factions {
  display: flex;
  gap: 10px;
}

.factions .card {
  flex: 1;
}

.idp {
  display: flex;
  align-items:center;
  gap: 10px;
}

.idp img {
  width: 40px;
  height: 40px;
}
</style>
