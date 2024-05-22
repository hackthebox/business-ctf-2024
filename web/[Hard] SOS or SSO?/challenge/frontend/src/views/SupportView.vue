<script setup>
import Card from '@/components/Card.vue'
import TheButton from '@/components/TheButton.vue';
</script>

<template>
  <div class="support">
    <h1>Factions setup</h1>
    <div class="factions">
      <Card
        v-for="faction in factions"
        :title="faction.name"
        :content="faction.region"
        @click="expandFaction(faction.id)"
      >
      </Card>
    </div>
    <div v-if="selected" class="faction-details">
      Client ID: <input type="text" v-model="config.clientId" /><br />
      Client Secret: <input type="text" v-model="config.clientSecret" /><br />
      Endpoint: <input type="text" v-model="config.endpoint" /><br />
      <TheButton @click="submitConfig" title="Submit" color="#32a852"></TheButton><br />
      <p v-if="submittedStatus">{{ submittedStatus }}</p>
    </div>
  </div>
</template>

<script>
import router from '@/router'

export default {
  name: 'SupportView',
  props: {
    user: null,
  },
  data() {
    return {
      factions: [],
      config: null,
      selected: null,
      submittedStatus: null
    }
  },
  methods: {
    expandFaction(id) {
      this.selected = id
      fetch(`/api/support/faction/${id}`)
        .then((r) => r.json())
        .then((j) => {
          if (j.config === null) {
            this.config = {
              clientId: '',
              clientSecret: '',
              endpoint: ''
            }
          } else {
            this.config = j.config
          }
        })
    },
    submitConfig() {
      fetch(`/api/support/faction/${this.selected}/config`, {
        method: 'POST',
        body: JSON.stringify(this.config),
        headers: {
          'X-NOTES-CSRF-PROTECTION': '1'
        }
      })
        .then((r) => r.json())
        .then((j) => {
          if (j.message) {
            this.submittedStatus = j.message
          } else {
            this.submittedStatus = 'Successfully submitted OIDC configuration'
          }
        })
    }
  },
  created() {
    if (this.user === null || this.user.role === "user") {
      router.push("/app")
      return
    }
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

.faction-details {
  margin-top: 30px;
}
</style>
