<script setup>
import TheButton from '@/components/TheButton.vue';
</script>

<template>
  <div class="admin">
    <h1>Admin portal</h1>
    <div class="user-table">
      <div class="table-header">
        <div>Email</div>
        <div>Faction</div>
        <div>Ban</div>
      </div>
      <div class="table-body">
        <div v-for="u in users" :key="u.id" class="table-row">
          <div>{{ u.email }}</div>
          <div>{{ u.faction }}</div>
          <TheButton @click="banUser(u.id)" title="Ban" color="#a8323a"></TheButton><br />
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import router from '@/router'

export default {
  name: 'AdminView',
  props: {
    user: null,
  },
  data() {
    return {
      users: [],
    }
  },
  methods: {
    banUser(id) {
      fetch(`/api/admin/users/${id}/ban`, {
        method: 'POST',
        headers: {
          'X-NOTES-CSRF-PROTECTION': '1'
        }
      })
        .then(() => this.fetchUsers())
    },
    fetchUsers() {
      fetch('/api/admin/users')
        .then((r) => r.json())
        .then((j) => (this.users = j))
    }
  },
  created() {
    if (this.user === null || this.user.role !== "admin") {
      router.push("/app")
      return
    }
    this.fetchUsers()
  }
}
</script>

<style scoped>
.user-table {
  width: 100%;
}

.table-header {
  display: flex;
  justify-content: space-between;
  background-color: #f2f2f2;
  padding: 10px;
  font-weight: bold;
}

.table-header div {
  flex-basis: calc(33.33% - 10px); /* Divide the space into three equal parts */
}

.table-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid #ddd;
  padding: 10px;
}
</style>
