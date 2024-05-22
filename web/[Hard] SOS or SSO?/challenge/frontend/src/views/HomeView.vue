<script setup>
import TheSection from '@/components/TheSection.vue'
import note from '@/assets/img/logo.png';
import cloud from '@/assets/img/cloud.png';
</script>

<template>
  <div class="sections">
    <TheSection
      :image="note"
      title="Perfect place for words to remember"
      description="PermNotes is West Oceania's most prized product, a place where anybody can share their thoughts knowing it will be there forever. Anonymous notes are welcome but talk of nuclear devices is strictly prohibited!"
      link="/app"
      linkText="Try out our amazing note taking app"
    ></TheSection>
    <TheSection
      :image="cloud"
      title="Seamless integration with SuperPower's SSO"
      description="For citizens of recognized world super powers we offer a great login experience using our SuperPower SSO. Please contact our support team if you cannot find your faction's portal in our offering."
      link="/login"
      linkText="Login with your IdP"
  ></TheSection>
  </div>
  <h2 class="footnote">Proudly brought you by West Oceania Software</h2>
</template>

<style scoped>
.route-button {
  height: fit-content;
  width: fit-content;
  background-color: yellow;
}

.sections {
  margin-top: 5%;
}

.section {
  width: 70%;
  margin-left: 10%;
  margin-top: 5%;
}

.footnote {
  text-align: center;
  margin-top: 10%;
}
</style>
