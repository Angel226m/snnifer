<script>
  import { onMount } from 'svelte';
  import '../styles/global.css';
  import { initializeStores } from '$lib/store';

  onMount(() => {
    initializeStores();
  });
</script>

<div class="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
  <slot />
</div>

<style global>
  :global(body) {
    margin: 0;
    padding: 0;
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
  }

  :global(button) {
    cursor: pointer;
    transition: all 0.3s ease;
  }

  :global(input, select, textarea) {
    font-family: inherit;
  }
</style>
