<script>
  import { onMount } from 'svelte';
  import '../styles/global.css';
  import { initializeStores } from '$lib/store';

  onMount(() => {
    initializeStores();
  });
</script>

<slot />
