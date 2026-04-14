<script>
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { authStore } from '$lib/store';
  import { authAPI } from '$lib/api';

  let email = '';
  let password = '';
  let isLoading = false;
  let error = '';
  let isLogin = true;

  onMount(() => {
    let auth;
    const unsub = authStore.subscribe(v => (auth = v));
    unsub();
    if (auth.isAuthenticated) goto('/dashboard');
  });

  async function handleSubmit(e) {
    e.preventDefault();
    error = '';
    isLoading = true;

    try {
      const response = isLogin
        ? await authAPI.login(email, password)
        : await authAPI.register(email, password);

      const { access_token, user } = response.data;

      localStorage.setItem('jwt_token', access_token);
      localStorage.setItem('user', JSON.stringify(user));

      authStore.set({
        token: access_token,
        user,
        isAuthenticated: true,
        loading: false,
        error: null
      });

      goto('/dashboard');
    } catch (err) {
      error = err.response?.data?.detail || 'Credenciales incorrectas';
    } finally {
      isLoading = false;
    }
  }
</script>

<div class="min-h-screen bg-gradient-to-br from-blue-800 via-blue-700 to-indigo-800 flex items-center justify-center p-4">
  <div class="w-full max-w-md">

    <!-- Logo -->
    <div class="text-center mb-8">
      <div class="inline-flex items-center justify-center w-16 h-16 bg-white bg-opacity-20 rounded-2xl mb-4 shadow-lg">
        <span class="text-3xl">🔐</span>
      </div>
      <h1 class="text-3xl font-bold text-white tracking-tight">ClientVault</h1>
      <p class="text-blue-200 mt-1 text-sm">Gestión segura de clientes</p>
    </div>

    <!-- Card -->
    <div class="bg-white rounded-2xl shadow-2xl overflow-hidden">

      <!-- Tabs -->
      <div class="flex border-b border-gray-100">
        <button
          type="button"
          class="flex-1 py-4 text-sm font-semibold transition-colors duration-200 {isLogin ? 'bg-blue-700 text-white' : 'bg-white text-gray-400 hover:text-gray-600'}"
          on:click={() => { isLogin = true; error = ''; }}
        >
          Iniciar Sesión
        </button>
        <button
          type="button"
          class="flex-1 py-4 text-sm font-semibold transition-colors duration-200 {!isLogin ? 'bg-blue-700 text-white' : 'bg-white text-gray-400 hover:text-gray-600'}"
          on:click={() => { isLogin = false; error = ''; }}
        >
          Registrarse
        </button>
      </div>

      <div class="p-8">
        {#if error}
          <div class="mb-5 p-3 bg-red-50 border border-red-200 text-red-700 rounded-lg text-sm flex items-center gap-2">
            <span>⚠️</span> {error}
          </div>
        {/if}

        <form on:submit={handleSubmit} class="space-y-5">
          <div>
            <label for="email" class="block text-sm font-semibold text-gray-700 mb-1">
              Correo electrónico
            </label>
            <input
              id="email"
              type="email"
              bind:value={email}
              placeholder="correo@ejemplo.com"
              class="input-field"
              required
              disabled={isLoading}
            />
          </div>

          <div>
            <label for="password" class="block text-sm font-semibold text-gray-700 mb-1">
              Contraseña
            </label>
            <input
              id="password"
              type="password"
              bind:value={password}
              placeholder="••••••••"
              class="input-field"
              required
              disabled={isLoading}
              minlength="6"
            />
          </div>

          <button
            type="submit"
            class="w-full py-3 bg-blue-700 text-white rounded-xl font-semibold hover:bg-blue-800 active:bg-blue-900 disabled:bg-gray-300 disabled:cursor-not-allowed transition-colors duration-200"
            disabled={isLoading}
          >
            {#if isLoading}
              <span class="inline-flex items-center justify-center gap-2">
                <span class="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></span>
                Cargando...
              </span>
            {:else}
              {isLogin ? 'Iniciar Sesión' : 'Crear Cuenta'}
            {/if}
          </button>
        </form>

        {#if isLogin}
          <div class="mt-6 p-4 bg-blue-50 rounded-xl border border-blue-100">
            <p class="text-xs font-bold text-blue-700 mb-1 uppercase tracking-wide">Credenciales de demo</p>
            <p class="text-sm font-mono text-blue-800">angel@gmail.com</p>
            <p class="text-sm font-mono text-blue-800">angel22</p>
          </div>
        {/if}
      </div>
    </div>

    <p class="text-center text-blue-300 text-xs mt-6">
      Contraseñas hasheadas con bcrypt · Sesión autenticada con JWT
    </p>
  </div>
</div>
