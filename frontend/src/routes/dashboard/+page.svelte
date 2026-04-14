<script>
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { authStore, clientsStore, logout } from '$lib/store';
  import { clientsAPI } from '$lib/api';
  import AddClientModal from './AddClientModal.svelte';
  import EditClientModal from './EditClientModal.svelte';

  let showAddModal = false;
  let showEditModal = false;
  let editingClient = null;
  let currentUser = null;
  let stats = { total: 0, encrypted: 0, plaintext: 0 };

  onMount(async () => {
    let interval;
    const unsub = authStore.subscribe(value => {
      if (!value.isAuthenticated) {
        clearInterval(interval);
        goto('/');
        return;
      }
      currentUser = value.user;
    });

    // Check auth once synchronously before making any API calls
    let auth;
    authStore.subscribe(v => (auth = v))();
    if (!auth?.isAuthenticated) return;

    await loadClients();
    // Refresh every 5 seconds only while authenticated
    interval = setInterval(loadClients, 5000);
    return () => { clearInterval(interval); unsub(); };
  });

  async function loadClients() {
    clientsStore.update(s => ({ ...s, loading: true }));
    try {
      const response = await clientsAPI.getClients();
      const clients = response.data.clients || [];
      const encrypted = clients.filter(c => c.encrypted).length;
      const plaintext = clients.length - encrypted;
      
      stats = {
        total: clients.length,
        encrypted,
        plaintext
      };
      
      clientsStore.set({ clients, total: clients.length, loading: false, error: null });
    } catch (err) {
      clientsStore.update(s => ({ ...s, loading: false, error: err.response?.data?.detail || 'Error al cargar clientes' }));
    }
  }

  function handleLogout() {
    logout();
    goto('/');
  }

  async function handleClientAdded() {
    showAddModal = false;
    await loadClients();
  }

  function openEditModal(client) {
    editingClient = { ...client };
    showEditModal = true;
  }

  async function handleClientUpdated() {
    showEditModal = false;
    editingClient = null;
    await loadClients();
  }

  async function handleDeleteClient(clientId, clientName) {
    if (confirm(`¿Eliminar cliente ${clientName}?`)) {
      try {
        await clientsAPI.deleteClient(clientId);
        await loadClients();
      } catch (err) {
        alert(`Error al eliminar: ${err.response?.data?.detail || 'Error desconocido'}`);
      }
    }
  }

</script>

<div class="min-h-screen bg-gray-50">

  <!-- Navbar -->
  <nav class="bg-blue-700 shadow-lg">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <span class="text-2xl">🔐</span>
        <span class="text-xl font-bold text-white tracking-tight">ClientVault</span>
      </div>
      <div class="flex items-center gap-4">
        <div class="hidden sm:block text-right">
          <p class="text-sm font-medium text-white leading-tight">{currentUser?.email}</p>
          <p class="text-xs text-blue-200">Administrador</p>
        </div>
        <button
          on:click={handleLogout}
          class="px-4 py-2 bg-blue-800 hover:bg-blue-900 text-white rounded-lg text-sm font-medium transition-colors"
        >
          Cerrar sesión
        </button>
      </div>
    </div>
  </nav>

  <!-- Page content -->
  <main class="max-w-7xl mx-auto px-4 sm:px-6 py-8 space-y-6">

    <!-- Stats + Settings row -->
    <div class="grid grid-cols-1 sm:grid-cols-3 gap-5">

      <!-- Stat card -->
      <div class="bg-white rounded-xl shadow-sm border border-gray-100 p-6 flex items-center gap-4">
        <div class="w-12 h-12 bg-blue-100 rounded-xl flex items-center justify-center flex-shrink-0">
          <span class="text-2xl">👥</span>
        </div>
        <div>
          <p class="text-xs font-semibold text-gray-400 uppercase tracking-wide">Total Clientes</p>
          <p class="text-3xl font-bold text-gray-800">{$clientsStore.total}</p>
        </div>
      </div>

      <!-- Security note -->
      <div class="bg-white rounded-xl shadow-sm border border-gray-100 p-6 sm:col-span-2">
        <p class="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-2">Seguridad</p>
        <p class="text-sm text-gray-700 leading-6">
          La contraseña se guarda hasheada con bcrypt. El resto de datos se envía al backend por el canal normal de la API y debe protegerse con HTTPS en despliegue.
        </p>
      </div>
    </div>

    <!-- Clients table -->
    <div class="bg-white rounded-xl shadow-sm border border-gray-100 overflow-hidden">

      <div class="px-6 py-4 border-b border-gray-100 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 class="text-lg font-bold text-gray-800">Clientes</h2>
          <p class="text-sm text-gray-400">{$clientsStore.total} registros en total</p>
        </div>
        <button
          on:click={() => showAddModal = true}
          class="inline-flex items-center gap-2 px-4 py-2 bg-blue-700 text-white rounded-lg text-sm font-semibold hover:bg-blue-800 transition-colors"
        >
          + Agregar cliente
        </button>
      </div>

      {#if $clientsStore.loading}
        <div class="py-20 text-center">
          <div class="inline-block w-8 h-8 border-4 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
          <p class="mt-4 text-sm text-gray-400">Cargando clientes...</p>
        </div>
      {:else if $clientsStore.error}
        <div class="m-6 p-4 bg-red-50 border border-red-200 text-red-700 rounded-lg text-sm">
          {$clientsStore.error}
        </div>
      {:else if $clientsStore.clients.length === 0}
        <div class="py-20 text-center">
          <span class="text-5xl">📋</span>
          <p class="mt-4 text-gray-400 text-sm">No hay clientes registrados.</p>
          <button on:click={() => showAddModal = true} class="mt-3 text-blue-600 font-semibold hover:underline text-sm">
            Agregar el primero →
          </button>
        </div>
      {:else}
        <div class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead>
              <tr class="bg-gray-50 border-b border-gray-100">
                <th class="px-5 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Nombre</th>
                <th class="px-5 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Apellido</th>
                <th class="px-5 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Edad</th>
                <th class="px-5 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">DNI</th>
                <th class="px-5 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Teléfono</th>
                <th class="px-5 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Email</th>
                <th class="px-5 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Dirección</th>
                <th class="px-5 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Acciones</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-gray-100">
              {#each $clientsStore.clients as client (client.id)}
                <tr class="hover:bg-blue-50 transition-colors duration-150">
                  <td class="px-5 py-3 font-medium text-gray-900">{client.name}</td>
                  <td class="px-5 py-3 text-gray-600">{client.surname}</td>
                  <td class="px-5 py-3 text-gray-600">{client.age ?? '-'}</td>
                  <td class="px-5 py-3 font-mono text-gray-600">{client.dni}</td>
                  <td class="px-5 py-3 text-gray-600">{client.phone}</td>
                  <td class="px-5 py-3 text-gray-600">{client.email ?? '-'}</td>
                  <td class="px-5 py-3 text-gray-600 max-w-xs truncate">{client.address ?? '-'}</td>
                  <td class="px-5 py-3">
                    <div class="flex gap-2">
                      <button
                        on:click={() => openEditModal(client)}
                        class="px-3 py-1 bg-blue-600 text-white text-xs rounded hover:bg-blue-700 transition"
                        title="Editar"
                      >
                        ✏️
                      </button>
                      <button
                        on:click={() => handleDeleteClient(client.id, `${client.name} ${client.surname}`)}
                        class="px-3 py-1 bg-red-600 text-white text-xs rounded hover:bg-red-700 transition"
                        title="Eliminar"
                      >
                        🗑️
                      </button>
                    </div>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </div>
  </main>
</div>

{#if showAddModal}
  <AddClientModal
    on:close={() => showAddModal = false}
    on:success={handleClientAdded}
  />
{/if}

{#if showEditModal && editingClient}
  <EditClientModal
    client={editingClient}
    on:close={() => { showEditModal = false; editingClient = null; }}
    on:success={handleClientUpdated}
  />
{/if}
