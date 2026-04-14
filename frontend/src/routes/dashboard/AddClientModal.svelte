<script>
  import { createEventDispatcher } from 'svelte';
  import { clientsAPI } from '$lib/api';

  const dispatch = createEventDispatcher();

  let name = '';
  let surname = '';
  let age = '';
  let dni = '';
  let phone = '';
  let email = '';
  let address = '';
  let isLoading = false;
  let error = '';

  async function handleSubmit(e) {
    e.preventDefault();
    error = '';
    isLoading = true;

    // Validate DNI
    if (!/^\d{8}$/.test(dni)) {
      error = 'DNI must be 8 digits';
      isLoading = false;
      return;
    }

    // Validate phone
    if (!/^\d{9}$/.test(phone)) {
      error = 'Phone must be 9 digits';
      isLoading = false;
      return;
    }

    try {
      const clientData = {
        name,
        surname,
        age: age ? parseInt(age) : null,
        dni,
        phone,
        email: email || null,
        address: address || null
      };

      await clientsAPI.createClient(clientData);

      // Reset form
      name = '';
      surname = '';
      age = '';
      dni = '';
      phone = '';
      email = '';
      address = '';

      dispatch('success');
    } catch (err) {
      error = err.response?.data?.detail || 'Failed to create client';
    } finally {
      isLoading = false;
    }
  }

  function handleClose() {
    dispatch('close');
  }
</script>

<!-- Backdrop -->
<div
  class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50"
  on:click={handleClose}
  role="presentation"
>
  <!-- Modal -->
  <div
    class="bg-white rounded-lg shadow-2xl max-w-md w-full mx-4 max-h-[90vh] overflow-y-auto"
    on:click|stopPropagation
    role="dialog"
    aria-modal="true"
  >
    <div class="sticky top-0 bg-blue-500 text-white px-6 py-4 flex justify-between items-center">
      <h2 class="text-xl font-bold">Add New Client</h2>
      <button
        on:click={handleClose}
        class="text-xl font-bold hover:bg-blue-600 px-2 py-1 rounded"
      >
        ✕
      </button>
    </div>

    <form on:submit={handleSubmit} class="p-6 space-y-4">
      {#if error}
        <div class="p-3 bg-red-100 border border-red-400 text-red-700 rounded text-sm">
          {error}
        </div>
      {/if}

      <div>
        <label for="name" class="block text-sm font-medium text-gray-700 mb-1">
          Name *
        </label>
        <input
          id="name"
          type="text"
          bind:value={name}
          class="input-field"
          required
          disabled={isLoading}
        />
      </div>

      <div>
        <label for="surname" class="block text-sm font-medium text-gray-700 mb-1">
          Surname *
        </label>
        <input
          id="surname"
          type="text"
          bind:value={surname}
          class="input-field"
          required
          disabled={isLoading}
        />
      </div>

      <div>
        <label for="age" class="block text-sm font-medium text-gray-700 mb-1">
          Age
        </label>
        <input
          id="age"
          type="number"
          bind:value={age}
          class="input-field"
          disabled={isLoading}
        />
      </div>

      <div>
        <label for="dni" class="block text-sm font-medium text-gray-700 mb-1">
          DNI (8 digits) *
        </label>
        <input
          id="dni"
          type="text"
          bind:value={dni}
          placeholder="12345678"
          class="input-field"
          maxlength="8"
          required
          disabled={isLoading}
        />
      </div>

      <div>
        <label for="phone" class="block text-sm font-medium text-gray-700 mb-1">
          Phone (9 digits) *
        </label>
        <input
          id="phone"
          type="text"
          bind:value={phone}
          placeholder="123456789"
          class="input-field"
          maxlength="9"
          required
          disabled={isLoading}
        />
      </div>

      <div>
        <label for="email" class="block text-sm font-medium text-gray-700 mb-1">
          Email
        </label>
        <input
          id="email"
          type="email"
          bind:value={email}
          class="input-field"
          disabled={isLoading}
        />
      </div>

      <div>
        <label for="address" class="block text-sm font-medium text-gray-700 mb-1">
          Address
        </label>
        <textarea
          id="address"
          bind:value={address}
          rows="3"
          class="input-field"
          disabled={isLoading}
        />
      </div>

      <div class="flex gap-3 pt-6">
        <button
          type="button"
          on:click={handleClose}
          class="btn-outline flex-1"
          disabled={isLoading}
        >
          Cancel
        </button>
        <button
          type="submit"
          class="btn-primary flex-1"
          disabled={isLoading}
        >
          {isLoading ? 'Creating...' : 'Create Client'}
        </button>
      </div>
    </form>
  </div>
</div>

<style>
  :global(body) {
    overflow: hidden;
  }
</style>
