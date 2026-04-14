import { c as create_ssr_component, e as escape, b as add_attribute } from './ssr-DfAEDww9.js';
import './ssr2-e2juEaAg.js';
import './state.svelte-LLcxisGS.js';
import './api-FNLPj6bw.js';
import 'axios';
import './index-DWyUw6A5.js';

const Page = create_ssr_component(($$result, $$props, $$bindings, slots) => {
  let email = "";
  let password = "";
  return `<div class="min-h-screen bg-gradient-to-br from-blue-800 via-blue-700 to-indigo-800 flex items-center justify-center p-4"><div class="w-full max-w-md"> <div class="text-center mb-8" data-svelte-h="svelte-1j7ic47"><div class="inline-flex items-center justify-center w-16 h-16 bg-white bg-opacity-20 rounded-2xl mb-4 shadow-lg"><span class="text-3xl">🔐</span></div> <h1 class="text-3xl font-bold text-white tracking-tight">ClientVault</h1> <p class="text-blue-200 mt-1 text-sm">Gestión segura de clientes</p></div>  <div class="bg-white rounded-2xl shadow-2xl overflow-hidden"> <div class="flex border-b border-gray-100"><button type="button" class="${"flex-1 py-4 text-sm font-semibold transition-colors duration-200 " + escape(
    "bg-blue-700 text-white",
    true
  )}">Iniciar Sesión</button> <button type="button" class="${"flex-1 py-4 text-sm font-semibold transition-colors duration-200 " + escape(
    "bg-white text-gray-400 hover:text-gray-600",
    true
  )}">Registrarse</button></div> <div class="p-8">${``} <form class="space-y-5"><div><label for="email" class="block text-sm font-semibold text-gray-700 mb-1" data-svelte-h="svelte-naanmk">Correo electrónico</label> <input id="email" type="email" placeholder="correo@ejemplo.com" class="input-field" required ${""}${add_attribute("value", email)}></div> <div><label for="password" class="block text-sm font-semibold text-gray-700 mb-1" data-svelte-h="svelte-1wffz2r">Contraseña</label> <input id="password" type="password" placeholder="••••••••" class="input-field" required ${""} minlength="6"${add_attribute("value", password)}></div> <button type="submit" class="w-full py-3 bg-blue-700 text-white rounded-xl font-semibold hover:bg-blue-800 active:bg-blue-900 disabled:bg-gray-300 disabled:cursor-not-allowed transition-colors duration-200" ${""}>${`${escape("Iniciar Sesión")}`}</button></form> ${`<div class="mt-6 p-4 bg-blue-50 rounded-xl border border-blue-100" data-svelte-h="svelte-1cghjs4"><p class="text-xs font-bold text-blue-700 mb-1 uppercase tracking-wide">Credenciales de demo</p> <p class="text-sm font-mono text-blue-800">angel@gmail.com</p> <p class="text-sm font-mono text-blue-800">angel22</p></div>`}</div></div> <p class="text-center text-blue-300 text-xs mt-6" data-svelte-h="svelte-1hkzzcn">Contraseñas hasheadas con bcrypt · Sesión autenticada con JWT</p></div></div>`;
});

export { Page as default };
//# sourceMappingURL=_page.svelte-BA9YpWbX.js.map
